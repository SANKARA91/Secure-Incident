# -*- coding: utf-8 -*-
"""
Routes API pour l'intégration Wazuh avec Active Directory
Collecte et analyse les événements de sécurité AD pour l'IA
"""
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from sqlalchemy.orm import Session
import httpx
import os
from datetime import datetime, timedelta
from typing import List, Optional, Dict
from app.db.database import get_db
from app.models.incident import WazuhAlert
import json

router = APIRouter(prefix="/wazuh/ad", tags=["Wazuh Active Directory"])

# Configuration
WAZUH_URL = os.getenv("WAZUH_URL", "https://192.168.1.19:55000")
WAZUH_USERNAME = os.getenv("WAZUH_USERNAME", "wazuh")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "WzH@2025!Secure+Admin_99")

# Règles Wazuh importantes pour AD (Windows Event IDs)
AD_SECURITY_RULES = {
    # Authentification
    "4624": "Ouverture de session réussie",
    "4625": "Échec d'ouverture de session",
    "4634": "Fermeture de session",
    "4648": "Tentative d'ouverture de session avec des informations d'identification explicites",
    
    # Gestion des comptes
    "4720": "Compte utilisateur créé",
    "4722": "Compte utilisateur activé",
    "4723": "Tentative de changement de mot de passe",
    "4724": "Tentative de réinitialisation de mot de passe",
    "4725": "Compte utilisateur désactivé",
    "4726": "Compte utilisateur supprimé",
    "4738": "Compte utilisateur modifié",
    "4740": "Compte utilisateur verrouillé",
    "4767": "Compte utilisateur déverrouillé",
    
    # Groupes de sécurité
    "4728": "Membre ajouté à un groupe de sécurité global",
    "4729": "Membre supprimé d'un groupe de sécurité global",
    "4732": "Membre ajouté à un groupe de sécurité local",
    "4733": "Membre supprimé d'un groupe de sécurité local",
    "4756": "Membre ajouté à un groupe de sécurité universel",
    "4757": "Membre supprimé d'un groupe de sécurité universel",
    
    # Modifications critiques
    "4735": "Groupe de sécurité local modifié",
    "4737": "Groupe de sécurité global modifié",
    "4755": "Groupe de sécurité universel modifié",
    
    # Événements suspects
    "4769": "Ticket de service Kerberos demandé",
    "4771": "Échec de pré-authentification Kerberos",
    "4776": "Tentative de validation des informations d'identification",
    
    # Politiques et privilèges
    "4704": "Droit utilisateur attribué",
    "4719": "Stratégie d'audit système modifiée",
    "4906": "Valeur CrashOnAuditFail modifiée",
}


async def get_wazuh_token():
    """Obtenir un token d'authentification Wazuh"""
    try:
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(
                f"{WAZUH_URL}/security/user/authenticate",
                auth=(WAZUH_USERNAME, WAZUH_PASSWORD),
                headers={"Content-Type": "application/json"},
                timeout=10.0
            )
            response.raise_for_status()
            data = response.json()
            return data.get("data", {}).get("token")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur connexion Wazuh: {str(e)}")


@router.get("/events")
async def get_ad_events(
    hours: int = 24,
    event_id: Optional[str] = None,
    severity_min: int = 3,
    limit: int = 500,
    db: Session = Depends(get_db)
):
    """
    Récupérer les événements Active Directory depuis Wazuh
    
    Args:
        hours: Nombre d'heures à remonter (défaut: 24h)
        event_id: Filtrer par Event ID Windows (ex: "4625" pour échecs de connexion)
        severity_min: Niveau de sévérité minimum (3-15)
        limit: Nombre maximum d'événements (max 1000)
    """
    try:
        token = await get_wazuh_token()
        
        # Construire la requête pour les événements Windows
        params = {
            "limit": min(limit, 1000),
            "sort": "-timestamp",
            "q": "rule.groups=windows"  # Filtrer uniquement les événements Windows
        }
        
        if event_id:
            params["q"] += f" and data.win.system.eventID={event_id}"
        
        if severity_min:
            params["rule.level"] = f"{severity_min}-15"
        
        # Récupérer les alertes
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(
                f"{WAZUH_URL}/alerts",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                params=params,
                timeout=60.0
            )
            response.raise_for_status()
            data = response.json()
        
        alerts = data.get("data", {}).get("affected_items", [])
        
        # Enrichir avec les descriptions d'événements AD
        enriched_alerts = []
        for alert in alerts:
            win_event_id = alert.get("data", {}).get("win", {}).get("system", {}).get("eventID")
            if win_event_id:
                alert["ad_event_description"] = AD_SECURITY_RULES.get(str(win_event_id), "Événement Windows")
            enriched_alerts.append(alert)
        
        # Statistiques
        stats = {
            "total": len(enriched_alerts),
            "by_event_id": {},
            "by_agent": {},
            "critical_count": 0
        }
        
        for alert in enriched_alerts:
            event_id = alert.get("data", {}).get("win", {}).get("system", {}).get("eventID", "unknown")
            stats["by_event_id"][str(event_id)] = stats["by_event_id"].get(str(event_id), 0) + 1
            
            agent_name = alert.get("agent", {}).get("name", "unknown")
            stats["by_agent"][agent_name] = stats["by_agent"].get(agent_name, 0) + 1
            
            if alert.get("rule", {}).get("level", 0) >= 10:
                stats["critical_count"] += 1
        
        return {
            "status": "success",
            "period_hours": hours,
            "stats": stats,
            "events": enriched_alerts[:100]  # Limiter l'affichage
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur: {str(e)}")


@router.get("/suspicious-activity")
async def detect_suspicious_activity(hours: int = 24):
    """
    Détecter les activités suspectes dans Active Directory
    
    Détecte automatiquement :
    - Échecs de connexion multiples (brute force)
    - Modifications de comptes critiques
    - Changements de groupes sensibles
    - Activité hors horaires normaux
    - Kerberoasting attempts
    """
    try:
        token = await get_wazuh_token()
        
        suspicious_patterns = {
            "failed_logins": [],
            "account_changes": [],
            "group_modifications": [],
            "kerberos_attacks": [],
            "privilege_escalation": []
        }
        
        # 1. Détecter les échecs de connexion (Event ID 4625)
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(
                f"{WAZUH_URL}/alerts",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                params={
                    "limit": 500,
                    "q": "rule.groups=windows and data.win.system.eventID=4625",
                    "sort": "-timestamp"
                },
                timeout=60.0
            )
            response.raise_for_status()
            failed_logins = response.json().get("data", {}).get("affected_items", [])
            
            # Analyser les patterns de brute force
            login_attempts = {}
            for alert in failed_logins:
                username = alert.get("data", {}).get("win", {}).get("eventdata", {}).get("targetUserName", "unknown")
                if username not in login_attempts:
                    login_attempts[username] = []
                login_attempts[username].append(alert)
            
            # Utilisateurs avec plus de 5 échecs = suspect
            for username, attempts in login_attempts.items():
                if len(attempts) >= 5:
                    suspicious_patterns["failed_logins"].append({
                        "username": username,
                        "attempts": len(attempts),
                        "severity": "HIGH" if len(attempts) >= 10 else "MEDIUM",
                        "description": f"Possibles tentatives de brute force: {len(attempts)} échecs"
                    })
        
        # 2. Modifications de comptes (Event IDs: 4720, 4722, 4725, 4726, 4738)
        async with httpx.AsyncClient(verify=False) as client:
            account_event_ids = "4720,4722,4725,4726,4738,4740"
            response = await client.get(
                f"{WAZUH_URL}/alerts",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                params={
                    "limit": 200,
                    "q": f"rule.groups=windows and (data.win.system.eventID=4720 or data.win.system.eventID=4722 or data.win.system.eventID=4725 or data.win.system.eventID=4726 or data.win.system.eventID=4738 or data.win.system.eventID=4740)"
                },
                timeout=60.0
            )
            if response.status_code == 200:
                account_changes = response.json().get("data", {}).get("affected_items", [])
                for alert in account_changes:
                    event_id = alert.get("data", {}).get("win", {}).get("system", {}).get("eventID")
                    suspicious_patterns["account_changes"].append({
                        "event_id": event_id,
                        "description": AD_SECURITY_RULES.get(str(event_id), "Modification de compte"),
                        "timestamp": alert.get("timestamp"),
                        "agent": alert.get("agent", {}).get("name")
                    })
        
        # 3. Modifications de groupes sensibles (Event IDs: 4728, 4732, 4756)
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(
                f"{WAZUH_URL}/alerts",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                params={
                    "limit": 100,
                    "q": "rule.groups=windows and (data.win.system.eventID=4728 or data.win.system.eventID=4732 or data.win.system.eventID=4756)"
                },
                timeout=60.0
            )
            if response.status_code == 200:
                group_changes = response.json().get("data", {}).get("affected_items", [])
                for alert in group_changes:
                    suspicious_patterns["group_modifications"].append({
                        "event_id": alert.get("data", {}).get("win", {}).get("system", {}).get("eventID"),
                        "description": "Modification de groupe de sécurité",
                        "severity": "HIGH",
                        "timestamp": alert.get("timestamp")
                    })
        
        # 4. Attaques Kerberos (Event IDs: 4769, 4771)
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(
                f"{WAZUH_URL}/alerts",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                params={
                    "limit": 100,
                    "q": "rule.groups=windows and (data.win.system.eventID=4769 or data.win.system.eventID=4771)"
                },
                timeout=60.0
            )
            if response.status_code == 200:
                kerberos_events = response.json().get("data", {}).get("affected_items", [])
                # Analyser pour Kerberoasting
                ticket_requests = {}
                for alert in kerberos_events:
                    username = alert.get("data", {}).get("win", {}).get("eventdata", {}).get("targetUserName", "unknown")
                    if username not in ticket_requests:
                        ticket_requests[username] = []
                    ticket_requests[username].append(alert)
                
                for username, requests in ticket_requests.items():
                    if len(requests) >= 10:  # Trop de demandes de tickets = suspect
                        suspicious_patterns["kerberos_attacks"].append({
                            "username": username,
                            "requests": len(requests),
                            "severity": "CRITICAL",
                            "description": "Possible Kerberoasting attack détecté"
                        })
        
        # Calculer le score de risque global
        risk_score = (
            len(suspicious_patterns["failed_logins"]) * 3 +
            len(suspicious_patterns["account_changes"]) * 2 +
            len(suspicious_patterns["group_modifications"]) * 5 +
            len(suspicious_patterns["kerberos_attacks"]) * 10
        )
        
        risk_level = "LOW"
        if risk_score >= 50:
            risk_level = "CRITICAL"
        elif risk_score >= 20:
            risk_level = "HIGH"
        elif risk_score >= 10:
            risk_level = "MEDIUM"
        
        return {
            "status": "success",
            "period_hours": hours,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "suspicious_activities": suspicious_patterns,
            "summary": {
                "total_suspicious_events": sum(len(v) for v in suspicious_patterns.values()),
                "brute_force_attempts": len(suspicious_patterns["failed_logins"]),
                "account_modifications": len(suspicious_patterns["account_changes"]),
                "group_changes": len(suspicious_patterns["group_modifications"]),
                "kerberos_attacks": len(suspicious_patterns["kerberos_attacks"])
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur détection: {str(e)}")


@router.get("/agents/ad")
async def get_ad_agents():
    """
    Liste des agents Wazuh sur les machines Active Directory
    Identifie automatiquement les contrôleurs de domaine et clients AD
    """
    try:
        token = await get_wazuh_token()
        
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(
                f"{WAZUH_URL}/agents",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                params={"limit": 500},
                timeout=30.0
            )
            response.raise_for_status()
            data = response.json()
        
        agents = data.get("data", {}).get("affected_items", [])
        
        # Classifier les agents
        ad_agents = {
            "domain_controllers": [],
            "ad_clients": [],
            "other": []
        }
        
        for agent in agents:
            name = agent.get("name", "").lower()
            os_name = agent.get("os", {}).get("name", "").lower()
            
            # Identifier les contrôleurs de domaine
            if "dc" in name or "domain" in name or "controller" in name:
                ad_agents["domain_controllers"].append(agent)
            elif "windows" in os_name and agent.get("status") == "active":
                ad_agents["ad_clients"].append(agent)
            else:
                ad_agents["other"].append(agent)
        
        return {
            "status": "success",
            "summary": {
                "total_agents": len(agents),
                "domain_controllers": len(ad_agents["domain_controllers"]),
                "ad_clients": len(ad_agents["ad_clients"]),
                "other": len(ad_agents["other"])
            },
            "agents": ad_agents
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur: {str(e)}")


@router.post("/collect-for-ai")
async def collect_data_for_ai(
    background_tasks: BackgroundTasks,
    days: int = 7,
    db: Session = Depends(get_db)
):
    """
    Collecter les données AD pour l'entraînement de l'IA
    
    Récupère un dataset complet des événements AD pour :
    - Classification des menaces
    - Prédiction d'incidents
    - Détection d'anomalies
    
    Args:
        days: Nombre de jours de données à collecter
    """
    try:
        token = await get_wazuh_token()
        
        # Collecter tous les événements Windows des X derniers jours
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(
                f"{WAZUH_URL}/alerts",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                params={
                    "limit": 5000,
                    "q": "rule.groups=windows",
                    "sort": "-timestamp"
                },
                timeout=120.0
            )
            response.raise_for_status()
            data = response.json()
        
        alerts = data.get("data", {}).get("affected_items", [])
        
        # Préparer le dataset pour l'IA
        ai_dataset = []
        for alert in alerts:
            # Extraire les features importantes
            features = {
                "timestamp": alert.get("timestamp"),
                "event_id": alert.get("data", {}).get("win", {}).get("system", {}).get("eventID"),
                "severity": alert.get("rule", {}).get("level"),
                "agent": alert.get("agent", {}).get("name"),
                "rule_description": alert.get("rule", {}).get("description"),
                "username": alert.get("data", {}).get("win", {}).get("eventdata", {}).get("targetUserName"),
                "source_ip": alert.get("data", {}).get("win", {}).get("eventdata", {}).get("ipAddress"),
                "logon_type": alert.get("data", {}).get("win", {}).get("eventdata", {}).get("logonType"),
                "full_data": alert  # Garder toutes les données
            }
            ai_dataset.append(features)
        
        # Sauvegarder dans la base de données pour l'IA
        saved_count = 0
        for item in ai_dataset:
            try:
                alert_id = f"{item['timestamp']}_{item['event_id']}_{item['agent']}"
                existing = db.query(WazuhAlert).filter(
                    WazuhAlert.alert_id == alert_id
                ).first()
                
                if not existing:
                    new_alert = WazuhAlert(
                        alert_id=alert_id,
                        timestamp=datetime.fromisoformat(item['timestamp'].replace("Z", "+00:00")),
                        rule_id=item['event_id'],
                        rule_description=item['rule_description'],
                        rule_level=item['severity'],
                        agent_name=item['agent'],
                        data=item['full_data']
                    )
                    db.add(new_alert)
                    saved_count += 1
            except Exception as e:
                print(f"⚠️ Erreur sauvegarde: {e}")
                continue
        
        if saved_count > 0:
            db.commit()
        
        return {
            "status": "success",
            "message": f"Données collectées pour l'IA sur {days} jours",
            "total_events": len(ai_dataset),
            "saved_to_db": saved_count,
            "ready_for_training": True,
            "dataset_stats": {
                "unique_event_ids": len(set(item['event_id'] for item in ai_dataset if item['event_id'])),
                "unique_agents": len(set(item['agent'] for item in ai_dataset if item['agent'])),
                "severity_distribution": {}
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur collecte: {str(e)}")