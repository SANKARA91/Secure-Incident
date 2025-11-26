# -*- coding: utf-8 -*-
"""
Routes API pour l'intégration Wazuh
Permet de récupérer les alertes, agents et statistiques depuis Wazuh
"""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
import httpx
import os
from datetime import datetime
from typing import List, Optional
from app.db.database import get_db
from app.models.incident import WazuhAlert

router = APIRouter(prefix="/wazuh", tags=["Wazuh"])

# Configuration Wazuh depuis les variables d'environnement
WAZUH_URL = os.getenv("WAZUH_URL", "https://192.168.1.19:55000")
WAZUH_USERNAME = os.getenv("WAZUH_USERNAME", "wazuh")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "wazuh")


async def get_wazuh_token():
    """
    Obtenir un token d'authentification Wazuh
    Le token est nécessaire pour toutes les requêtes à l'API Wazuh
    """
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
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=e.response.status_code,
            detail=f"Erreur authentification Wazuh: {e.response.text}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Erreur connexion Wazuh: {str(e)}"
        )


@router.get("/alerts")
async def get_alerts(
    limit: int = 100,
    level: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """
    Récupérer les alertes Wazuh récentes
    
    - **limit**: Nombre d'alertes à récupérer (max 500)
    - **level**: Filtrer par niveau de sévérité (optionnel, ex: 3, 7, 12)
    
    Les alertes sont automatiquement sauvegardées dans la base de données
    """
    try:
        # Obtenir le token d'authentification
        token = await get_wazuh_token()
        
        # Construire les paramètres de requête
        params = {
            "limit": min(limit, 500),
            "sort": "-timestamp"
        }
        
        if level:
            params["rule.level"] = level
        
        # Récupérer les alertes depuis Wazuh
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(
                f"{WAZUH_URL}/alerts",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                params=params,
                timeout=30.0
            )
            response.raise_for_status()
            data = response.json()
        
        alerts = data.get("data", {}).get("affected_items", [])
        
        # Sauvegarder les nouvelles alertes dans la base de données
        saved_count = 0
        for alert in alerts:
            try:
                # Vérifier si l'alerte existe déjà
                alert_id = alert.get("id", "unknown")
                existing = db.query(WazuhAlert).filter(
                    WazuhAlert.alert_id == alert_id
                ).first()
                
                if not existing:
                    # Extraire les informations importantes
                    rule = alert.get("rule", {})
                    agent = alert.get("agent", {})
                    timestamp_str = alert.get("timestamp", "")
                    
                    # Convertir le timestamp
                    try:
                        timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                    except:
                        timestamp = datetime.utcnow()
                    
                    # Créer la nouvelle alerte
                    new_alert = WazuhAlert(
                        alert_id=alert_id,
                        timestamp=timestamp,
                        rule_id=rule.get("id"),
                        rule_description=rule.get("description"),
                        rule_level=rule.get("level"),
                        agent_id=agent.get("id"),
                        agent_name=agent.get("name"),
                        full_log=alert.get("full_log"),
                        data=alert  # Stocker tout le JSON
                    )
                    db.add(new_alert)
                    saved_count += 1
            except Exception as e:
                print(f"⚠️ Erreur sauvegarde alerte {alert.get('id')}: {e}")
                continue
        
        # Sauvegarder en base de données
        if saved_count > 0:
            db.commit()
            print(f"💾 {saved_count} nouvelles alertes sauvegardées")
        
        return {
            "status": "success",
            "total": len(alerts),
            "saved_new": saved_count,
            "alerts": alerts[:20]  # Retourner les 20 premières pour ne pas surcharger
        }
        
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=e.response.status_code,
            detail=f"Erreur API Wazuh: {e.response.text}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Erreur: {str(e)}"
        )


@router.get("/alerts/stats")
async def get_alerts_stats():
    """
    Statistiques détaillées sur les alertes Wazuh
    
    Retourne:
    - Nombre total d'alertes
    - Répartition par niveau de sévérité
    - Répartition par agent
    - Top 10 des règles les plus fréquentes
    """
    try:
        token = await get_wazuh_token()
        
        async with httpx.AsyncClient(verify=False) as client:
            # Récupérer les alertes des dernières 24h
            response = await client.get(
                f"{WAZUH_URL}/alerts",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                params={"limit": 1000, "sort": "-timestamp"},
                timeout=30.0
            )
            response.raise_for_status()
            data = response.json()
        
        alerts = data.get("data", {}).get("affected_items", [])
        
        # Calculer les statistiques
        stats = {
            "total": len(alerts),
            "by_level": {},
            "by_agent": {},
            "top_rules": {}
        }
        
        for alert in alerts:
            # Par niveau
            level = alert.get("rule", {}).get("level", 0)
            stats["by_level"][str(level)] = stats["by_level"].get(str(level), 0) + 1
            
            # Par agent
            agent = alert.get("agent", {}).get("name", "unknown")
            stats["by_agent"][agent] = stats["by_agent"].get(agent, 0) + 1
            
            # Par règle
            rule_desc = alert.get("rule", {}).get("description", "unknown")
            stats["top_rules"][rule_desc] = stats["top_rules"].get(rule_desc, 0) + 1
        
        # Trier les top rules (top 10)
        stats["top_rules"] = dict(
            sorted(stats["top_rules"].items(), key=lambda x: x[1], reverse=True)[:10]
        )
        
        return {
            "status": "success",
            "stats": stats
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur: {str(e)}")


@router.get("/agents")
async def get_agents():
    """
    Liste de tous les agents Wazuh enregistrés
    
    Retourne les informations sur tous les agents connectés au serveur Wazuh:
    - ID, nom, IP
    - Statut (active, disconnected, etc.)
    - Version de l'agent
    - Système d'exploitation
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
        
        # Résumé des statuts
        summary = {
            "total": len(agents),
            "active": 0,
            "disconnected": 0,
            "never_connected": 0,
            "pending": 0
        }
        
        for agent in agents:
            status = agent.get("status", "").lower()
            if status in summary:
                summary[status] += 1
        
        return {
            "status": "success",
            "summary": summary,
            "total": len(agents),
            "agents": agents
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur: {str(e)}")


@router.get("/agents/{agent_id}")
async def get_agent_details(agent_id: str):
    """
    Détails d'un agent spécifique
    
    - **agent_id**: ID de l'agent (ex: "001", "002", etc.)
    """
    try:
        token = await get_wazuh_token()
        
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(
                f"{WAZUH_URL}/agents/{agent_id}",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                timeout=30.0
            )
            response.raise_for_status()
            data = response.json()
        
        agent = data.get("data", {}).get("affected_items", [])
        
        if not agent:
            raise HTTPException(status_code=404, detail=f"Agent {agent_id} non trouvé")
        
        return {
            "status": "success",
            "agent": agent[0]
        }
        
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            raise HTTPException(status_code=404, detail=f"Agent {agent_id} non trouvé")
        raise HTTPException(
            status_code=e.response.status_code,
            detail=f"Erreur API Wazuh: {e.response.text}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur: {str(e)}")


@router.get("/health")
async def wazuh_health():
    """
    Vérifier la santé de la connexion Wazuh
    
    Teste la connexion au serveur Wazuh et retourne les informations du manager
    """
    try:
        token = await get_wazuh_token()
        
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(
                f"{WAZUH_URL}/manager/info",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                timeout=10.0
            )
            response.raise_for_status()
            data = response.json()
        
        manager_info = data.get("data", {}).get("affected_items", [])
        
        return {
            "status": "healthy",
            "connected": True,
            "wazuh_url": WAZUH_URL,
            "manager_info": manager_info[0] if manager_info else {}
        }
        
    except Exception as e:
        return {
            "status": "unhealthy",
            "connected": False,
            "wazuh_url": WAZUH_URL,
            "error": str(e)
        }


@router.get("/rules")
async def get_rules(limit: int = 100, search: Optional[str] = None):
    """
    Liste des règles Wazuh
    
    - **limit**: Nombre de règles à récupérer (max 500)
    - **search**: Rechercher dans les descriptions de règles (optionnel)
    """
    try:
        token = await get_wazuh_token()
        
        params = {"limit": min(limit, 500)}
        if search:
            params["search"] = search
        
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(
                f"{WAZUH_URL}/rules",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                params=params,
                timeout=30.0
            )
            response.raise_for_status()
            data = response.json()
        
        rules = data.get("data", {}).get("affected_items", [])
        
        return {
            "status": "success",
            "total": len(rules),
            "rules": rules
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur: {str(e)}")