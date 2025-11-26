# -*- coding: utf-8 -*-
"""
Module d'analyse IA avec Claude pour les menaces AD
Utilise l'API Claude pour classification, prédiction et détection d'anomalies
"""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from anthropic import Anthropic
import os
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from app.db.database import get_db
from app.models.incident import WazuhAlert, Incident
import json

router = APIRouter(prefix="/ai/threats", tags=["AI Threat Analysis"])

# Configuration Claude AI
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
if not ANTHROPIC_API_KEY:
    print("⚠️ ANTHROPIC_API_KEY non configurée")

client = Anthropic(api_key=ANTHROPIC_API_KEY) if ANTHROPIC_API_KEY else None


@router.post("/classify")
async def classify_threat(
    alert_data: Dict,
    db: Session = Depends(get_db)
):
    """
    Classifier une alerte/menace avec l'IA Claude
    
    Analyse un événement AD et détermine :
    - Type de menace (brute force, privilege escalation, lateral movement, etc.)
    - Niveau de risque (LOW, MEDIUM, HIGH, CRITICAL)
    - Actions recommandées
    - Indicateurs de compromission (IOCs)
    """
    if not client:
        raise HTTPException(status_code=500, detail="Claude AI non configuré")
    
    try:
        # Préparer le contexte pour Claude
        prompt = f"""Tu es un expert en cybersécurité spécialisé dans Active Directory.

Analyse cet événement de sécurité et fournis une classification détaillée :

**Données de l'alerte :**
```json
{json.dumps(alert_data, indent=2)}
```

**Fournis une analyse JSON structurée avec :**
1. threat_type : Type de menace (ex: "brute_force", "privilege_escalation", "lateral_movement", "data_exfiltration", "credential_theft", "reconnaissance", "benign")
2. severity : Niveau de gravité ("LOW", "MEDIUM", "HIGH", "CRITICAL")
3. confidence : Niveau de confiance de ta classification (0-100%)
4. indicators : Liste des IOCs détectés
5. attack_stage : Phase de la kill chain (ex: "Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Exfiltration", "Impact")
6. recommendations : Actions recommandées (liste de 3-5 actions concrètes)
7. analysis : Explication détaillée de ton analyse (2-3 phrases)
8. related_techniques : Techniques MITRE ATT&CK pertinentes (liste de 1-3 techniques avec IDs)

Réponds UNIQUEMENT avec un JSON valide, sans texte avant ou après."""

        # Appeler Claude
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            temperature=0.3,  # Plus déterministe pour la classification
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        # Parser la réponse
        response_text = message.content[0].text.strip()
        
        # Nettoyer la réponse si nécessaire
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        
        classification = json.loads(response_text.strip())
        
        # Ajouter des métadonnées
        classification["analyzed_at"] = datetime.utcnow().isoformat()
        classification["ai_model"] = "claude-sonnet-4"
        classification["alert_id"] = alert_data.get("id", "unknown")
        
        return {
            "status": "success",
            "classification": classification
        }
        
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"Erreur parsing JSON: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur classification: {str(e)}")


@router.post("/predict-incident")
async def predict_incident_risk(
    hours_lookback: int = 24,
    db: Session = Depends(get_db)
):
    """
    Prédire les risques d'incidents basés sur les patterns récents
    
    Analyse les dernières X heures d'activité pour :
    - Identifier les patterns anormaux
    - Prédire la probabilité d'incident majeur
    - Suggérer des mesures préventives
    """
    if not client:
        raise HTTPException(status_code=500, detail="Claude AI non configuré")
    
    try:
        # Récupérer les alertes récentes
        cutoff_time = datetime.utcnow() - timedelta(hours=hours_lookback)
        recent_alerts = db.query(WazuhAlert).filter(
            WazuhAlert.timestamp >= cutoff_time
        ).order_by(WazuhAlert.timestamp.desc()).limit(200).all()
        
        if not recent_alerts:
            return {
                "status": "success",
                "prediction": {
                    "risk_level": "LOW",
                    "probability": 0,
                    "message": "Pas assez de données pour prédiction"
                }
            }
        
        # Préparer les données pour Claude
        alerts_summary = []
        for alert in recent_alerts[:50]:  # Limiter pour ne pas dépasser le contexte
            alerts_summary.append({
                "timestamp": str(alert.timestamp),
                "rule_id": alert.rule_id,
                "description": alert.rule_description,
                "level": alert.rule_level,
                "agent": alert.agent_name
            })
        
        prompt = f"""Tu es un expert en cybersécurité spécialisé dans la prédiction d'incidents.

Analyse ces {len(alerts_summary)} alertes des dernières {hours_lookback} heures et prédit les risques :

**Alertes récentes :**
```json
{json.dumps(alerts_summary, indent=2)}
```

**Fournis une prédiction JSON structurée avec :**
1. risk_level : Niveau de risque global ("LOW", "MEDIUM", "HIGH", "CRITICAL")
2. incident_probability : Probabilité d'incident majeur dans les prochaines 24h (0-100%)
3. attack_indicators : Liste des indicateurs d'attaque détectés
4. predicted_scenarios : 2-3 scénarios d'attaque les plus probables avec leur probabilité
5. time_to_potential_breach : Estimation du temps avant compromission potentielle (ex: "24-48 hours", "immediate", "72+ hours")
6. vulnerable_assets : Liste des actifs les plus à risque
7. preventive_actions : Liste de 5-7 actions préventives prioritaires et concrètes
8. monitoring_focus : Zones à surveiller en priorité (liste de 3-4 éléments)
9. analysis_summary : Résumé de l'analyse en 2-3 phrases

Réponds UNIQUEMENT avec un JSON valide."""

        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=3000,
            temperature=0.4,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        response_text = message.content[0].text.strip()
        
        # Nettoyer la réponse
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        
        prediction = json.loads(response_text.strip())
        
        # Ajouter métadonnées
        prediction["analyzed_at"] = datetime.utcnow().isoformat()
        prediction["alerts_analyzed"] = len(alerts_summary)
        prediction["time_window_hours"] = hours_lookback
        
        return {
            "status": "success",
            "prediction": prediction
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur prédiction: {str(e)}")


@router.post("/detect-anomalies")
async def detect_anomalies(
    days_baseline: int = 7,
    hours_check: int = 1,
    db: Session = Depends(get_db)
):
    """
    Détection d'anomalies par rapport à une baseline normale
    
    Compare l'activité récente avec le comportement habituel pour détecter :
    - Activités inhabituelles
    - Changements de patterns
    - Comportements suspects
    """
    if not client:
        raise HTTPException(status_code=500, detail="Claude AI non configuré")
    
    try:
        # Récupérer baseline (7 derniers jours)
        baseline_start = datetime.utcnow() - timedelta(days=days_baseline)
        baseline_end = datetime.utcnow() - timedelta(hours=hours_check)
        baseline_alerts = db.query(WazuhAlert).filter(
            WazuhAlert.timestamp >= baseline_start,
            WazuhAlert.timestamp <= baseline_end
        ).all()
        
        # Récupérer période récente à analyser
        recent_start = datetime.utcnow() - timedelta(hours=hours_check)
        recent_alerts = db.query(WazuhAlert).filter(
            WazuhAlert.timestamp >= recent_start
        ).all()
        
        # Créer des statistiques pour Claude
        def create_stats(alerts):
            stats = {
                "total": len(alerts),
                "by_rule": {},
                "by_agent": {},
                "by_severity": {},
                "hourly_distribution": {}
            }
            for alert in alerts:
                # Par règle
                rule = alert.rule_id or "unknown"
                stats["by_rule"][rule] = stats["by_rule"].get(rule, 0) + 1
                
                # Par agent
                agent = alert.agent_name or "unknown"
                stats["by_agent"][agent] = stats["by_agent"].get(agent, 0) + 1
                
                # Par sévérité
                severity = str(alert.rule_level or 0)
                stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
                
                # Par heure
                hour = alert.timestamp.hour if alert.timestamp else 0
                stats["hourly_distribution"][hour] = stats["hourly_distribution"].get(hour, 0) + 1
            
            return stats
        
        baseline_stats = create_stats(baseline_alerts)
        recent_stats = create_stats(recent_alerts)
        
        prompt = f"""Tu es un expert en détection d'anomalies de sécurité.

Compare ces statistiques pour détecter des anomalies :

**Baseline normale (derniers {days_baseline} jours) :**
```json
{json.dumps(baseline_stats, indent=2)}
```

**Activité récente (dernière {hours_check}h) :**
```json
{json.dumps(recent_stats, indent=2)}
```

**Fournis une analyse JSON avec :**
1. anomalies_detected : Nombre d'anomalies détectées
2. anomaly_score : Score d'anomalie global (0-100)
3. is_suspicious : true/false si l'activité est suspecte
4. detected_anomalies : Liste des anomalies avec pour chacune :
   - type (ex: "volume_spike", "new_pattern", "unusual_timing", "suspicious_agent")
   - description (explication)
   - severity ("LOW", "MEDIUM", "HIGH", "CRITICAL")
   - affected_entities (liste des agents/règles concernés)
5. normal_deviations : Écarts par rapport à la normale (%)
6. recommended_actions : Actions recommandées (3-5 items)
7. summary : Résumé en 2-3 phrases

Réponds UNIQUEMENT avec un JSON valide."""

        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2500,
            temperature=0.3,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        response_text = message.content[0].text.strip()
        
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        
        anomalies = json.loads(response_text.strip())
        
        anomalies["analyzed_at"] = datetime.utcnow().isoformat()
        anomalies["baseline_period_days"] = days_baseline
        anomalies["check_period_hours"] = hours_check
        
        return {
            "status": "success",
            "anomaly_detection": anomalies
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur détection: {str(e)}")


@router.post("/auto-create-incident")
async def auto_create_incident_from_ai(
    alert_id: str,
    db: Session = Depends(get_db)
):
    """
    Créer automatiquement un incident depuis une alerte classifiée par l'IA
    
    Si la classification IA indique une menace sérieuse (HIGH/CRITICAL),
    crée automatiquement un incident dans le système
    """
    if not client:
        raise HTTPException(status_code=500, detail="Claude AI non configuré")
    
    try:
        # Récupérer l'alerte
        alert = db.query(WazuhAlert).filter(WazuhAlert.alert_id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alerte non trouvée")
        
        # Classifier avec l'IA
        alert_data = {
            "id": alert.alert_id,
            "timestamp": str(alert.timestamp),
            "rule_id": alert.rule_id,
            "description": alert.rule_description,
            "level": alert.rule_level,
            "agent": alert.agent_name,
            "full_data": alert.data
        }
        
        classification_response = await classify_threat(alert_data, db)
        classification = classification_response["classification"]
        
        # Créer un incident si la menace est sérieuse
        if classification["severity"] in ["HIGH", "CRITICAL"]:
            new_incident = Incident(
                title=f"[AI] {classification['threat_type']}: {alert.rule_description[:100]}",
                description=f"""
Incident créé automatiquement par l'IA Claude

**Analyse IA :**
{classification['analysis']}

**Type de menace :** {classification['threat_type']}
**Niveau de gravité :** {classification['severity']}
**Confiance :** {classification['confidence']}%
**Phase d'attaque :** {classification.get('attack_stage', 'Unknown')}

**Indicateurs de compromission :**
{chr(10).join('- ' + ioc for ioc in classification.get('indicators', []))}

**Actions recommandées :**
{chr(10).join('- ' + action for action in classification.get('recommendations', []))}

**Techniques MITRE ATT&CK :**
{chr(10).join('- ' + tech for tech in classification.get('related_techniques', []))}

**Alerte source :** {alert.alert_id}
**Agent concerné :** {alert.agent_name}
**Timestamp :** {alert.timestamp}
                """.strip(),
                severity=classification['severity'].lower(),
                status="open",
                source="wazuh_ai",
                created_by="AI_Claude"
            )
            
            db.add(new_incident)
            db.commit()
            db.refresh(new_incident)
            
            return {
                "status": "success",
                "message": "Incident créé automatiquement",
                "incident_id": new_incident.id,
                "classification": classification,
                "incident": {
                    "id": new_incident.id,
                    "title": new_incident.title,
                    "severity": new_incident.severity,
                    "status": new_incident.status
                }
            }
        else:
            return {
                "status": "info",
                "message": "Menace pas assez sérieuse pour créer un incident",
                "classification": classification
            }
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Erreur: {str(e)}")


@router.get("/dashboard-insights")
async def get_ai_dashboard_insights(
    hours: int = 24,
    db: Session = Depends(get_db)
):
    """
    Obtenir des insights IA pour le dashboard
    
    Analyse globale de la situation de sécurité avec :
    - Résumé exécutif
    - Tendances
    - Recommandations prioritaires
    """
    if not client:
        raise HTTPException(status_code=500, detail="Claude AI non configuré")
    
    try:
        # Récupérer données récentes
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        alerts = db.query(WazuhAlert).filter(
            WazuhAlert.timestamp >= cutoff
        ).all()
        
        incidents = db.query(Incident).filter(
            Incident.created_at >= cutoff
        ).all()
        
        # Créer un résumé
        summary = {
            "total_alerts": len(alerts),
            "total_incidents": len(incidents),
            "critical_alerts": sum(1 for a in alerts if a.rule_level and a.rule_level >= 10),
            "open_incidents": sum(1 for i in incidents if i.status == "open"),
            "incident_severities": {},
            "top_agents": {}
        }
        
        for incident in incidents:
            severity = incident.severity or "unknown"
            summary["incident_severities"][severity] = summary["incident_severities"].get(severity, 0) + 1
        
        for alert in alerts[:100]:
            agent = alert.agent_name or "unknown"
            summary["top_agents"][agent] = summary["top_agents"].get(agent, 0) + 1
        
        prompt = f"""Tu es un CISO (Chief Information Security Officer) expert.

Fournis des insights stratégiques basés sur ces données des dernières {hours}h :

```json
{json.dumps(summary, indent=2)}
```

**Fournis un JSON avec :**
1. executive_summary : Résumé exécutif en 2-3 phrases
2. security_posture : Évaluation globale ("EXCELLENT", "GOOD", "FAIR", "POOR", "CRITICAL")
3. trend : Tendance ("IMPROVING", "STABLE", "DEGRADING", "CRITICAL_DEGRADATION")
4. key_concerns : Liste de 3-4 préoccupations principales
5. priority_actions : 3 actions prioritaires immédiates
6. risk_summary : {
     "current_risk": "LOW/MEDIUM/HIGH/CRITICAL",
     "risk_factors": [liste de facteurs de risque]
   }
7. positive_indicators : 2-3 points positifs détectés
8. recommendations_for_management : Recommandations pour la direction (2-3 points)

Réponds UNIQUEMENT avec un JSON valide."""

        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            temperature=0.5,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        response_text = message.content[0].text.strip()
        
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        
        insights = json.loads(response_text.strip())
        insights["generated_at"] = datetime.utcnow().isoformat()
        insights["time_window_hours"] = hours
        
        return {
            "status": "success",
            "insights": insights,
            "raw_data": summary
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur: {str(e)}")