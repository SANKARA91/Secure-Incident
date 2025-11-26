# -*- coding: utf-8 -*-
from fastapi import APIRouter, HTTPException, Depends, Request
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel
import json
from app.db.database import get_db
from app.models.incident import Incident, Analysis, Action, WazuhAlert

router = APIRouter()

# ==================== SCHÉMAS PYDANTIC ====================

class IncidentCreate(BaseModel):
    title: str
    description: str
    severity: str  # low, medium, high, critical
    status: str = "open"  # open, investigating, resolved, closed
    source: Optional[str] = "manual"

class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None

class AnalysisCreate(BaseModel):
    incident_id: int
    analysis_text: str
    recommendations: Optional[str] = None

class ActionCreate(BaseModel):
    incident_id: int
    action_type: str
    description: str
    status: str = "pending"


# ==================== WEBHOOK WAZUH (EXISTANT) ====================

@router.post("/wazuh/webhook")
async def wazuh_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Endpoint pour recevoir les alertes Wazuh via webhook.
    Wazuh peut envoyer des alertes automatiquement ici.
    """
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Payload invalide")

    # Sauvegarder l'alerte Wazuh dans la base de données
    try:
        alert = WazuhAlert(
            alert_id=payload.get("id", "unknown"),
            rule_id=payload.get("rule", {}).get("id") if isinstance(payload.get("rule"), dict) else payload.get("rule", ""),
            rule_description=payload.get("rule", {}).get("description", "") if isinstance(payload.get("rule"), dict) else "",
            rule_level=payload.get("severity", 0),
            agent_name=payload.get("agent_name", ""),
            timestamp=payload.get("timestamp", datetime.utcnow()),
            data=payload  # stocke tout le JSON brut
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        
        return {
            "status": "success",
            "message": "Alerte Wazuh reçue et enregistrée",
            "alert_id": alert.id
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Erreur base de données: {str(e)}")


# ==================== INCIDENTS ====================

@router.get("/incidents")
async def get_incidents(
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Récupérer la liste des incidents
    
    - **skip**: Nombre d'incidents à sauter
    - **limit**: Nombre maximum d'incidents à retourner
    - **status**: Filtrer par statut (open, investigating, resolved, closed)
    - **severity**: Filtrer par sévérité (low, medium, high, critical)
    """
    query = db.query(Incident)
    
    if status:
        query = query.filter(Incident.status == status)
    if severity:
        query = query.filter(Incident.severity == severity)
    
    total = query.count()
    incidents = query.order_by(Incident.created_at.desc()).offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "returned": len(incidents),
        "incidents": incidents
    }


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: int, db: Session = Depends(get_db)):
    """Récupérer un incident spécifique avec ses analyses et actions"""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    
    if not incident:
        raise HTTPException(status_code=404, detail="Incident non trouvé")
    
    # Récupérer les analyses et actions associées
    analyses = db.query(Analysis).filter(Analysis.incident_id == incident_id).all()
    actions = db.query(Action).filter(Action.incident_id == incident_id).all()
    
    return {
        "incident": incident,
        "analyses": analyses,
        "actions": actions
    }


@router.post("/incidents")
async def create_incident(incident: IncidentCreate, db: Session = Depends(get_db)):
    """Créer un nouveau incident"""
    
    new_incident = Incident(
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        status=incident.status,
        source=incident.source,
        created_at=datetime.utcnow()
    )
    
    db.add(new_incident)
    db.commit()
    db.refresh(new_incident)
    
    return {
        "status": "success",
        "message": "Incident créé avec succès",
        "incident": new_incident
    }


@router.put("/incidents/{incident_id}")
async def update_incident(
    incident_id: int,
    incident_update: IncidentUpdate,
    db: Session = Depends(get_db)
):
    """Mettre à jour un incident existant"""
    
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    
    if not incident:
        raise HTTPException(status_code=404, detail="Incident non trouvé")
    
    # Mettre à jour les champs fournis
    update_data = incident_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(incident, field, value)
    
    incident.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(incident)
    
    return {
        "status": "success",
        "message": "Incident mis à jour",
        "incident": incident
    }


@router.delete("/incidents/{incident_id}")
async def delete_incident(incident_id: int, db: Session = Depends(get_db)):
    """Supprimer un incident"""
    
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    
    if not incident:
        raise HTTPException(status_code=404, detail="Incident non trouvé")
    
    db.delete(incident)
    db.commit()
    
    return {
        "status": "success",
        "message": f"Incident {incident_id} supprimé"
    }


# ==================== ANALYSES ====================

@router.post("/analyses")
async def create_analysis(analysis: AnalysisCreate, db: Session = Depends(get_db)):
    """Créer une nouvelle analyse pour un incident"""
    
    # Vérifier que l'incident existe
    incident = db.query(Incident).filter(Incident.id == analysis.incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident non trouvé")
    
    new_analysis = Analysis(
        incident_id=analysis.incident_id,
        analysis_text=analysis.analysis_text,
        recommendations=analysis.recommendations,
        created_at=datetime.utcnow()
    )
    
    db.add(new_analysis)
    db.commit()
    db.refresh(new_analysis)
    
    return {
        "status": "success",
        "message": "Analyse créée",
        "analysis": new_analysis
    }


@router.get("/analyses/{incident_id}")
async def get_analyses(incident_id: int, db: Session = Depends(get_db)):
    """Récupérer toutes les analyses d'un incident"""
    
    analyses = db.query(Analysis).filter(
        Analysis.incident_id == incident_id
    ).order_by(Analysis.created_at.desc()).all()
    
    return {
        "incident_id": incident_id,
        "total": len(analyses),
        "analyses": analyses
    }


# ==================== ACTIONS ====================

@router.post("/actions")
async def create_action(action: ActionCreate, db: Session = Depends(get_db)):
    """Créer une nouvelle action pour un incident"""
    
    # Vérifier que l'incident existe
    incident = db.query(Incident).filter(Incident.id == action.incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident non trouvé")
    
    new_action = Action(
        incident_id=action.incident_id,
        action_type=action.action_type,
        description=action.description,
        status=action.status,
        created_at=datetime.utcnow()
    )
    
    db.add(new_action)
    db.commit()
    db.refresh(new_action)
    
    return {
        "status": "success",
        "message": "Action créée",
        "action": new_action
    }


@router.get("/actions/{incident_id}")
async def get_actions(incident_id: int, db: Session = Depends(get_db)):
    """Récupérer toutes les actions d'un incident"""
    
    actions = db.query(Action).filter(
        Action.incident_id == incident_id
    ).order_by(Action.created_at.desc()).all()
    
    return {
        "incident_id": incident_id,
        "total": len(actions),
        "actions": actions
    }


@router.put("/actions/{action_id}")
async def update_action_status(
    action_id: int,
    status: str,
    db: Session = Depends(get_db)
):
    """Mettre à jour le statut d'une action"""
    
    action = db.query(Action).filter(Action.id == action_id).first()
    
    if not action:
        raise HTTPException(status_code=404, detail="Action non trouvée")
    
    action.status = status
    action.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(action)
    
    return {
        "status": "success",
        "message": "Statut de l'action mis à jour",
        "action": action
    }


# ==================== ALERTES WAZUH ====================

@router.get("/wazuh/alerts")
async def get_wazuh_alerts(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """Récupérer les alertes Wazuh stockées dans la base de données"""
    
    query = db.query(WazuhAlert)
    total = query.count()
    alerts = query.order_by(WazuhAlert.timestamp.desc()).offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "returned": len(alerts),
        "alerts": alerts
    }


# ==================== STATISTIQUES ====================

@router.get("/stats")
async def get_stats(db: Session = Depends(get_db)):
    """Obtenir des statistiques globales"""
    
    total_incidents = db.query(Incident).count()
    open_incidents = db.query(Incident).filter(Incident.status == "open").count()
    critical_incidents = db.query(Incident).filter(Incident.severity == "critical").count()
    total_alerts = db.query(WazuhAlert).count()
    
    # Incidents par sévérité
    severity_stats = {}
    for severity in ["low", "medium", "high", "critical"]:
        count = db.query(Incident).filter(Incident.severity == severity).count()
        severity_stats[severity] = count
    
    # Incidents par statut
    status_stats = {}
    for status in ["open", "investigating", "resolved", "closed"]:
        count = db.query(Incident).filter(Incident.status == status).count()
        status_stats[status] = count
    
    return {
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "critical_incidents": critical_incidents,
        "total_wazuh_alerts": total_alerts,
        "by_severity": severity_stats,
        "by_status": status_stats
    }