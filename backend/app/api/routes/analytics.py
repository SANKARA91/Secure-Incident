# -*- coding: utf-8 -*-
"""
Routes API pour les analyses et statistiques
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.models.incident import Incident, WazuhAlert
from datetime import datetime, timedelta

router = APIRouter(prefix="/analytics", tags=["Analytics"])


@router.get("/")
async def get_analytics_overview(db: Session = Depends(get_db)):
    """Vue d'ensemble des analytics"""
    total_incidents = db.query(Incident).count()
    total_alerts = db.query(WazuhAlert).count()
    
    return {
        "total_incidents": total_incidents,
        "total_alerts": total_alerts,
        "message": "Analytics disponibles"
    }


@router.get("/dashboard")
async def get_dashboard_stats(db: Session = Depends(get_db)):
    """Statistiques pour le dashboard principal"""
    
    # Incidents par statut
    open_incidents = db.query(Incident).filter(Incident.status == "open").count()
    investigating = db.query(Incident).filter(Incident.status == "investigating").count()
    resolved = db.query(Incident).filter(Incident.status == "resolved").count()
    closed = db.query(Incident).filter(Incident.status == "closed").count()
    
    # Incidents par sévérité
    critical = db.query(Incident).filter(Incident.severity == "critical").count()
    high = db.query(Incident).filter(Incident.severity == "high").count()
    medium = db.query(Incident).filter(Incident.severity == "medium").count()
    low = db.query(Incident).filter(Incident.severity == "low").count()
    
    # Alertes récentes (dernières 24h)
    yesterday = datetime.utcnow() - timedelta(days=1)
    recent_alerts = db.query(WazuhAlert).filter(
        WazuhAlert.timestamp >= yesterday
    ).count()
    
    return {
        "incidents_by_status": {
            "open": open_incidents,
            "investigating": investigating,
            "resolved": resolved,
            "closed": closed
        },
        "incidents_by_severity": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low
        },
        "recent_alerts_24h": recent_alerts,
        "total_incidents": open_incidents + investigating + resolved + closed
    }


@router.get("/trends")
async def get_trends(days: int = 7, db: Session = Depends(get_db)):
    """Tendances sur les X derniers jours"""
    cutoff = datetime.utcnow() - timedelta(days=days)
    
    recent_incidents = db.query(Incident).filter(
        Incident.created_at >= cutoff
    ).count()
    
    recent_alerts = db.query(WazuhAlert).filter(
        WazuhAlert.timestamp >= cutoff
    ).count()
    
    return {
        "period_days": days,
        "incidents_created": recent_incidents,
        "alerts_received": recent_alerts,
        "average_per_day": {
            "incidents": round(recent_incidents / days, 2),
            "alerts": round(recent_alerts / days, 2)
        }
    }