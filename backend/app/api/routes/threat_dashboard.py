# app/routers/threat_dashboard.py
"""
API pour le dashboard de détection de menaces
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict
from datetime import datetime, timedelta

from app.db.database import get_db
from app.models import ThreatDetection, BlockedAccount, SecurityAction, UserBehaviorProfile

router = APIRouter(prefix="/api/threats", tags=["threats"])


@router.get("/dashboard")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Statistiques du dashboard"""
    
    now = datetime.now()
    today = now.date()
    this_week = now - timedelta(days=7)
    
    # Menaces par période
    threats_today = db.query(ThreatDetection).filter(
        ThreatDetection.timestamp >= today
    ).count()
    
    threats_week = db.query(ThreatDetection).filter(
        ThreatDetection.timestamp >= this_week
    ).count()
    
    # Comptes bloqués actifs
    blocked_count = db.query(BlockedAccount).filter(
        BlockedAccount.is_blocked == True
    ).count()
    
    # Menaces par sévérité (cette semaine)
    threats_by_severity = db.query(
        ThreatDetection.severity,
        db.func.count(ThreatDetection.id)
    ).filter(
        ThreatDetection.timestamp >= this_week
    ).group_by(ThreatDetection.severity).all()
    
    # Menaces par type
    threats_by_type = db.query(
        ThreatDetection.threat_type,
        db.func.count(ThreatDetection.id)
    ).filter(
        ThreatDetection.timestamp >= this_week
    ).group_by(ThreatDetection.threat_type).all()
    
    # Utilisateurs à risque
    high_risk_users = db.query(UserBehaviorProfile).filter(
        UserBehaviorProfile.risk_score >= 70
    ).order_by(UserBehaviorProfile.risk_score.desc()).limit(10).all()
    
    return {
        "summary": {
            "threats_today": threats_today,
            "threats_this_week": threats_week,
            "accounts_blocked": blocked_count,
            "high_risk_users": len(high_risk_users)
        },
        "threats_by_severity": {
            s: c for s, c in threats_by_severity
        },
        "threats_by_type": {
            t: c for t, c in threats_by_type
        },
        "high_risk_users": [
            {
                "username": u.username,
                "domain": u.domain,
                "risk_score": u.risk_score,
                "threat_count": u.threat_count
            }
            for u in high_risk_users
        ]
    }


@router.get("/recent")
def get_recent_threats(
    limit: int = 20,
    severity: str = None,
    db: Session = Depends(get_db)
):
    """Menaces récentes"""
    
    query = db.query(ThreatDetection).order_by(
        ThreatDetection.timestamp.desc()
    )
    
    if severity:
        query = query.filter(ThreatDetection.severity == severity.upper())
    
    threats = query.limit(limit).all()
    
    return {
        "total": query.count(),
        "threats": [
            {
                "id": t.id,
                "timestamp": t.timestamp.isoformat(),
                "type": t.threat_type,
                "severity": t.severity,
                "username": t.username,
                "domain": t.domain,
                "description": t.description,
                "ai_confidence": t.ai_confidence,
                "ai_recommendation": t.ai_recommendation,
                "action_taken": t.action_taken,
                "action_status": t.action_status
            }
            for t in threats
        ]
    }


@router.get("/threat/{threat_id}")
def get_threat_details(threat_id: int, db: Session = Depends(get_db)):
    """Détails d'une menace spécifique"""
    
    threat = db.query(ThreatDetection).filter(
        ThreatDetection.id == threat_id
    ).first()
    
    if not threat:
        raise HTTPException(status_code=404, detail="Menace non trouvée")
    
    return {
        "id": threat.id,
        "timestamp": threat.timestamp.isoformat(),
        "type": threat.threat_type,
        "severity": threat.severity,
        "username": threat.username,
        "domain": threat.domain,
        "description": threat.description,
        "details": threat.details,
        "evidence": threat.evidence,
        "ai_analysis": {
            "confidence": threat.ai_confidence,
            "recommendation": threat.ai_recommendation,
            "reasoning": threat.ai_reasoning,
            "false_positive_probability": threat.false_positive_probability
        },
        "action": {
            "taken": threat.action_taken,
            "timestamp": threat.action_timestamp.isoformat() if threat.action_timestamp else None,
            "status": threat.action_status,
            "details": threat.action_details
        },
        "investigation": {
            "investigated": threat.investigated,
            "investigator": threat.investigator,
            "notes": threat.investigation_notes,
            "resolution": threat.resolution
        }
    }


@router.get("/blocked-accounts")
def get_blocked_accounts(
    active_only: bool = True,
    db: Session = Depends(get_db)
):
    """Liste des comptes bloqués"""
    
    query = db.query(BlockedAccount)
    
    if active_only:
        query = query.filter(BlockedAccount.is_blocked == True)
    
    accounts = query.order_by(BlockedAccount.timestamp.desc()).all()
    
    return {
        "total": len(accounts),
        "accounts": [
            {
                "id": a.id,
                "username": a.username,
                "domain": a.domain,
                "blocked_timestamp": a.timestamp.isoformat(),
                "reason": a.reason,
                "is_blocked": a.is_blocked,
                "unblocked_timestamp": a.unblocked_timestamp.isoformat() if a.unblocked_timestamp else None,
                "unblocked_by": a.unblocked_by,
                "reviewed": a.reviewed
            }
            for a in accounts
        ]
    }


@router.post("/unblock-account/{account_id}")
def unblock_account(
    account_id: int,
    reason: str,
    unblocked_by: str,
    db: Session = Depends(get_db)
):
    """Débloquer un compte"""
    
    account = db.query(BlockedAccount).filter(
        BlockedAccount.id == account_id
    ).first()
    
    if not account:
        raise HTTPException(status_code=404, detail="Compte non trouvé")
    
    account.is_blocked = False
    account.unblocked_timestamp = datetime.now()
    account.unblocked_by = unblocked_by
    account.unblock_reason = reason
    
    # Logger l'action
    action = SecurityAction(
        action_type="UNBLOCK",
        target_type="USER",
        target=f"{account.domain}\\{account.username}",
        reason=reason,
        triggered_by="MANUAL",
        status="SUCCESS",
        executed_by=unblocked_by
    )
    db.add(action)
    
    db.commit()
    
    return {
        "success": True,
        "message": f"Compte {account.username} débloqué",
        "account": {
            "username": account.username,
            "domain": account.domain,
            "unblocked_at": account.unblocked_timestamp.isoformat()
        }
    }


@router.post("/investigate-threat/{threat_id}")
def investigate_threat(
    threat_id: int,
    investigator: str,
    notes: str,
    resolution: str,
    db: Session = Depends(get_db)
):
    """Marquer une menace comme investiguée"""
    
    threat = db.query(ThreatDetection).filter(
        ThreatDetection.id == threat_id
    ).first()
    
    if not threat:
        raise HTTPException(status_code=404, detail="Menace non trouvée")
    
    threat.investigated = True
    threat.investigator = investigator
    threat.investigation_notes = notes
    threat.resolution = resolution
    
    db.commit()
    
    return {
        "success": True,
        "message": "Investigation enregistrée",
        "threat_id": threat_id
    }


@router.get("/security-actions")
def get_security_actions(
    limit: int = 50,
    action_type: str = None,
    db: Session = Depends(get_db)
):
    """Historique des actions de sécurité"""
    
    query = db.query(SecurityAction).order_by(
        SecurityAction.timestamp.desc()
    )
    
    if action_type:
        query = query.filter(SecurityAction.action_type == action_type.upper())
    
    actions = query.limit(limit).all()
    
    return {
        "total": query.count(),
        "actions": [
            {
                "id": a.id,
                "timestamp": a.timestamp.isoformat(),
                "action_type": a.action_type,
                "target": a.target,
                "reason": a.reason,
                "triggered_by": a.triggered_by,
                "status": a.status,
                "executed_by": a.executed_by
            }
            for a in actions
        ]
    }


@router.get("/user-profile/{username}")
def get_user_profile(username: str, db: Session = Depends(get_db)):
    """Profil comportemental d'un utilisateur"""
    
    profile = db.query(UserBehaviorProfile).filter(
        UserBehaviorProfile.username == username
    ).first()
    
    if not profile:
        raise HTTPException(status_code=404, detail="Profil non trouvé")
    
    # Récupérer les menaces associées
    threats = db.query(ThreatDetection).filter(
        ThreatDetection.username.contains(username)
    ).order_by(ThreatDetection.timestamp.desc()).limit(10).all()
    
    return {
        "profile": {
            "username": profile.username,
            "domain": profile.domain,
            "risk_score": profile.risk_score,
            "total_logins": profile.total_logins,
            "failed_logins": profile.failed_logins,
            "threat_count": profile.threat_count,
            "average_login_hour": profile.average_login_hour,
            "typical_login_days": profile.typical_login_days,
            "typical_ips": profile.typical_ips,
            "first_seen": profile.first_seen.isoformat(),
            "last_seen": profile.last_seen.isoformat(),
            "is_monitored": profile.is_monitored,
            "is_whitelisted": profile.is_whitelisted
        },
        "recent_threats": [
            {
                "id": t.id,
                "timestamp": t.timestamp.isoformat(),
                "type": t.threat_type,
                "severity": t.severity,
                "action_taken": t.action_taken
            }
            for t in threats
        ]
    }


@router.get("/statistics/timeline")
def get_threat_timeline(
    days: int = 7,
    db: Session = Depends(get_db)
):
    """Timeline des menaces sur X jours"""
    
    start_date = datetime.now() - timedelta(days=days)
    
    # Menaces par jour
    daily_threats = db.query(
        db.func.date(ThreatDetection.timestamp).label('date'),
        ThreatDetection.severity,
        db.func.count(ThreatDetection.id).label('count')
    ).filter(
        ThreatDetection.timestamp >= start_date
    ).group_by('date', ThreatDetection.severity).all()
    
    # Organiser par date
    timeline = {}
    for date, severity, count in daily_threats:
        date_str = str(date)
        if date_str not in timeline:
            timeline[date_str] = {}
        timeline[date_str][severity] = count
    
    return {
        "days": days,
        "timeline": timeline
    }


# Ajouter ce router dans main.py
# from app.routers import threat_dashboard
# app.include_router(threat_dashboard.router)