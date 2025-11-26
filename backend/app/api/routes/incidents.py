# -*- coding: utf-8 -*-
"""
Routes API pour la gestion des incidents de sécurité
"""
from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

from app.db.database import get_db
from app.models.incident import Incident
from app.db.schemas import IncidentCreate, IncidentUpdate, IncidentResponse

# IMPORTANT: La variable doit s'appeler 'router'
router = APIRouter(
    prefix="/incidents",
    tags=["Incidents"]
)


@router.get("/", response_model=List[IncidentResponse])
async def get_incidents(
    skip: int = 0,
    limit: int = 100,
    status_filter: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Récupérer la liste de tous les incidents
    
    - **skip**: Nombre d'incidents à ignorer (pagination)
    - **limit**: Nombre maximum d'incidents à retourner
    - **status_filter**: Filtrer par statut (open, investigating, resolved, closed)
    - **severity**: Filtrer par sévérité (low, medium, high, critical)
    """
    query = db.query(Incident)
    
    if status_filter:
        query = query.filter(Incident.status == status_filter)
    
    if severity:
        query = query.filter(Incident.severity == severity)
    
    incidents = query.offset(skip).limit(limit).all()
    return incidents


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: int,
    db: Session = Depends(get_db)
):
    """
    Récupérer un incident spécifique par son ID
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} non trouvé"
        )
    
    return incident


@router.post("/", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    incident: IncidentCreate,
    db: Session = Depends(get_db)
):
    """
    Créer un nouvel incident
    
    Exemple de body:
    ```json
    {
        "title": "Tentative d'intrusion détectée",
        "description": "Plusieurs échecs de connexion sur le serveur web",
        "severity": "high",
        "status": "open",
        "source": "wazuh"
    }
    ```
    """
    new_incident = Incident(
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        status=incident.status or "open",
        source=incident.source or "manual",
        created_at=datetime.utcnow()
    )
    
    db.add(new_incident)
    db.commit()
    db.refresh(new_incident)
    
    return new_incident


@router.put("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: int,
    incident_update: IncidentUpdate,
    db: Session = Depends(get_db)
):
    """
    Mettre à jour un incident existant
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} non trouvé"
        )
    
    # Mettre à jour uniquement les champs fournis
    update_data = incident_update.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(incident, key, value)
    
    incident.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(incident)
    
    return incident


@router.delete("/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_incident(
    incident_id: int,
    db: Session = Depends(get_db)
):
    """
    Supprimer un incident
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} non trouvé"
        )
    
    db.delete(incident)
    db.commit()
    
    return None


@router.get("/stats/summary")
async def get_incidents_summary(db: Session = Depends(get_db)):
    """
    Obtenir un résumé des incidents
    
    Retourne le nombre d'incidents par statut et par sévérité
    """
    total = db.query(Incident).count()
    
    # Par statut
    open_count = db.query(Incident).filter(Incident.status == "open").count()
    investigating_count = db.query(Incident).filter(Incident.status == "investigating").count()
    resolved_count = db.query(Incident).filter(Incident.status == "resolved").count()
    closed_count = db.query(Incident).filter(Incident.status == "closed").count()
    
    # Par sévérité
    low_count = db.query(Incident).filter(Incident.severity == "low").count()
    medium_count = db.query(Incident).filter(Incident.severity == "medium").count()
    high_count = db.query(Incident).filter(Incident.severity == "high").count()
    critical_count = db.query(Incident).filter(Incident.severity == "critical").count()
    
    return {
        "total": total,
        "by_status": {
            "open": open_count,
            "investigating": investigating_count,
            "resolved": resolved_count,
            "closed": closed_count
        },
        "by_severity": {
            "low": low_count,
            "medium": medium_count,
            "high": high_count,
            "critical": critical_count
        }
    }


@router.patch("/{incident_id}/status")
async def change_incident_status(
    incident_id: int,
    new_status: str,
    db: Session = Depends(get_db)
):
    """
    Changer uniquement le statut d'un incident
    
    Statuts valides: open, investigating, resolved, closed
    """
    valid_statuses = ["open", "investigating", "resolved", "closed"]
    
    if new_status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Statut invalide. Statuts valides: {', '.join(valid_statuses)}"
        )
    
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} non trouvé"
        )
    
    incident.status = new_status
    incident.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(incident)
    
    return {
        "message": f"Statut de l'incident {incident_id} changé en '{new_status}'",
        "incident": incident
    }


@router.get("/search/by-title")
async def search_incidents_by_title(
    query: str,
    db: Session = Depends(get_db)
):
    """
    Rechercher des incidents par titre
    """
    incidents = db.query(Incident).filter(
        Incident.title.ilike(f"%{query}%")
    ).all()
    
    return {
        "query": query,
        "results": len(incidents),
        "incidents": incidents
    }