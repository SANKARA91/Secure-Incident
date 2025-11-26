# -*- coding: utf-8 -*-
"""
Schémas Pydantic pour la validation des données
À placer dans app/db/schemas.py
"""
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


# ============================================
# SCHÉMAS POUR LES INCIDENTS
# ============================================

class IncidentBase(BaseModel):
    """Schéma de base pour un incident"""
    title: str = Field(..., min_length=3, max_length=200, description="Titre de l'incident")
    description: Optional[str] = Field(None, description="Description détaillée")
    severity: str = Field(..., description="Sévérité: low, medium, high, critical")
    status: Optional[str] = Field("open", description="Statut: open, investigating, resolved, closed")
    source: Optional[str] = Field("manual", description="Source de l'incident: manual, wazuh, ai, etc.")


class IncidentCreate(IncidentBase):
    """Schéma pour créer un incident"""
    pass


class IncidentUpdate(BaseModel):
    """Schéma pour mettre à jour un incident (tous les champs optionnels)"""
    title: Optional[str] = Field(None, min_length=3, max_length=200)
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    source: Optional[str] = None


class IncidentResponse(IncidentBase):
    """Schéma de réponse pour un incident (inclut les champs auto-générés)"""
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    created_by: Optional[str] = None
    assigned_to: Optional[str] = None
    
    class Config:
        from_attributes = True  # Pydantic v2 (remplace orm_mode = True)


# ============================================
# SCHÉMAS POUR LES ALERTES WAZUH
# ============================================

class WazuhAlertBase(BaseModel):
    """Schéma de base pour une alerte Wazuh"""
    alert_id: str
    timestamp: datetime
    rule_id: Optional[str] = None
    rule_description: Optional[str] = None
    rule_level: Optional[int] = None
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    full_log: Optional[str] = None


class WazuhAlertCreate(WazuhAlertBase):
    """Schéma pour créer une alerte Wazuh"""
    data: Optional[dict] = None


class WazuhAlertResponse(WazuhAlertBase):
    """Schéma de réponse pour une alerte Wazuh"""
    id: int
    data: Optional[dict] = None
    
    class Config:
        from_attributes = True


# ============================================
# SCHÉMAS POUR L'AUTHENTIFICATION
# ============================================

class UserBase(BaseModel):
    """Schéma de base pour un utilisateur"""
    username: str = Field(..., min_length=3, max_length=50)
    email: Optional[str] = None
    full_name: Optional[str] = None


class UserCreate(UserBase):
    """Schéma pour créer un utilisateur"""
    password: str = Field(..., min_length=8)


class UserResponse(UserBase):
    """Schéma de réponse pour un utilisateur"""
    id: int
    is_active: bool = True
    is_admin: bool = False
    created_at: datetime
    
    class Config:
        from_attributes = True


class Token(BaseModel):
    """Schéma pour le token JWT"""
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    """Données contenues dans le token"""
    username: Optional[str] = None


# ============================================
# SCHÉMAS POUR LES STATISTIQUES
# ============================================

class IncidentStats(BaseModel):
    """Statistiques des incidents"""
    total: int
    by_status: dict
    by_severity: dict


class AlertStats(BaseModel):
    """Statistiques des alertes"""
    total: int
    critical: int
    high: int
    medium: int
    low: int
    by_agent: dict


# ============================================
# SCHÉMAS POUR L'IA
# ============================================

class ThreatClassification(BaseModel):
    """Résultat de classification d'une menace par l'IA"""
    threat_type: str
    severity: str
    confidence: float
    indicators: list
    attack_stage: str
    recommendations: list
    analysis: str
    related_techniques: list


class IncidentPrediction(BaseModel):
    """Prédiction d'incident par l'IA"""
    risk_level: str
    incident_probability: float
    attack_indicators: list
    predicted_scenarios: list
    time_to_potential_breach: str
    vulnerable_assets: list
    preventive_actions: list
    monitoring_focus: list
    analysis_summary: str


class AnomalyDetection(BaseModel):
    """Détection d'anomalies par l'IA"""
    anomalies_detected: int
    anomaly_score: float
    is_suspicious: bool
    detected_anomalies: list
    normal_deviations: dict
    recommended_actions: list
    summary: str