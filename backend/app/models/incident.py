# -*- coding: utf-8 -*-
"""
Modèles SQLAlchemy pour la base de données
Définit les tables: incidents, analyses, actions, wazuh_alerts
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
from app.db.database import Base


class Incident(Base):
    """
    Table des incidents de sécurité
    """
    __tablename__ = "incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(50), nullable=False)  # low, medium, high, critical
    status = Column(String(50), nullable=False, default="open")  # open, investigating, resolved, closed
    source = Column(String(100), default="manual")  # manual, wazuh, api, etc.
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relations
    analyses = relationship("Analysis", back_populates="incident", cascade="all, delete-orphan")
    actions = relationship("Action", back_populates="incident", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Incident {self.id}: {self.title}>"


class Analysis(Base):
    """
    Table des analyses d'incidents (générées par l'IA ou manuellement)
    """
    __tablename__ = "analyses"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    
    analysis_text = Column(Text, nullable=False)
    recommendations = Column(Text)
    confidence_score = Column(Integer)  # Score de confiance 0-100
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relation
    incident = relationship("Incident", back_populates="analyses")
    
    def __repr__(self):
        return f"<Analysis {self.id} for Incident {self.incident_id}>"


class Action(Base):
    """
    Table des actions de remédiation
    """
    __tablename__ = "actions"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    
    action_type = Column(String(100), nullable=False)  # block_ip, isolate_host, etc.
    description = Column(Text, nullable=False)
    status = Column(String(50), default="pending")  # pending, in_progress, completed, failed
    
    executed_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relation
    incident = relationship("Incident", back_populates="actions")
    
    def __repr__(self):
        return f"<Action {self.id}: {self.action_type}>"


class WazuhAlert(Base):
    """
    Table des alertes Wazuh reçues
    """
    __tablename__ = "wazuh_alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(255), unique=True, index=True)  # ID unique de l'alerte Wazuh
    
    timestamp = Column(DateTime, nullable=False)
    rule_id = Column(String(50))
    rule_description = Column(Text)
    rule_level = Column(Integer)  # Niveau de sévérité 0-15
    
    agent_id = Column(String(50))
    agent_name = Column(String(255))
    
    full_log = Column(Text)
    data = Column(JSON)  # Stocke tout le JSON de l'alerte
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<WazuhAlert {self.alert_id}: Level {self.rule_level}>"