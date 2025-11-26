# backend/app/models/wazuh_alert.py
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Float, Boolean
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, unique=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    agent_id = Column(String, index=True)
    agent_name = Column(String, index=True)
    rule_id = Column(String, index=True)
    rule_description = Column(Text)
    rule_level = Column(Integer, index=True)
    rule_groups = Column(String)
    full_log = Column(Text)
    data_json = Column(JSON)
    processed = Column(Boolean, default=False)
    anomaly_score = Column(Float, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class SecurityLog(Base):
    __tablename__ = "security_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source = Column(String, index=True)
    event_type = Column(String, index=True)
    event_id = Column(String)
    user = Column(String, index=True)
    source_ip = Column(String, index=True)
    severity = Column(Integer)
    description = Column(Text)
    raw_log = Column(Text)
    anomaly_detected = Column(Boolean, default=False)
    cluster_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Agent(Base):
    __tablename__ = "agents"
    
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String, unique=True, index=True)
    name = Column(String)
    ip = Column(String)
    status = Column(String)
    os_name = Column(String)
    os_version = Column(String)
    version = Column(String)
    last_keepalive = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class IAAnalysis(Base):
    __tablename__ = "ia_analysis"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, index=True)
    analysis_type = Column(String)
    result = Column(JSON)
    confidence_score = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)