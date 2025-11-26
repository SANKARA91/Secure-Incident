from sqlalchemy import Column, Integer, String, Float
from app.db.database import Base


class ThreatDetection(Base):
    __tablename__ = "threat_detections"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String, nullable=False)
    threat_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    description = Column(String, nullable=True)


class BlockedAccount(Base):
    __tablename__ = "blocked_accounts"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, nullable=False)
    blocked_at = Column(String, nullable=False)
    reason = Column(String, nullable=True)


class SecurityAction(Base):
    __tablename__ = "security_actions"

    id = Column(Integer, primary_key=True, index=True)
    action_type = Column(String, nullable=False)
    target = Column(String, nullable=False)
    status = Column(String, nullable=False)
    timestamp = Column(String, nullable=True)


class UserBehaviorProfile(Base):
    __tablename__ = "user_behavior_profiles"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, nullable=False)
    risk_score = Column(Float, nullable=False)
    anomalies = Column(String, nullable=True)  # stockée en CSV
