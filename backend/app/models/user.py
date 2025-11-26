# app/models.py - Ajouter ces modèles

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()


class ThreatDetection(Base):
    """Menaces détectées par le système"""
    __tablename__ = "threat_detections"
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.now, nullable=False)
    
    # Informations sur la menace
    threat_type = Column(String(100), nullable=False)  # connexions_rapides, heures_inhabituelles, etc.
    severity = Column(String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    username = Column(String(255), nullable=False)
    domain = Column(String(100))
    description = Column(Text)
    
    # Détails techniques
    details = Column(JSON)  # IPs, timestamps, etc.
    evidence = Column(JSON)  # Événements bruts
    
    # Analyse IA
    ai_confidence = Column(Integer)  # 0-100
    ai_recommendation = Column(String(50))  # MONITOR, ALERT, BLOCK
    ai_reasoning = Column(Text)
    false_positive_probability = Column(Integer)
    
    # Action prise
    action_taken = Column(String(50))  # NONE, ALERTED, BLOCKED
    action_timestamp = Column(DateTime)
    action_status = Column(String(50))  # PENDING, SUCCESS, FAILED
    action_details = Column(Text)
    
    # Investigation
    investigated = Column(Boolean, default=False)
    investigator = Column(String(100))
    investigation_notes = Column(Text)
    resolution = Column(String(50))  # FALSE_POSITIVE, CONFIRMED_THREAT, RESOLVED
    
    def __repr__(self):
        return f"<ThreatDetection {self.threat_type} - {self.username} at {self.timestamp}>"


class BlockedAccount(Base):
    """Comptes bloqués par le système"""
    __tablename__ = "blocked_accounts"
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.now, nullable=False)
    
    # Compte
    username = Column(String(255), nullable=False)
    domain = Column(String(100))
    
    # Raison du blocage
    reason = Column(Text, nullable=False)
    threat_id = Column(Integer)  # Lien vers ThreatDetection
    
    # Statut
    is_blocked = Column(Boolean, default=True)
    unblocked_timestamp = Column(DateTime)
    unblocked_by = Column(String(100))
    unblock_reason = Column(Text)
    
    # Metadata
    blocked_by = Column(String(100), default="AI_SYSTEM")
    reviewed = Column(Boolean, default=False)
    reviewer = Column(String(100))
    review_notes = Column(Text)
    
    def __repr__(self):
        return f"<BlockedAccount {self.domain}\\{self.username} - {'BLOCKED' if self.is_blocked else 'UNBLOCKED'}>"


class SecurityAction(Base):
    """Log de toutes les actions de sécurité"""
    __tablename__ = "security_actions"
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.now, nullable=False)
    
    # Action
    action_type = Column(String(50), nullable=False)  # BLOCK, UNBLOCK, ALERT, MONITOR
    target_type = Column(String(50))  # USER, IP, DEVICE
    target = Column(String(255), nullable=False)
    
    # Contexte
    reason = Column(Text)
    triggered_by = Column(String(100))  # AI_SYSTEM, ADMIN_USER, RULE_ENGINE
    related_threat_id = Column(Integer)
    
    # Résultat
    status = Column(String(50))  # SUCCESS, FAILED, PENDING
    error_message = Column(Text)
    
    # Audit
    executed_by = Column(String(100))
    reviewed = Column(Boolean, default=False)
    
    def __repr__(self):
        return f"<SecurityAction {self.action_type} on {self.target} - {self.status}>"


class UserBehaviorProfile(Base):
    """Profil comportemental des utilisateurs"""
    __tablename__ = "user_behavior_profiles"
    
    id = Column(Integer, primary_key=True)
    username = Column(String(255), nullable=False, unique=True)
    domain = Column(String(100))
    
    # Statistiques de connexion
    average_login_hour = Column(Integer)  # Heure moyenne de connexion
    typical_login_days = Column(JSON)  # [1,2,3,4,5] = lundi-vendredi
    typical_ips = Column(JSON)  # Liste des IPs habituelles
    typical_workstations = Column(JSON)
    
    # Compteurs
    total_logins = Column(Integer, default=0)
    failed_logins = Column(Integer, default=0)
    threat_count = Column(Integer, default=0)
    
    # Dates
    first_seen = Column(DateTime, default=datetime.now)
    last_seen = Column(DateTime, default=datetime.now)
    last_updated = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    
    # Statut
    risk_score = Column(Integer, default=0)  # 0-100
    is_monitored = Column(Boolean, default=False)
    is_whitelisted = Column(Boolean, default=False)
    
    def __repr__(self):
        return f"<UserBehaviorProfile {self.username} - Risk: {self.risk_score}>"


# Script de création des tables
def create_threat_tables():
    """Crée les tables pour le système de détection de menaces"""
    from app.database import engine
    
    print("📊 Création des tables de détection de menaces...")
    
    ThreatDetection.__table__.create(engine, checkfirst=True)
    BlockedAccount.__table__.create(engine, checkfirst=True)
    SecurityAction.__table__.create(engine, checkfirst=True)
    UserBehaviorProfile.__table__.create(engine, checkfirst=True)
    
    print("✅ Tables créées avec succès!")
    
    # Créer quelques exemples
    from app.database import SessionLocal
    db = SessionLocal()
    
    try:
        # Exemple de profil utilisateur
        if not db.query(UserBehaviorProfile).filter_by(username="Administrateur").first():
            admin_profile = UserBehaviorProfile(
                username="Administrateur",
                domain="LUTIN",
                average_login_hour=9,
                typical_login_days=[1, 2, 3, 4, 5],
                typical_ips=["192.168.1.10", "192.168.1.100"],
                risk_score=0
            )
            db.add(admin_profile)
            db.commit()
            print("✅ Profil administrateur créé")
    
    except Exception as e:
        print(f"⚠️ Erreur création exemples: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    create_threat_tables()