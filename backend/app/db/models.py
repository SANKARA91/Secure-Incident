from sqlalchemy import Column, Integer, String, Boolean
from app.db.database import Base

# Importer tous les modèles pour que SQLAlchemy les détecte
import app.models.incident
import app.models.threat
import app.models.wazuh_alert

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    is_admin = Column(Boolean, default=False)
