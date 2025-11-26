# -*- coding: utf-8 -*-
"""
Gestion de la connexion à la base de données PostgreSQL
Compatible avec SQLAlchemy 2.x et FastAPI
"""

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
import os
from typing import Generator

# URL de connexion depuis les variables d'environnement
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:admin123@localhost:5432/secure_incident"
)

# Configuration du moteur SQLAlchemy
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    pool_recycle=3600,
    echo=False
)

# Session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Base pour les modèles
Base = declarative_base()

def get_db() -> Generator[Session, None, None]:
    """Générateur de session de base de données pour FastAPI"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def test_connection() -> bool:
    """Teste la connexion à la base de données"""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            return True
    except Exception as e:
        print(f"❌ Erreur connexion DB: {e}")
        return False

def get_db_version() -> str:
    """Retourne la version de PostgreSQL"""
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT version()"))
            return result.scalar()
    except Exception as e:
        return f"Erreur: {e}"

def init_db():
    """
    Crée toutes les tables définies par Base.metadata
    À appeler au démarrage de l'application FastAPI
    """
    # CORRECTION: Utiliser directement Base au lieu d'importer depuis models
    # Cela évite les imports circulaires
    print("🔧 Création des tables si nécessaire...")
    
    # Important: importer tous les modèles pour que SQLAlchemy les connaisse
    from app.models import incident  # Ceci enregistre tous les modèles
    
    # Créer toutes les tables
    Base.metadata.create_all(bind=engine)
    print("✅ Tables créées ou déjà existantes.")

# Test rapide si ce fichier est exécuté directement
if __name__ == "__main__":
    print("🔍 Test de connexion à la base de données...")
    if test_connection():
        print("✅ Connexion réussie !")
        print(f"📊 Version: {get_db_version()}")
    else:
        print("❌ Échec de la connexion")