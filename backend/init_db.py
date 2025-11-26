import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, text

load_dotenv()

print("=" * 70)
print("🗄️  INITIALISATION DE LA BASE DE DONNÉES")
print("=" * 70 + "\n")

database_url = os.getenv("DATABASE_URL")

if not database_url:
    print("❌ DATABASE_URL non définie\n")
    exit(1)

try:
    print("🔄 Connexion à PostgreSQL...")
    engine = create_engine(database_url)
    
    with engine.connect() as conn:
        result = conn.execute(text("SELECT version();"))
        version = result.fetchone()[0]
        print(f"✅ Connecté à PostgreSQL")
        print(f"   {version.split(',')[0]}\n")
    
    print("🔄 Création des tables...")
    from app.db.database import Base
    from app.models.incident import Incident, Alert, ThreatAnalysis
    
    Base.metadata.create_all(bind=engine)
    
    with engine.connect() as conn:
        result = conn.execute(text("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
            ORDER BY table_name;
        """))
        tables = [row[0] for row in result]
    
    if tables:
        print(f"✅ Tables créées:")
        for table in tables:
            print(f"   - {table}")
    else:
        print("⚠️  Aucune table créée")
    
    print(f"\n🎉 Base de données prête!\n")
    
except Exception as e:
    print(f"❌ Erreur: {e}\n")

print("=" * 70)