"""
Test complet du système Secure Incident - Version corrigée (SQLAlchemy 2.x)
Adapté à votre structure existante
"""
from dotenv import load_dotenv
load_dotenv()
import os
import sys
from pathlib import Path

# Ajouter le dossier parent au path
sys.path.insert(0, str(Path(__file__).parent))

def print_section(title, emoji=""):
    """Affiche une section formatée"""
    print(f"\n{emoji} {title}")
    print("=" * 70)

def print_result(label, value, is_success=None):
    """Affiche un résultat formaté"""
    if is_success is None:
        status = ""
    elif is_success:
        status = "✅"
    else:
        status = "❌"
    
    # Masquer partiellement les secrets
    if "KEY" in label or "PASSWORD" in label:
        if value and len(value) > 10:
            value = f"***{value[-6:]}"
    
    print(f"{status} {label:30} → {value}")

def test_env_variables():
    """Test 1: Vérification des variables d'environnement"""
    print_section("Variables d'environnement", "1️⃣")
    
    required_vars = {
        "DATABASE_URL": os.getenv("DATABASE_URL"),
        "WAZUH_URL": os.getenv("WAZUH_URL"),
        "WAZUH_USERNAME": os.getenv("WAZUH_USERNAME"),
        "WAZUH_PASSWORD": os.getenv("WAZUH_PASSWORD"),
        "ANTHROPIC_API_KEY": os.getenv("ANTHROPIC_API_KEY"),
        "THREAT_DETECTION_ENABLED": os.getenv("THREAT_DETECTION_ENABLED"),
    }
    
    for var, value in required_vars.items():
        print_result(var, value or "❌ Non défini", bool(value))
    
    return all(required_vars.values())

def test_database():
    """Test 2: Connexion PostgreSQL (corrigé pour SQLAlchemy 2.x)"""
    print_section("Test connexion PostgreSQL", "2️⃣")
    
    try:
        from app.db.database import engine
        from sqlalchemy import text

        with engine.connect() as conn:
            result = conn.execute(text("SELECT version()"))
            version = result.scalar()
            print_result("Connexion PostgreSQL", "✅ Connecté", True)
            print(f"   Version: {version.split(',')[0]}")
            return True
            
    except ImportError:
        print_result("Import app.db.database", "❌ Module introuvable", False)
        print("   💡 Créez le fichier app/db/database.py")
        return False
    except Exception as e:
        print_result("Connexion DB", f"❌ Erreur: {str(e)[:80]}", False)
        return False

def test_wazuh():
    """Test 3: Connexion Wazuh (VM) - gestion JSON ou JWT brut"""
    print_section("Test connexion Wazuh (VM)", "3️⃣")
    
    try:
        import requests
        from requests.auth import HTTPBasicAuth
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        wazuh_url = os.getenv("WAZUH_URL")
        username = os.getenv("WAZUH_USERNAME")
        password = os.getenv("WAZUH_PASSWORD")
        
        if not all([wazuh_url, username, password]):
            print_result("Configuration Wazuh", "❌ Variables manquantes", False)
            return False
        
        url = f"{wazuh_url}/security/user/authenticate"
        response = requests.post(
            url,
            auth=HTTPBasicAuth(username, password),
            verify=False,
            timeout=10,
            params={"raw": "true"}  # Wazuh renvoie JWT brut
        )
        
        if response.status_code == 200:
            token = None
            try:
                token = response.json().get("data", {}).get("token")
            except ValueError:
                token = response.text.strip()
            
            if token:
                print_result("Connexion Wazuh", "✅ Connecté", True)
                print(f"   Token obtenu: {token[:20]}...")
                return True
            else:
                print_result("Connexion Wazuh", "❌ Token introuvable", False)
                return False
        else:
            print_result("Authentification Wazuh", f"❌ HTTP {response.status_code}", False)
            return False
            
    except requests.exceptions.Timeout:
        print_result("Connexion Wazuh", "❌ Timeout (VM inaccessible?)", False)
        print("   💡 Vérifiez que la VM Wazuh est démarrée")
        return False
    except Exception as e:
        print_result("Erreur Wazuh", f"❌ {str(e)[:80]}", False)
        return False

def test_anthropic():
    """Test 4: API Anthropic Claude"""
    print_section("Test connexion Anthropic IA (Claude)", "4️⃣")
    
    try:
        import anthropic
        
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key or not api_key.startswith("sk-ant-"):
            print_result("Format clé API", "❌ Clé invalide ou manquante", False)
            print("   💡 La clé doit commencer par 'sk-ant-'")
            return False
        
        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=50,
            messages=[{"role": "user", "content": "Réponds juste: OK"}]
        )
        
        response = message.content[0].text
        print_result("API Anthropic", "✅ Connecté", True)
        print(f"   Réponse: {response}")
        return True
        
    except anthropic.AuthenticationError:
        print_result("Authentification Claude", "❌ Clé API invalide", False)
        print("   💡 Vérifiez votre clé sur https://console.anthropic.com/settings/keys")
        return False
    except Exception as e:
        print_result("Erreur Claude", f"❌ {str(e)[:100]}", False)
        return False

def test_database_tables():
    """Test 5: Vérification des tables"""
    print_section("Vérification des tables", "5️⃣")
    
    try:
        from app.db.database import engine
        from sqlalchemy import inspect
        
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        
        expected_tables = ["incidents", "analyses", "actions", "wazuh_alerts"]
        
        if not tables:
            print_result("Tables", "❌ Aucune table trouvée", False)
            print("   💡 Exécutez: python -c \"from app.models.incident import Base; from app.db.database import engine; Base.metadata.create_all(engine)\"")
            return False
        
        print_result("Tables trouvées", f"{len(tables)} table(s)", True)
        for table in tables:
            status = "✅" if table in expected_tables else "ℹ️"
            print(f"   {status} {table}")
        
        missing = set(expected_tables) - set(tables)
        if missing:
            print(f"\n   ⚠️ Tables manquantes: {', '.join(missing)}")
            return False
            
        return True
        
    except ImportError as e:
        print_result("Import models", f"❌ {str(e)}", False)
        return False
    except Exception as e:
        print_result("Erreur tables", f"❌ {str(e)[:80]}", False)
        return False

def test_file_structure():
    """Test bonus: Structure des fichiers"""
    print_section("Structure des fichiers", "📁")
    
    required_files = {
        "app/__init__.py": "Package principal",
        "app/db/database.py": "Connexion DB",
        "app/models/incident.py": "Modèles incidents",
        "app/api/api_v1.py": "Routes API",
        "app/core/config.py": "Configuration",
        ".env": "Variables d'environnement"
    }
    
    all_exist = True
    for file_path, description in required_files.items():
        exists = Path(file_path).exists()
        print_result(file_path, description, exists)
        all_exist = all_exist and exists
    
    return all_exist

def main():
    """Fonction principale"""
    print("\n" + "=" * 70)
    print("🔍 Test complet du système Secure Incident")
    print("=" * 70)
    
    results = {
        "Variables d'env": test_env_variables(),
        "PostgreSQL": test_database(),
        "Wazuh": test_wazuh(),
        "Claude IA": test_anthropic(),
        "Tables DB": test_database_tables(),
        "Structure": test_file_structure()
    }
    
    # Résumé
    print("\n" + "=" * 70)
    print("📊 RÉSUMÉ DES TESTS")
    print("=" * 70)
    
    for test_name, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}")
    
    total = len(results)
    passed = sum(results.values())
    
    print("\n" + "=" * 70)
    print(f"🎯 Score: {passed}/{total} tests réussis ({passed*100//total}%)")
    print("=" * 70)
    
    if passed == total:
        print("\n🎉 Excellent ! Tous les tests sont passés !")
        print("Vous pouvez lancer l'application: uvicorn app.main:app --reload")
    else:
        print("\n⚠️ Certains tests ont échoué. Vérifiez les erreurs ci-dessus.")

if __name__ == "__main__":
    main()
