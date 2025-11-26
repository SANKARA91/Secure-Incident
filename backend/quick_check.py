import os
from dotenv import load_dotenv

load_dotenv()

print("=" * 70)
print("🔍 VÉRIFICATION RAPIDE DES VARIABLES D'ENVIRONNEMENT")
print("=" * 70 + "\n")

checks = {
    "DATABASE_URL": os.getenv("DATABASE_URL"),
    "WAZUH_URL": os.getenv("WAZUH_URL"),
    "WAZUH_USERNAME": os.getenv("WAZUH_USERNAME"),
    "WAZUH_PASSWORD": os.getenv("WAZUH_PASSWORD"),
    "ANTHROPIC_API_KEY": os.getenv("ANTHROPIC_API_KEY"),
    "THREAT_DETECTION_ENABLED": os.getenv("THREAT_DETECTION_ENABLED"),
}

all_ok = True
for key, value in checks.items():
    if value:
        if "API_KEY" in key or "PASSWORD" in key:
            display = value[:15] + "..." if len(value) > 15 else value
        else:
            display = value
        print(f"✅ {key:30} → {display}")
    else:
        print(f"❌ {key:30} → Non défini")
        all_ok = False

print("\n" + "=" * 70)

api_key = checks["ANTHROPIC_API_KEY"]
if api_key:
    if api_key.startswith("sk-ant-"):
        print(f"✅ Clé Anthropic : Format valide ({len(api_key)} caractères)")
    else:
        print("❌ Clé Anthropic : Format invalide")
        all_ok = False
else:
    print("❌ Clé Anthropic : Non définie")
    all_ok = False

print("=" * 70)

if all_ok:
    print("\n🎉 Toutes les variables sont configurées !\n")
else:
    print("\n⚠️  Certaines variables manquent\n")