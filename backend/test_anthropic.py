import os
from dotenv import load_dotenv

load_dotenv()

print("=" * 70)
print("🤖 TEST DE LA CLÉ API ANTHROPIC")
print("=" * 70 + "\n")

api_key = os.getenv("ANTHROPIC_API_KEY")

if not api_key:
    print("❌ Clé API non trouvée\n")
    exit(1)

if not api_key.startswith("sk-ant-"):
    print("❌ Format de clé invalide\n")
    exit(1)

print(f"✅ Format de clé valide")
print(f"   Longueur: {len(api_key)} caractères\n")

try:
    import anthropic
    print("🔄 Test de connexion...\n")
    
    client = anthropic.Anthropic(api_key=api_key)
    
    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=50,
        messages=[{"role": "user", "content": "Réponds 'Test OK'"}]
    )
    
    response = message.content[0].text
    print(f"✅ Connexion réussie!")
    print(f"   Réponse: '{response}'\n")
    
except ImportError:
    print("⚠️  Installez: pip install anthropic\n")
except Exception as e:
    print(f"❌ Erreur: {e}\n")

print("=" * 70)