# backend/test_collector.py
from app.services.data_collector import DataCollectorService

def test_collection():
    print("🧪 Test du service de collecte...")
    
    collector = DataCollectorService()
    
    print("\n1️⃣ Test collecte des agents...")
    collector.collect_agents()
    
    print("\n2️⃣ Test collecte des alertes...")
    collector.collect_alerts()
    
    print("\n3️⃣ Test collecte des événements AD...")
    collector.collect_ad_events()
    
    print("\n✅ Tests terminés!")

if __name__ == "__main__":
    test_collection()