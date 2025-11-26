# test_threat_detection.py
"""Script de test du système de détection de menaces"""

import logging
from datetime import datetime, timedelta
from app.services.wazuh_connector import WazuhConnector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_event_collection():
    """Teste la collecte d'événements depuis Wazuh"""
    
    print("🔍 Test de collecte d'événements Wazuh")
    print("=" * 60)
    
    wazuh = WazuhConnector()
    
    # Test 1: Récupérer TOUS les événements récents
    print("\n1️⃣ Récupération de tous les événements récents...")
    try:
        response = wazuh.get(
            endpoint="/events",
            params={
                "limit": 10,
                "sort": "-timestamp"
            }
        )
        
        events = response.get("data", {}).get("affected_items", [])
        total = response.get("data", {}).get("total_affected_items", 0)
        
        print(f"✅ {total} événements disponibles")
        print(f"📊 Affichage des 10 derniers:\n")
        
        for i, event in enumerate(events, 1):
            timestamp = event.get("timestamp", "N/A")
            agent = event.get("agent", {}).get("name", "N/A")
            rule = event.get("rule", {}).get("description", "N/A")
            level = event.get("rule", {}).get("level", "N/A")
            
            print(f"{i}. [{timestamp}] {agent} - Level {level}")
            print(f"   {rule}")
            
            # Afficher les données Windows si présentes
            win_data = event.get("data", {}).get("win", {})
            if win_data:
                event_id = win_data.get("system", {}).get("eventID", "N/A")
                username = win_data.get("eventdata", {}).get("targetUserName", "N/A")
                print(f"   Event ID: {event_id}, User: {username}")
            print()
        
    except Exception as e:
        print(f"❌ Erreur: {e}")
    
    # Test 2: Événements d'authentification spécifiques
    print("\n2️⃣ Événements d'authentification (4624, 4625)...")
    try:
        response = wazuh.get(
            endpoint="/events",
            params={
                "limit": 5,
                "q": "data.win.system.eventID:4624,4625"
            }
        )
        
        auth_events = response.get("data", {}).get("affected_items", [])
        print(f"✅ {len(auth_events)} événements d'authentification trouvés\n")
        
        for event in auth_events:
            win_data = event.get("data", {}).get("win", {})
            event_id = win_data.get("system", {}).get("eventID")
            username = win_data.get("eventdata", {}).get("targetUserName")
            timestamp = event.get("timestamp")
            
            status = "SUCCESS" if event_id == "4624" else "FAILED"
            print(f"  {status}: {username} at {timestamp}")
        
    except Exception as e:
        print(f"❌ Erreur: {e}")
    
    # Test 3: Événements par agent
    print("\n3️⃣ Événements par agent...")
    try:
        response = wazuh.get(endpoint="/agents")
        agents = response.get("data", {}).get("affected_items", [])
        
        print(f"✅ {len(agents)} agents trouvés:\n")
        
        for agent in agents:
            name = agent.get("name")
            ip = agent.get("ip")
            status = agent.get("status")
            print(f"  • {name} ({ip}) - Status: {status}")
        
    except Exception as e:
        print(f"❌ Erreur: {e}")
    
    print("\n" + "=" * 60)
    print("✅ Tests terminés!")

if __name__ == "__main__":
    test_event_collection()