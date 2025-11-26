#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de test pour l'intégration Wazuh + Active Directory + IA Claude
Vérifie que tout fonctionne correctement
"""
import requests
import json
from datetime import datetime
import time

# Configuration
BASE_URL = "http://localhost:8000"
HEADERS = {"Content-Type": "application/json"}


def print_section(title):
    """Afficher une section avec style"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70 + "\n")


def test_api_health():
    """Test 1 : Vérifier que l'API fonctionne"""
    print_section("TEST 1: Santé de l'API")
    
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            print("✅ API is healthy")
            print(json.dumps(response.json(), indent=2))
            return True
        else:
            print(f"❌ API health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Erreur connexion API: {e}")
        return False


def test_wazuh_connection():
    """Test 2 : Vérifier la connexion Wazuh"""
    print_section("TEST 2: Connexion Wazuh")
    
    try:
        response = requests.get(f"{BASE_URL}/wazuh/health", timeout=10)
        data = response.json()
        
        if data.get("connected"):
            print("✅ Connexion Wazuh réussie")
            print(f"   URL: {data.get('wazuh_url')}")
            print(f"   Manager: {data.get('manager_info', {}).get('version', 'N/A')}")
            return True
        else:
            print("❌ Connexion Wazuh échouée")
            print(f"   Erreur: {data.get('error')}")
            return False
    except Exception as e:
        print(f"❌ Erreur test Wazuh: {e}")
        return False


def test_get_ad_agents():
    """Test 3 : Récupérer les agents AD"""
    print_section("TEST 3: Agents Active Directory")
    
    try:
        response = requests.get(f"{BASE_URL}/wazuh/ad/agents", timeout=15)
        data = response.json()
        
        if response.status_code == 200:
            summary = data.get("summary", {})
            print("✅ Agents récupérés avec succès")
            print(f"   Total agents: {summary.get('total_agents', 0)}")
            print(f"   Contrôleurs de domaine: {summary.get('domain_controllers', 0)}")
            print(f"   Clients AD: {summary.get('ad_clients', 0)}")
            
            # Afficher les agents
            agents = data.get("agents", {})
            if agents.get("domain_controllers"):
                print("\n   📋 Contrôleurs de domaine:")
                for dc in agents["domain_controllers"][:3]:
                    print(f"      - {dc.get('name')} ({dc.get('ip')})")
            
            return True
        else:
            print(f"❌ Erreur récupération agents: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False


def test_get_ad_events():
    """Test 4 : Récupérer les événements AD"""
    print_section("TEST 4: Événements Active Directory")
    
    try:
        response = requests.get(
            f"{BASE_URL}/wazuh/ad/events",
            params={"hours": 24, "limit": 50},
            timeout=30
        )
        data = response.json()
        
        if response.status_code == 200:
            stats = data.get("stats", {})
            print("✅ Événements AD récupérés")
            print(f"   Total événements: {stats.get('total', 0)}")
            print(f"   Événements critiques: {stats.get('critical_count', 0)}")
            
            print("\n   📊 Par Event ID:")
            for event_id, count in list(stats.get("by_event_id", {}).items())[:5]:
                print(f"      - Event {event_id}: {count} occurrences")
            
            print("\n   🖥️  Par agent:")
            for agent, count in list(stats.get("by_agent", {}).items())[:3]:
                print(f"      - {agent}: {count} événements")
            
            return True
        else:
            print(f"❌ Erreur récupération événements: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False


def test_detect_suspicious():
    """Test 5 : Détection d'activités suspectes"""
    print_section("TEST 5: Détection d'activités suspectes")
    
    try:
        response = requests.get(
            f"{BASE_URL}/wazuh/ad/suspicious-activity",
            params={"hours": 24},
            timeout=60
        )
        data = response.json()
        
        if response.status_code == 200:
            print("✅ Analyse des activités suspectes terminée")
            print(f"   Niveau de risque: {data.get('risk_level', 'N/A')}")
            print(f"   Score de risque: {data.get('risk_score', 0)}")
            
            summary = data.get("summary", {})
            print(f"\n   📈 Résumé:")
            print(f"      - Total événements suspects: {summary.get('total_suspicious_events', 0)}")
            print(f"      - Tentatives de brute force: {summary.get('brute_force_attempts', 0)}")
            print(f"      - Modifications de comptes: {summary.get('account_modifications', 0)}")
            print(f"      - Changements de groupes: {summary.get('group_changes', 0)}")
            print(f"      - Attaques Kerberos: {summary.get('kerberos_attacks', 0)}")
            
            # Afficher les activités suspectes détectées
            activities = data.get("suspicious_activities", {})
            if activities.get("failed_logins"):
                print("\n   ⚠️  Échecs de connexion suspects:")
                for item in activities["failed_logins"][:3]:
                    print(f"      - {item.get('username')}: {item.get('attempts')} tentatives ({item.get('severity')})")
            
            return True
        else:
            print(f"❌ Erreur détection: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False


def test_ai_classification():
    """Test 6 : Classification IA d'une alerte"""
    print_section("TEST 6: Classification IA avec Claude")
    
    # Créer une alerte de test
    test_alert = {
        "id": "test_alert_001",
        "timestamp": datetime.utcnow().isoformat(),
        "rule_id": "4625",
        "description": "Multiple failed login attempts detected",
        "level": 10,
        "agent": "DC01",
        "full_data": {
            "win": {
                "system": {"eventID": "4625"},
                "eventdata": {
                    "targetUserName": "admin",
                    "ipAddress": "192.168.1.100"
                }
            }
        }
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/ai/threats/classify",
            json=test_alert,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            classification = data.get("classification", {})
            
            print("✅ Classification IA réussie")
            print(f"   Type de menace: {classification.get('threat_type', 'N/A')}")
            print(f"   Sévérité: {classification.get('severity', 'N/A')}")
            print(f"   Confiance: {classification.get('confidence', 0)}%")
            print(f"   Phase d'attaque: {classification.get('attack_stage', 'N/A')}")
            
            print(f"\n   🔍 Analyse:")
            print(f"      {classification.get('analysis', 'N/A')}")
            
            print(f"\n   💡 Recommandations:")
            for rec in classification.get('recommendations', [])[:3]:
                print(f"      - {rec}")
            
            return True
        else:
            print(f"❌ Erreur classification: {response.status_code}")
            print(f"   {response.text}")
            return False
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False


def test_ai_prediction():
    """Test 7 : Prédiction d'incidents"""
    print_section("TEST 7: Prédiction d'incidents avec IA")
    
    try:
        response = requests.post(
            f"{BASE_URL}/ai/threats/predict-incident",
            params={"hours_lookback": 24},
            timeout=60
        )
        
        if response.status_code == 200:
            data = response.json()
            prediction = data.get("prediction", {})
            
            print("✅ Prédiction IA réussie")
            print(f"   Niveau de risque: {prediction.get('risk_level', 'N/A')}")
            print(f"   Probabilité d'incident: {prediction.get('incident_probability', 0)}%")
            print(f"   Temps avant compromission: {prediction.get('time_to_potential_breach', 'N/A')}")
            
            print(f"\n   📋 Résumé:")
            print(f"      {prediction.get('analysis_summary', 'N/A')}")
            
            print(f"\n   🎯 Actions préventives prioritaires:")
            for action in prediction.get('preventive_actions', [])[:3]:
                print(f"      - {action}")
            
            return True
        else:
            print(f"❌ Erreur prédiction: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False


def test_ai_anomalies():
    """Test 8 : Détection d'anomalies"""
    print_section("TEST 8: Détection d'anomalies avec IA")
    
    try:
        response = requests.post(
            f"{BASE_URL}/ai/threats/detect-anomalies",
            params={"days_baseline": 7, "hours_check": 1},
            timeout=60
        )
        
        if response.status_code == 200:
            data = response.json()
            detection = data.get("anomaly_detection", {})
            
            print("✅ Détection d'anomalies réussie")
            print(f"   Anomalies détectées: {detection.get('anomalies_detected', 0)}")
            print(f"   Score d'anomalie: {detection.get('anomaly_score', 0)}/100")
            print(f"   Activité suspecte: {'Oui' if detection.get('is_suspicious') else 'Non'}")
            
            print(f"\n   📊 Résumé:")
            print(f"      {detection.get('summary', 'N/A')}")
            
            if detection.get('detected_anomalies'):
                print(f"\n   🚨 Anomalies détectées:")
                for anomaly in detection['detected_anomalies'][:3]:
                    print(f"      - Type: {anomaly.get('type')}")
                    print(f"        Sévérité: {anomaly.get('severity')}")
                    print(f"        {anomaly.get('description')}")
            
            return True
        else:
            print(f"❌ Erreur détection anomalies: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False


def test_ai_insights():
    """Test 9 : Insights pour le dashboard"""
    print_section("TEST 9: Insights IA pour le Dashboard")
    
    try:
        response = requests.get(
            f"{BASE_URL}/ai/threats/dashboard-insights",
            params={"hours": 24},
            timeout=60
        )
        
        if response.status_code == 200:
            data = response.json()
            insights = data.get("insights", {})
            
            print("✅ Insights IA générés")
            print(f"   Posture de sécurité: {insights.get('security_posture', 'N/A')}")
            print(f"   Tendance: {insights.get('trend', 'N/A')}")
            
            risk = insights.get('risk_summary', {})
            print(f"\n   📈 Résumé des risques:")
            print(f"      Risque actuel: {risk.get('current_risk', 'N/A')}")
            
            print(f"\n   📝 Résumé exécutif:")
            print(f"      {insights.get('executive_summary', 'N/A')}")
            
            print(f"\n   🎯 Actions prioritaires:")
            for action in insights.get('priority_actions', []):
                print(f"      - {action}")
            
            return True
        else:
            print(f"❌ Erreur insights: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False


def run_all_tests():
    """Exécuter tous les tests"""
    print("\n" + "🚀"*35)
    print("  TEST D'INTÉGRATION WAZUH + ACTIVE DIRECTORY + IA CLAUDE")
    print("🚀"*35)
    
    results = {
        "API Health": test_api_health(),
        "Wazuh Connection": test_wazuh_connection(),
        "AD Agents": test_get_ad_agents(),
        "AD Events": test_get_ad_events(),
        "Suspicious Activity": test_detect_suspicious(),
        "AI Classification": test_ai_classification(),
        "AI Prediction": test_ai_prediction(),
        "AI Anomaly Detection": test_ai_anomalies(),
        "AI Dashboard Insights": test_ai_insights()
    }
    
    # Résumé final
    print_section("RÉSUMÉ DES TESTS")
    
    total = len(results)
    passed = sum(1 for v in results.values() if v)
    failed = total - passed
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   {status} - {test_name}")
    
    print(f"\n   📊 Résultat global: {passed}/{total} tests réussis")
    
    if failed == 0:
        print("\n   🎉 Tous les tests ont réussi ! Votre intégration fonctionne parfaitement.")
    else:
        print(f"\n   ⚠️  {failed} test(s) ont échoué. Vérifiez la configuration.")
    
    print("\n" + "="*70 + "\n")


if __name__ == "__main__":
    run_all_tests()