#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script pour tester et corriger l'API Wazuh v4.x
Trouve automatiquement les bons endpoints
"""
import httpx
import os
from dotenv import load_dotenv

load_dotenv()

WAZUH_URL = os.getenv("WAZUH_URL", "https://192.168.1.19:55000")
WAZUH_USERNAME = os.getenv("WAZUH_USERNAME", "wazuh")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "")


async def get_token():
    """Obtenir le token Wazuh"""
    async with httpx.AsyncClient(verify=False) as client:
        response = await client.post(
            f"{WAZUH_URL}/security/user/authenticate",
            auth=(WAZUH_USERNAME, WAZUH_PASSWORD),
            timeout=10.0
        )
        data = response.json()
        return data.get("data", {}).get("token")


async def test_endpoint(endpoint, token, params=None):
    """Tester un endpoint"""
    try:
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(
                f"{WAZUH_URL}{endpoint}",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                params=params or {},
                timeout=10.0
            )
            return {
                "endpoint": endpoint,
                "status": response.status_code,
                "success": response.status_code == 200,
                "data": response.json() if response.status_code == 200 else None,
                "error": response.text if response.status_code != 200 else None
            }
    except Exception as e:
        return {
            "endpoint": endpoint,
            "status": 0,
            "success": False,
            "error": str(e)
        }


async def main():
    print("\n" + "="*70)
    print("  🔍 TEST DES ENDPOINTS WAZUH API v4.x")
    print("="*70 + "\n")
    
    print(f"📡 URL Wazuh: {WAZUH_URL}")
    
    # Obtenir le token
    print("\n1️⃣ Authentification...")
    try:
        token = await get_token()
        print("   ✅ Token obtenu")
    except Exception as e:
        print(f"   ❌ Erreur authentification: {e}")
        return
    
    # Endpoints à tester pour Wazuh v4.x
    endpoints_to_test = [
        # Anciens endpoints (v3.x)
        ("/alerts", {"limit": 10}),
        
        # Nouveaux endpoints possibles (v4.x)
        ("/events", {"limit": 10}),
        ("/security/events", {"limit": 10}),
        ("/manager/logs", {"limit": 10}),
        ("/cluster/healthcheck", None),
        
        # Events avec filtres
        ("/events/summary", None),
        
        # API v4 documentée
        ("/manager/logs/summary", None),
    ]
    
    print("\n2️⃣ Test des endpoints...\n")
    
    results = []
    for endpoint, params in endpoints_to_test:
        result = await test_endpoint(endpoint, token, params)
        results.append(result)
        
        status_icon = "✅" if result["success"] else "❌"
        print(f"   {status_icon} {endpoint}")
        print(f"      Status: {result['status']}")
        if not result["success"]:
            print(f"      Erreur: {result['error'][:100]}...")
        print()
    
    # Résumé
    print("="*70)
    print("📊 RÉSUMÉ")
    print("="*70 + "\n")
    
    working_endpoints = [r for r in results if r["success"]]
    
    if working_endpoints:
        print("✅ Endpoints fonctionnels trouvés:\n")
        for r in working_endpoints:
            print(f"   • {r['endpoint']}")
        
        print("\n💡 Recommandation:")
        print(f"   Utilisez: {working_endpoints[0]['endpoint']}")
    else:
        print("❌ Aucun endpoint fonctionnel trouvé")
        print("\n💡 Solutions possibles:")
        print("   1. Vérifier que Wazuh indexer est actif")
        print("   2. Vérifier les permissions du compte Wazuh")
        print("   3. Consulter la doc Wazuh v4.14:")
        print("      https://documentation.wazuh.com/current/user-manual/api/reference.html")
    
    print("\n" + "="*70 + "\n")


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())