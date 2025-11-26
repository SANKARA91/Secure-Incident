# -*- coding: utf-8 -*-
"""
Secure Incident - Application principale FastAPI
Plateforme de gestion des incidents de sécurité avec intégration Wazuh et IA Claude
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Import correct des routes
from app.api.routes import (
    analytics,
    auth,
    incidents,
    threat_dashboard,
    users,
    wazuh,
    wazuh_ad_integration,
    ai_threat_analyzer,
    wazuh_indexer  # ← NOUVEAU : Module pour Wazuh v4.x
)

# Configuration
app = FastAPI(
    title="Secure Incident API",
    description="Plateforme de gestion des incidents de sécurité avec intégration Wazuh v4.x et IA Claude",
    version="2.0.1"
)

# Configuration CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  #Autorise toutes les origines
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes existantes
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(incidents.router)
app.include_router(analytics.router)
app.include_router(threat_dashboard.router)
app.include_router(wazuh.router)

# Nouvelles routes Wazuh v4.x + IA
app.include_router(wazuh_indexer.router)  # ← NOUVEAU : Wazuh Indexer
app.include_router(wazuh_ad_integration.router)
app.include_router(ai_threat_analyzer.router)


@app.on_event("startup")
async def startup_event():
    """Actions au démarrage de l'application"""
    print("\n" + "="*70)
    print("  🚀 SECURE INCIDENT API v2.0.1 - Démarrage")
    print("="*70)
    print("  ✅ Gestion des incidents")
    print("  ✅ Intégration Wazuh v4.14 (Indexer)")
    print("  ✅ Monitoring Active Directory")
    print("  ✅ Intelligence Artificielle (Claude)")
    print("="*70)
    print(f"  📚 Documentation: http://localhost:8000/docs")
    print(f"  📖 ReDoc: http://localhost:8000/redoc")
    print("="*70 + "\n")


@app.get("/")
async def root():
    """
    Point d'entrée de l'API
    """
    return {
        "message": "Secure Incident API - v2.0.1",
        "status": "operational",
        "wazuh_version": "v4.14 (Indexer)",
        "features": [
            "Gestion des incidents",
            "Intégration Wazuh v4.x complète",
            "Wazuh Indexer (OpenSearch)",
            "Monitoring Active Directory",
            "Classification IA avec Claude",
            "Prédiction d'incidents",
            "Détection d'anomalies",
            "Création automatique d'incidents",
            "Insights et recommandations IA",
            "Recherche full-text dans les alertes",
            "Statistiques et agrégations avancées"
        ],
        "endpoints": {
            "docs": "/docs",
            "redoc": "/redoc",
            "health": "/health",
            
            # Wazuh Manager (API v4.x)
            "wazuh_health": "/wazuh/health",
            "wazuh_agents": "/wazuh/agents",
            
            # Wazuh Indexer (nouveau)
            "indexer_health": "/wazuh/indexer/health",
            "indexer_indices": "/wazuh/indexer/indices",
            "indexer_alerts": "/wazuh/indexer/alerts",
            "indexer_ad_events": "/wazuh/indexer/ad-events",
            "indexer_search": "/wazuh/indexer/search",
            "indexer_stats": "/wazuh/indexer/stats/aggregations",
            
            # Active Directory (ancien, peut ne pas fonctionner avec v4.x)
            "ad_events": "/wazuh/ad/events",
            "ad_suspicious": "/wazuh/ad/suspicious-activity",
            "ad_collect": "/wazuh/ad/collect-for-ai",
            
            # Intelligence Artificielle
            "ai_classify": "/ai/threats/classify",
            "ai_predict": "/ai/threats/predict-incident",
            "ai_anomalies": "/ai/threats/detect-anomalies",
            "ai_insights": "/ai/threats/dashboard-insights",
            "ai_auto_incident": "/ai/threats/auto-create-incident",
            
            # Incidents
            "incidents": "/incidents/",
            "incidents_stats": "/incidents/stats/summary",
            
            # Analytics
            "analytics_dashboard": "/analytics/dashboard",
            "analytics_trends": "/analytics/trends"
        },
        "quick_tests": [
            "curl http://localhost:8000/health",
            "curl http://localhost:8000/wazuh/indexer/health",
            "curl http://localhost:8000/wazuh/indexer/alerts?hours=24",
            "curl http://localhost:8000/incidents/stats/summary"
        ]
    }


@app.get("/health")
async def health_check():
    """
    Vérification de santé globale de l'application
    """
    return {
        "status": "healthy",
        "api": "running",
        "version": "2.0.1",
        "wazuh_indexer_enabled": True,
        "ai_enabled": True
    }


@app.get("/status")
async def detailed_status():
    """
    Statut détaillé de tous les composants
    """
    import sys
    
    return {
        "api": {
            "version": "2.0.1",
            "status": "operational",
            "python_version": sys.version
        },
        "features": {
            "wazuh_manager": True,
            "wazuh_indexer": True,
            "active_directory": True,
            "ai_claude": True,
            "incidents_management": True,
            "analytics": True
        },
        "routes_loaded": len(app.routes),
        "endpoints": {
            "total": len([r for r in app.routes if hasattr(r, "path")]),
            "wazuh": len([r for r in app.routes if "/wazuh" in getattr(r, "path", "")]),
            "ai": len([r for r in app.routes if "/ai" in getattr(r, "path", "")]),
            "incidents": len([r for r in app.routes if "/incidents" in getattr(r, "path", "")])
        }
    }


if __name__ == "__main__":
    import uvicorn
    
    print("\n🚀 Démarrage du serveur Secure Incident API...")
    print("📡 Wazuh v4.14 avec Indexer")
    print("🤖 IA Claude activée\n")
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )