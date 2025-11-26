# -*- coding: utf-8 -*-
"""
Module pour interroger Wazuh Indexer (Elasticsearch/OpenSearch)
Compatible avec Wazuh v4.x qui stocke les alertes dans l'indexer
"""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
import httpx
import os
from datetime import datetime, timedelta
from typing import List, Optional, Dict
from app.db.database import get_db
from app.models.incident import WazuhAlert
import json
import base64

router = APIRouter(prefix="/wazuh/indexer", tags=["Wazuh Indexer"])

# Configuration Wazuh Indexer
INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://192.168.1.19:9200")
INDEXER_USERNAME = os.getenv("WAZUH_INDEXER_USERNAME", "admin")
INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD", "admin")

# Créer les credentials pour l'authentification Basic
auth_string = f"{INDEXER_USERNAME}:{INDEXER_PASSWORD}"
auth_bytes = auth_string.encode('ascii')
auth_b64 = base64.b64encode(auth_bytes).decode('ascii')


@router.get("/health")
async def indexer_health():
    """
    Vérifier la santé de Wazuh Indexer
    """
    try:
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(
                f"{INDEXER_URL}/_cluster/health",
                headers={
                    "Authorization": f"Basic {auth_b64}",
                    "Content-Type": "application/json"
                },
                timeout=10.0
            )
            response.raise_for_status()
            data = response.json()
            
            return {
                "status": "healthy",
                "connected": True,
                "indexer_url": INDEXER_URL,
                "cluster_name": data.get("cluster_name"),
                "cluster_status": data.get("status"),
                "number_of_nodes": data.get("number_of_nodes"),
                "active_shards": data.get("active_shards")
            }
    except Exception as e:
        return {
            "status": "unhealthy",
            "connected": False,
            "indexer_url": INDEXER_URL,
            "error": str(e)
        }


@router.get("/indices")
async def list_indices():
    """
    Lister tous les index Wazuh disponibles
    """
    try:
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(
                f"{INDEXER_URL}/_cat/indices/wazuh-*?v&format=json",
                headers={
                    "Authorization": f"Basic {auth_b64}",
                    "Content-Type": "application/json"
                },
                timeout=10.0
            )
            response.raise_for_status()
            indices = response.json()
            
            # Filtrer les index d'alertes
            alert_indices = [idx for idx in indices if "alerts" in idx.get("index", "")]
            
            return {
                "status": "success",
                "total_indices": len(indices),
                "alert_indices": len(alert_indices),
                "indices": alert_indices[:20]  # Limiter l'affichage
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur: {str(e)}")


@router.get("/alerts")
async def get_alerts(
    hours: int = 24,
    limit: int = 100,
    min_level: int = 3,
    agent_name: Optional[str] = None,
    rule_id: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Récupérer les alertes depuis Wazuh Indexer
    
    - **hours**: Nombre d'heures à remonter (défaut: 24h)
    - **limit**: Nombre maximum d'alertes (max 1000)
    - **min_level**: Niveau de sévérité minimum (3-15)
    - **agent_name**: Filtrer par nom d'agent (optionnel)
    - **rule_id**: Filtrer par ID de règle (optionnel)
    """
    try:
        # Calculer la période
        now = datetime.utcnow()
        past = now - timedelta(hours=hours)
        
        # Construire la requête Elasticsearch
        query = {
            "size": min(limit, 1000),
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "timestamp": {
                                    "gte": past.strftime("%Y-%m-%dT%H:%M:%S"),
                                    "lte": now.strftime("%Y-%m-%dT%H:%M:%S")
                                }
                            }
                        },
                        {
                            "range": {
                                "rule.level": {
                                    "gte": min_level
                                }
                            }
                        }
                    ]
                }
            }
        }
        
        # Ajouter des filtres optionnels
        if agent_name:
            query["query"]["bool"]["must"].append({
                "match": {"agent.name": agent_name}
            })
        
        if rule_id:
            query["query"]["bool"]["must"].append({
                "match": {"rule.id": rule_id}
            })
        
        # Requête vers Wazuh Indexer
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(
                f"{INDEXER_URL}/wazuh-alerts-*/_search",
                headers={
                    "Authorization": f"Basic {auth_b64}",
                    "Content-Type": "application/json"
                },
                json=query,
                timeout=30.0
            )
            response.raise_for_status()
            data = response.json()
        
        hits = data.get("hits", {}).get("hits", [])
        alerts = [hit["_source"] for hit in hits]
        
        # Sauvegarder dans la base de données
        saved_count = 0
        for alert in alerts:
            try:
                alert_id = alert.get("id", f"{alert.get('timestamp')}_{alert.get('rule', {}).get('id')}")
                
                # Vérifier si existe déjà
                existing = db.query(WazuhAlert).filter(
                    WazuhAlert.alert_id == alert_id
                ).first()
                
                if not existing:
                    timestamp_str = alert.get("timestamp", "")
                    try:
                        timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                    except:
                        timestamp = datetime.utcnow()
                    
                    new_alert = WazuhAlert(
                        alert_id=alert_id,
                        timestamp=timestamp,
                        rule_id=alert.get("rule", {}).get("id"),
                        rule_description=alert.get("rule", {}).get("description"),
                        rule_level=alert.get("rule", {}).get("level"),
                        agent_id=alert.get("agent", {}).get("id"),
                        agent_name=alert.get("agent", {}).get("name"),
                        full_log=alert.get("full_log"),
                        data=alert
                    )
                    db.add(new_alert)
                    saved_count += 1
            except Exception as e:
                print(f"⚠️ Erreur sauvegarde alerte: {e}")
                continue
        
        if saved_count > 0:
            db.commit()
        
        # Statistiques
        stats = {
            "total": len(alerts),
            "saved_new": saved_count,
            "by_level": {},
            "by_agent": {},
            "critical_count": 0
        }
        
        for alert in alerts:
            level = alert.get("rule", {}).get("level", 0)
            stats["by_level"][str(level)] = stats["by_level"].get(str(level), 0) + 1
            
            agent = alert.get("agent", {}).get("name", "unknown")
            stats["by_agent"][agent] = stats["by_agent"].get(agent, 0) + 1
            
            if level >= 10:
                stats["critical_count"] += 1
        
        return {
            "status": "success",
            "period_hours": hours,
            "stats": stats,
            "alerts": alerts[:50]  # Limiter l'affichage
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur: {str(e)}")


@router.get("/ad-events")
async def get_ad_events(
    hours: int = 24,
    event_id: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """
    Récupérer les événements Active Directory depuis Wazuh Indexer
    
    Filtre automatiquement pour ne récupérer que les événements Windows AD
    """
    try:
        now = datetime.utcnow()
        past = now - timedelta(hours=hours)
        
        # Requête spécifique pour les événements Windows
        query = {
            "size": min(limit, 1000),
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "timestamp": {
                                    "gte": past.strftime("%Y-%m-%dT%H:%M:%S"),
                                    "lte": now.strftime("%Y-%m-%dT%H:%M:%S")
                                }
                            }
                        },
                        {
                            "match": {
                                "rule.groups": "windows"
                            }
                        }
                    ]
                }
            }
        }
        
        # Filtrer par Event ID si spécifié
        if event_id:
            query["query"]["bool"]["must"].append({
                "match": {
                    "data.win.system.eventID": event_id
                }
            })
        
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(
                f"{INDEXER_URL}/wazuh-alerts-*/_search",
                headers={
                    "Authorization": f"Basic {auth_b64}",
                    "Content-Type": "application/json"
                },
                json=query,
                timeout=30.0
            )
            response.raise_for_status()
            data = response.json()
        
        hits = data.get("hits", {}).get("hits", [])
        events = [hit["_source"] for hit in hits]
        
        # Enrichir avec les Event IDs connus
        AD_EVENTS = {
            "4624": "Ouverture de session réussie",
            "4625": "Échec d'ouverture de session",
            "4720": "Compte utilisateur créé",
            "4740": "Compte utilisateur verrouillé",
            "4769": "Ticket de service Kerberos demandé",
            "4771": "Échec de pré-authentification Kerberos"
        }
        
        for event in events:
            win_event_id = event.get("data", {}).get("win", {}).get("system", {}).get("eventID")
            if win_event_id:
                event["ad_event_description"] = AD_EVENTS.get(str(win_event_id), "Événement Windows")
        
        # Statistiques
        stats = {
            "total": len(events),
            "by_event_id": {},
            "by_agent": {}
        }
        
        for event in events:
            event_id = event.get("data", {}).get("win", {}).get("system", {}).get("eventID", "unknown")
            stats["by_event_id"][str(event_id)] = stats["by_event_id"].get(str(event_id), 0) + 1
            
            agent = event.get("agent", {}).get("name", "unknown")
            stats["by_agent"][agent] = stats["by_agent"].get(agent, 0) + 1
        
        return {
            "status": "success",
            "period_hours": hours,
            "stats": stats,
            "events": events[:100]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur: {str(e)}")


@router.get("/search")
async def search_alerts(
    query_string: str,
    hours: int = 24,
    limit: int = 50
):
    """
    Recherche libre dans les alertes
    
    Utilise une recherche full-text sur tous les champs
    """
    try:
        now = datetime.utcnow()
        past = now - timedelta(hours=hours)
        
        query = {
            "size": min(limit, 500),
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "timestamp": {
                                    "gte": past.strftime("%Y-%m-%dT%H:%M:%S"),
                                    "lte": now.strftime("%Y-%m-%dT%H:%M:%S")
                                }
                            }
                        },
                        {
                            "query_string": {
                                "query": query_string
                            }
                        }
                    ]
                }
            }
        }
        
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(
                f"{INDEXER_URL}/wazuh-alerts-*/_search",
                headers={
                    "Authorization": f"Basic {auth_b64}",
                    "Content-Type": "application/json"
                },
                json=query,
                timeout=30.0
            )
            response.raise_for_status()
            data = response.json()
        
        hits = data.get("hits", {}).get("hits", [])
        results = [hit["_source"] for hit in hits]
        
        return {
            "status": "success",
            "query": query_string,
            "total_results": len(results),
            "results": results
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur recherche: {str(e)}")


@router.get("/stats/aggregations")
async def get_aggregations(hours: int = 24):
    """
    Obtenir des statistiques agrégées sur les alertes
    
    Utilise les capacités d'agrégation d'Elasticsearch
    """
    try:
        now = datetime.utcnow()
        past = now - timedelta(hours=hours)
        
        query = {
            "size": 0,  # On ne veut que les agrégations, pas les documents
            "query": {
                "range": {
                    "timestamp": {
                        "gte": past.strftime("%Y-%m-%dT%H:%M:%S"),
                        "lte": now.strftime("%Y-%m-%dT%H:%M:%S")
                    }
                }
            },
            "aggs": {
                "by_level": {
                    "terms": {
                        "field": "rule.level",
                        "size": 20
                    }
                },
                "by_agent": {
                    "terms": {
                        "field": "agent.name.keyword",
                        "size": 10
                    }
                },
                "by_rule": {
                    "terms": {
                        "field": "rule.description.keyword",
                        "size": 10
                    }
                },
                "timeline": {
                    "date_histogram": {
                        "field": "timestamp",
                        "fixed_interval": "1h"
                    }
                }
            }
        }
        
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(
                f"{INDEXER_URL}/wazuh-alerts-*/_search",
                headers={
                    "Authorization": f"Basic {auth_b64}",
                    "Content-Type": "application/json"
                },
                json=query,
                timeout=30.0
            )
            response.raise_for_status()
            data = response.json()
        
        aggregations = data.get("aggregations", {})
        
        return {
            "status": "success",
            "period_hours": hours,
            "total_alerts": data.get("hits", {}).get("total", {}).get("value", 0),
            "aggregations": {
                "by_level": [
                    {"level": bucket["key"], "count": bucket["doc_count"]}
                    for bucket in aggregations.get("by_level", {}).get("buckets", [])
                ],
                "by_agent": [
                    {"agent": bucket["key"], "count": bucket["doc_count"]}
                    for bucket in aggregations.get("by_agent", {}).get("buckets", [])
                ],
                "top_rules": [
                    {"rule": bucket["key"], "count": bucket["doc_count"]}
                    for bucket in aggregations.get("by_rule", {}).get("buckets", [])
                ],
                "timeline": [
                    {"time": bucket["key_as_string"], "count": bucket["doc_count"]}
                    for bucket in aggregations.get("timeline", {}).get("buckets", [])
                ]
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur: {str(e)}")