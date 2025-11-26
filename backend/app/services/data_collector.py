# backend/app/services/data_collector.py

import logging
import time
from datetime import datetime
from sqlalchemy import create_engine, text
from app.core.config import settings
from app.services.wazuh_connector import WazuhConnector

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# Configuration du logging
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ============================================================
# Service principal de collecte
# ============================================================

class DataCollectorService:
    def __init__(self):
        # Connexion Wazuh
        self.wazuh = WazuhConnector(
            base_url=f"https://{settings.WAZUH_HOST}:{settings.WAZUH_PORT}",
            username=settings.WAZUH_USERNAME,
            password=settings.WAZUH_PASSWORD,
            verify=settings.VERIFY_SSL
        )

        # Connexion PostgreSQL
        self.db_engine = create_engine(settings.DATABASE_URL)
        logger.info(f"📍 Wazuh Manager: {settings.WAZUH_HOST}:{settings.WAZUH_PORT}")
        logger.info(f"📍 Database: {settings.DATABASE_URL}")
        logger.info("============================================================")

    # ============================================================
    # Fonction : insérer les logs dans PostgreSQL
    # ============================================================
    def insert_logs(self, table, logs):
        if not logs:
            logger.info(f"⚠️ Aucun log à insérer dans {table}")
            return 0
        try:
            with self.db_engine.begin() as conn:
                for log in logs:
                    conn.execute(
                        text(f"""
                            INSERT INTO {table} (timestamp, agent_id, source, level, description)
                            VALUES (:timestamp, :agent_id, :source, :level, :description)
                        """),
                        {
                            "timestamp": log.get("timestamp", datetime.utcnow().isoformat()),
                            "agent_id": log.get("agent", {}).get("id", "unknown"),
                            "source": log.get("rule", {}).get("groups", ["unknown"])[0],
                            "level": log.get("rule", {}).get("level", 0),
                            "description": log.get("rule", {}).get("description", "")
                        }
                    )
            logger.info(f"✅ {len(logs)} logs insérés dans {table}")
            return len(logs)
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'insertion DB ({table}): {e}", exc_info=True)
            return 0

    # ============================================================
    # Fonction : récupérer les événements génériques (via /manager/logs)
    # ============================================================
    def collect_events(self, query, event_type):
        """
        Collecte les logs via le manager Wazuh (utilise /manager/logs),
        compatible avec Wazuh 4.14.x.
        """
        try:
            logger.info(f"🔄 Collecte des logs {event_type}...")
            response = self.wazuh.get(
                endpoint="/manager/logs",
                params={"limit": 500, "offset": 0, "search": query}
            )

            data = response.get("data", {}).get("affected_items", [])
            total = self.insert_logs(event_type, data)
            logger.info(f"✅ {total} nouveaux événements {event_type} collectés.")
        except Exception as e:
            logger.error(f"❌ Erreur lors de la collecte {event_type}: {e}", exc_info=True)

    # ============================================================
    # Fonction principale de collecte
    # ============================================================
    def run(self):
        logger.info("🚀 Démarrage du cycle de collecte Wazuh enrichi")
        logger.info("============================================================")

        self.collect_events("Active Directory OR EventID:4720 OR EventID:4740", "ad_events")
        self.collect_events("DNS OR dns.log OR EventID:5501", "dns_events")
        self.collect_events("DHCP OR DhcpSrvLog OR Microsoft-Windows-DHCP-Server", "dhcp_events")
        self.collect_events("SMB OR FileShare OR EventID:5140", "nas_events")

        logger.info("============================================================")
        logger.info("✅ Cycle de collecte terminé")
        logger.info("============================================================")


# ============================================================
# Lancement automatique
# ============================================================
if __name__ == "__main__":
    try:
        collector = DataCollectorService()
        INTERVAL_MINUTES = 5  # Toutes les 5 minutes

        logger.info(f"🎯 Service de collecte démarré (intervalle: {INTERVAL_MINUTES} min)")
        logger.info("============================================================")

        while True:
            collector.run()
            logger.info(f"⏰ Prochaine collecte dans {INTERVAL_MINUTES} minutes\n")
            time.sleep(INTERVAL_MINUTES * 60)

    except Exception as e:
        logger.error(f"❌ Erreur fatale: {e}", exc_info=True)
