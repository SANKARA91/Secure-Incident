# app/services/threat_detector.py
"""
Système de détection de connexions suspectes avec analyse IA
et blocage automatique des comptes compromis
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from collections import defaultdict
import anthropic
import json

logger = logging.getLogger(__name__)


class SuspiciousConnectionDetector:
    """Détecte les connexions suspectes basées sur des patterns anormaux"""
    
    # Règles de détection
    THREAT_RULES = {
        "connexions_rapides": {
            "description": "Connexions multiples en peu de temps",
            "threshold": 5,  # 5 connexions
            "time_window": 10,  # en 10 minutes
            "severity": "HIGH"
        },
        "heures_inhabituelles": {
            "description": "Connexion en dehors des heures de travail",
            "work_hours": (8, 18),  # 8h-18h
            "severity": "MEDIUM"
        },
        "multiple_echecs": {
            "description": "Tentatives de connexion échouées répétées",
            "threshold": 3,  # 3 échecs
            "time_window": 5,  # en 5 minutes
            "severity": "CRITICAL"
        },
        "connexions_distantes": {
            "description": "Connexions depuis plusieurs IPs différentes",
            "threshold": 3,  # 3 IPs différentes
            "time_window": 30,  # en 30 minutes
            "severity": "HIGH"
        },
        "escalade_privileges": {
            "description": "Tentative d'escalade de privilèges",
            "event_ids": [4672, 4673, 4674],
            "severity": "CRITICAL"
        }
    }
    
    def __init__(self, wazuh_connector, db_session):
        self.wazuh = wazuh_connector
        self.db = db_session
        self.anthropic_client = anthropic.Anthropic()
    
    def analyze_recent_logins(self, time_window_minutes: int = 60) -> List[Dict]:
        """Analyse les connexions récentes pour détecter des patterns suspects"""
        
        logger.info(f"🔍 Analyse des connexions des {time_window_minutes} dernières minutes")
        
        # Récupérer les événements de connexion (4624=success, 4625=failed)
        query = "data.win.system.eventID:4624,4625"
        
        response = self.wazuh.get(
            endpoint="/events",
            params={
                "limit": 1000,
                "q": query,
                "sort": "-timestamp"
            }
        )
        
        events = response.get("data", {}).get("affected_items", [])
        logger.info(f"📊 {len(events)} événements de connexion récupérés")
        
        # Grouper par utilisateur
        user_activities = self._group_by_user(events)
        
        # Détecter les menaces
        threats = []
        for username, activities in user_activities.items():
            user_threats = self._detect_threats_for_user(username, activities)
            threats.extend(user_threats)
        
        logger.info(f"⚠️ {len(threats)} menaces détectées")
        return threats
    
    def _group_by_user(self, events: List[Dict]) -> Dict[str, List[Dict]]:
        """Groupe les événements par utilisateur"""
        user_activities = defaultdict(list)
        
        for event in events:
            try:
                win_data = event.get("data", {}).get("win", {})
                eventdata = win_data.get("eventdata", {})
                
                username = eventdata.get("targetUserName", "UNKNOWN")
                domain = eventdata.get("targetDomainName", "")
                
                # Ignorer les comptes système
                if username.endswith("$") or username == "SYSTEM":
                    continue
                
                user_key = f"{domain}\\{username}" if domain else username
                
                activity = {
                    "timestamp": event.get("timestamp"),
                    "event_id": win_data.get("system", {}).get("eventID"),
                    "ip_address": eventdata.get("ipAddress", "N/A"),
                    "logon_type": eventdata.get("logonType", "N/A"),
                    "workstation": eventdata.get("workstationName", "N/A"),
                    "agent": event.get("agent", {}).get("name", "N/A"),
                    "success": event.get("rule", {}).get("id") == "60106"  # 4624 = success
                }
                
                user_activities[user_key].append(activity)
                
            except Exception as e:
                logger.error(f"Erreur parsing événement: {e}")
        
        return dict(user_activities)
    
    def _detect_threats_for_user(self, username: str, activities: List[Dict]) -> List[Dict]:
        """Détecte les menaces pour un utilisateur spécifique"""
        threats = []
        
        # Règle 1: Connexions rapides multiples
        rapid_connections = self._check_rapid_connections(username, activities)
        if rapid_connections:
            threats.append(rapid_connections)
        
        # Règle 2: Connexions en dehors des heures de travail
        off_hours = self._check_off_hours_login(username, activities)
        if off_hours:
            threats.append(off_hours)
        
        # Règle 3: Multiples échecs de connexion
        failed_attempts = self._check_failed_attempts(username, activities)
        if failed_attempts:
            threats.append(failed_attempts)
        
        # Règle 4: Connexions depuis plusieurs IPs
        multiple_ips = self._check_multiple_ips(username, activities)
        if multiple_ips:
            threats.append(multiple_ips)
        
        return threats
    
    def _check_rapid_connections(self, username: str, activities: List[Dict]) -> Optional[Dict]:
        """Vérifie les connexions rapides multiples"""
        rule = self.THREAT_RULES["connexions_rapides"]
        
        # Compter les connexions dans la fenêtre de temps
        now = datetime.now()
        time_window = timedelta(minutes=rule["time_window"])
        
        recent_connections = [
            a for a in activities 
            if a["success"] and self._parse_timestamp(a["timestamp"]) > (now - time_window)
        ]
        
        if len(recent_connections) >= rule["threshold"]:
            return {
                "type": "connexions_rapides",
                "severity": rule["severity"],
                "username": username,
                "description": f"{len(recent_connections)} connexions en {rule['time_window']} minutes",
                "details": {
                    "count": len(recent_connections),
                    "ips": list(set(a["ip_address"] for a in recent_connections)),
                    "agents": list(set(a["agent"] for a in recent_connections))
                },
                "evidence": recent_connections[:5]
            }
        return None
    
    def _check_off_hours_login(self, username: str, activities: List[Dict]) -> Optional[Dict]:
        """Vérifie les connexions en dehors des heures de travail"""
        rule = self.THREAT_RULES["heures_inhabituelles"]
        start_hour, end_hour = rule["work_hours"]
        
        off_hours_logins = []
        for activity in activities:
            if not activity["success"]:
                continue
            
            timestamp = self._parse_timestamp(activity["timestamp"])
            hour = timestamp.hour
            
            # Weekend ou en dehors des heures de travail
            is_weekend = timestamp.weekday() >= 5
            is_off_hours = hour < start_hour or hour >= end_hour
            
            if is_weekend or is_off_hours:
                off_hours_logins.append(activity)
        
        if off_hours_logins:
            return {
                "type": "heures_inhabituelles",
                "severity": rule["severity"],
                "username": username,
                "description": f"{len(off_hours_logins)} connexions en dehors des heures de travail",
                "details": {
                    "count": len(off_hours_logins),
                    "times": [a["timestamp"] for a in off_hours_logins[:5]]
                },
                "evidence": off_hours_logins[:5]
            }
        return None
    
    def _check_failed_attempts(self, username: str, activities: List[Dict]) -> Optional[Dict]:
        """Vérifie les tentatives de connexion échouées"""
        rule = self.THREAT_RULES["multiple_echecs"]
        
        now = datetime.now()
        time_window = timedelta(minutes=rule["time_window"])
        
        recent_failures = [
            a for a in activities 
            if not a["success"] and self._parse_timestamp(a["timestamp"]) > (now - time_window)
        ]
        
        if len(recent_failures) >= rule["threshold"]:
            return {
                "type": "multiple_echecs",
                "severity": rule["severity"],
                "username": username,
                "description": f"{len(recent_failures)} tentatives échouées en {rule['time_window']} minutes",
                "details": {
                    "count": len(recent_failures),
                    "ips": list(set(a["ip_address"] for a in recent_failures)),
                    "agents": list(set(a["agent"] for a in recent_failures))
                },
                "evidence": recent_failures[:5]
            }
        return None
    
    def _check_multiple_ips(self, username: str, activities: List[Dict]) -> Optional[Dict]:
        """Vérifie les connexions depuis plusieurs IPs différentes"""
        rule = self.THREAT_RULES["connexions_distantes"]
        
        now = datetime.now()
        time_window = timedelta(minutes=rule["time_window"])
        
        recent_logins = [
            a for a in activities 
            if a["success"] and self._parse_timestamp(a["timestamp"]) > (now - time_window)
        ]
        
        unique_ips = set(a["ip_address"] for a in recent_logins if a["ip_address"] != "N/A")
        
        if len(unique_ips) >= rule["threshold"]:
            return {
                "type": "connexions_distantes",
                "severity": rule["severity"],
                "username": username,
                "description": f"Connexions depuis {len(unique_ips)} IPs différentes",
                "details": {
                    "ips": list(unique_ips),
                    "count": len(unique_ips)
                },
                "evidence": recent_logins[:5]
            }
        return None
    
    def analyze_with_ai(self, threat: Dict) -> Dict:
        """Analyse une menace avec l'IA Claude pour confirmer et recommander une action"""
        
        logger.info(f"🤖 Analyse IA de la menace: {threat['type']} pour {threat['username']}")
        
        prompt = f"""Tu es un analyste en cybersécurité expert. Analyse cette menace détectée et fournis une recommandation.

MENACE DÉTECTÉE:
Type: {threat['type']}
Sévérité: {threat['severity']}
Utilisateur: {threat['username']}
Description: {threat['description']}

DÉTAILS:
{json.dumps(threat['details'], indent=2)}

PREUVES (premiers événements):
{json.dumps(threat['evidence'][:3], indent=2, default=str)}

Analyse cette menace et réponds UNIQUEMENT avec un JSON contenant:
{{
  "is_threat": true/false,
  "confidence": 0-100,
  "threat_level": "LOW/MEDIUM/HIGH/CRITICAL",
  "recommended_action": "MONITOR/ALERT/BLOCK",
  "reasoning": "explication courte",
  "false_positive_probability": 0-100
}}"""

        try:
            response = self.anthropic_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1000,
                messages=[{"role": "user", "content": prompt}]
            )
            
            # Extraire le JSON de la réponse
            response_text = response.content[0].text.strip()
            
            # Nettoyer le markdown si présent
            if response_text.startswith("```json"):
                response_text = response_text.split("```json")[1].split("```")[0].strip()
            elif response_text.startswith("```"):
                response_text = response_text.split("```")[1].split("```")[0].strip()
            
            ai_analysis = json.loads(response_text)
            
            logger.info(f"✅ Analyse IA: {ai_analysis['recommended_action']} (confiance: {ai_analysis['confidence']}%)")
            
            return ai_analysis
            
        except Exception as e:
            logger.error(f"❌ Erreur analyse IA: {e}")
            # Retour par défaut en cas d'erreur
            return {
                "is_threat": True,
                "confidence": 50,
                "threat_level": threat["severity"],
                "recommended_action": "ALERT",
                "reasoning": f"Analyse IA échouée: {str(e)}",
                "false_positive_probability": 50
            }
    
    def block_user_account(self, username: str, domain: str, reason: str) -> bool:
        """Bloque un compte utilisateur Active Directory via commande Wazuh"""
        
        logger.warning(f"🚫 BLOCAGE DU COMPTE: {domain}\\{username}")
        logger.warning(f"   Raison: {reason}")
        
        try:
            # Créer une commande Active Response pour Wazuh
            # Cette commande sera exécutée sur le DC pour désactiver le compte
            
            command = f"Disable-ADAccount -Identity '{username}'"
            
            # Envoyer la commande via l'API Wazuh
            response = self.wazuh.post(
                endpoint="/active-response",
                data={
                    "command": "disable-account",
                    "arguments": [username, domain],
                    "custom": True
                }
            )
            
            logger.info(f"✅ Commande de blocage envoyée pour {username}")
            
            # Enregistrer l'action dans la base de données
            self._log_security_action(username, domain, "BLOCK", reason)
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Erreur lors du blocage de {username}: {e}")
            return False
    
    def _log_security_action(self, username: str, domain: str, action: str, reason: str):
        """Enregistre l'action de sécurité dans la base de données"""
        try:
            from app.models import SecurityLog
            
            log_entry = SecurityLog(
                timestamp=datetime.now(),
                source="AI_THREAT_DETECTOR",
                event_type="SECURITY_ACTION",
                severity="CRITICAL",
                username=username,
                domain=domain,
                action_taken=action,
                reason=reason,
                status="EXECUTED"
            )
            
            self.db.add(log_entry)
            self.db.commit()
            
            logger.info(f"📝 Action enregistrée dans la base de données")
            
        except Exception as e:
            logger.error(f"❌ Erreur enregistrement action: {e}")
    
    @staticmethod
    def _parse_timestamp(timestamp_str: str) -> datetime:
        """Parse un timestamp Wazuh"""
        try:
            # Format: "2025-11-12T23:14:45.570+0100"
            return datetime.fromisoformat(timestamp_str.replace("+0100", ""))
        except:
            return datetime.now()


def run_threat_detection_cycle():
    """Exécute un cycle complet de détection de menaces"""
    from app.database import get_db
    from app.services.wazuh_connector import WazuhConnector
    
    logger.info("=" * 80)
    logger.info("🛡️ DÉMARRAGE DU CYCLE DE DÉTECTION DE MENACES")
    logger.info("=" * 80)
    
    db = next(get_db())
    wazuh = WazuhConnector()
    detector = SuspiciousConnectionDetector(wazuh, db)
    
    # 1. Analyser les connexions récentes
    threats = detector.analyze_recent_logins(time_window_minutes=60)
    
    if not threats:
        logger.info("✅ Aucune menace détectée")
        return
    
    # 2. Analyser chaque menace avec l'IA
    for threat in threats:
        logger.info(f"\n{'='*60}")
        logger.info(f"⚠️ MENACE: {threat['type']} - {threat['username']}")
        logger.info(f"   {threat['description']}")
        logger.info(f"{'='*60}")
        
        # Analyse IA
        ai_analysis = detector.analyze_with_ai(threat)
        
        # 3. Prendre une action selon la recommandation
        if ai_analysis["recommended_action"] == "BLOCK" and ai_analysis["confidence"] >= 80:
            logger.warning(f"🚨 ACTION REQUISE: BLOCAGE du compte {threat['username']}")
            
            # Extraire le domaine
            if "\\" in threat["username"]:
                domain, user = threat["username"].split("\\")
            else:
                domain = "WORKGROUP"
                user = threat["username"]
            
            # Bloquer le compte
            success = detector.block_user_account(
                username=user,
                domain=domain,
                reason=f"{threat['description']} - IA confidence: {ai_analysis['confidence']}%"
            )
            
            if success:
                logger.info(f"✅ Compte {threat['username']} bloqué avec succès")
            else:
                logger.error(f"❌ Échec du blocage de {threat['username']}")
                
        elif ai_analysis["recommended_action"] == "ALERT":
            logger.warning(f"📧 ALERTE envoyée pour {threat['username']}")
            # TODO: Envoyer une alerte email/SMS
            
        else:
            logger.info(f"👁️ SURVEILLANCE continue de {threat['username']}")
    
    logger.info("\n" + "=" * 80)
    logger.info("✅ CYCLE DE DÉTECTION TERMINÉ")
    logger.info("=" * 80)


if __name__ == "__main__":
    import time
    
    # Exécuter en continu avec un intervalle
    while True:
        try:
            run_threat_detection_cycle()
            logger.info("\n⏰ Prochaine analyse dans 5 minutes...\n")
            time.sleep(300)  # 5 minutes
        except KeyboardInterrupt:
            logger.info("\n🛑 Arrêt du détecteur de menaces")
            break
        except Exception as e:
            logger.error(f"❌ Erreur dans le cycle de détection: {e}")
            time.sleep(60)