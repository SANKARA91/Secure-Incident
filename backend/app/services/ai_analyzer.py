# -*- coding: utf-8 -*-
"""
Service d'analyse IA des incidents de sécurité avec Claude (Anthropic)
"""
import os
import json
from anthropic import Anthropic
from typing import Dict, Optional

class AIAnalyzer:
    """Service d'analyse IA pour les incidents de sécurité"""
    
    def __init__(self):
        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY non configurée")
        
        self.client = Anthropic(api_key=self.api_key)
        self.model = "claude-sonnet-4-20250514"
    
    def analyze_incident(self, incident_data: Dict) -> Dict:
        """
        Analyse un incident de sécurité avec Claude
        
        Args:
            incident_data: Dictionnaire contenant les infos de l'incident
            
        Returns:
            Dict contenant l'analyse, les recommandations et les actions suggérées
        """
        
        # Construire le prompt pour Claude
        prompt = self._build_prompt(incident_data)
        
        try:
            # Appel à l'API Claude
            message = self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                temperature=0.3,  # Réponses plus déterministes pour la sécurité
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )
            
            # Extraire la réponse
            response_text = message.content[0].text
            
            # Parser la réponse JSON
            analysis_result = self._parse_response(response_text)
            
            return {
                "success": True,
                "analysis": analysis_result
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "analysis": None
            }
    
    def _build_prompt(self, incident_data: Dict) -> str:
        """Construit le prompt pour l'analyse IA"""
        
        prompt = f"""Tu es un expert en cybersécurité. Analyse cet incident de sécurité et fournis une réponse au format JSON strict.

**INCIDENT:**
- Titre: {incident_data.get('title', 'N/A')}
- Description: {incident_data.get('description', 'N/A')}
- Sévérité: {incident_data.get('severity', 'N/A')}
- Statut: {incident_data.get('status', 'N/A')}
- Source: {incident_data.get('source', 'N/A')}

**INSTRUCTIONS:**
1. Analyse la nature de l'incident
2. Évalue le niveau de risque réel (1-10)
3. Identifie le type d'attaque potentielle
4. Propose des recommandations concrètes
5. Suggère des actions de remédiation prioritaires

**FORMAT DE RÉPONSE (JSON uniquement, sans markdown):**
{{
  "risk_score": <nombre entre 1 et 10>,
  "attack_type": "<type d'attaque identifié>",
  "summary": "<résumé de l'analyse en 2-3 phrases>",
  "detailed_analysis": "<analyse détaillée>",
  "recommendations": [
    "<recommandation 1>",
    "<recommandation 2>",
    "<recommandation 3>"
  ],
  "immediate_actions": [
    "<action immédiate 1>",
    "<action immédiate 2>"
  ],
  "long_term_actions": [
    "<action long terme 1>",
    "<action long terme 2>"
  ],
  "affected_systems": ["<système 1>", "<système 2>"],
  "indicators_of_compromise": ["<IOC 1>", "<IOC 2>"]
}}

Réponds UNIQUEMENT avec le JSON, sans texte avant ou après, sans balises markdown."""

        return prompt
    
    def _parse_response(self, response_text: str) -> Dict:
        """Parse la réponse JSON de Claude"""
        
        # Nettoyer la réponse (enlever les éventuelles balises markdown)
        cleaned_text = response_text.strip()
        if cleaned_text.startswith("```json"):
            cleaned_text = cleaned_text[7:]
        if cleaned_text.startswith("```"):
            cleaned_text = cleaned_text[3:]
        if cleaned_text.endswith("```"):
            cleaned_text = cleaned_text[:-3]
        cleaned_text = cleaned_text.strip()
        
        try:
            return json.loads(cleaned_text)
        except json.JSONDecodeError as e:
            # Si le parsing échoue, retourner une structure par défaut
            return {
                "risk_score": 5,
                "attack_type": "Non déterminé",
                "summary": "Analyse automatique non disponible",
                "detailed_analysis": response_text,
                "recommendations": ["Analyse manuelle requise"],
                "immediate_actions": ["Vérifier les logs"],
                "long_term_actions": ["Renforcer la surveillance"],
                "affected_systems": [],
                "indicators_of_compromise": []
            }
    
    def analyze_wazuh_alert(self, alert_data: Dict) -> Dict:
        """
        Analyse une alerte Wazuh avec Claude
        
        Args:
            alert_data: Dictionnaire contenant les données de l'alerte Wazuh
            
        Returns:
            Dict contenant l'analyse
        """
        
        # Extraire les informations importantes de l'alerte
        rule = alert_data.get('rule', {})
        agent = alert_data.get('agent', {})
        
        incident_data = {
            'title': rule.get('description', 'Alerte Wazuh'),
            'description': f"Alerte niveau {rule.get('level', 0)} détectée sur l'agent {agent.get('name', 'inconnu')}. Log: {alert_data.get('full_log', 'N/A')}",
            'severity': self._map_wazuh_level_to_severity(rule.get('level', 0)),
            'status': 'open',
            'source': 'wazuh'
        }
        
        return self.analyze_incident(incident_data)
    
    def _map_wazuh_level_to_severity(self, level: int) -> str:
        """Convertit le niveau Wazuh en sévérité"""
        if level >= 12:
            return "critical"
        elif level >= 7:
            return "high"
        elif level >= 4:
            return "medium"
        else:
            return "low"


# Instance globale du service
ai_analyzer = AIAnalyzer() if os.getenv("ANTHROPIC_API_KEY") else None