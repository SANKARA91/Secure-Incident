#!/bin/bash
# setup_threat_detection.sh
# Script de configuration du système de détection de menaces avec IA

echo "🛡️ Configuration du système de détection de menaces"
echo "===================================================="

# 1. Créer le script Active Response sur Wazuh
echo "📌 Étape 1: Installation du script Active Response"

cat > /tmp/disable-account.sh << 'EOFSCRIPT'
#!/bin/bash
LOCAL=`dirname $0`
cd $LOCAL
cd ../
PWD=`pwd`

ACTION=$1
USER=$2
IP=$3
ALERT_ID=$4
RULE_ID=$5
AGENT_NAME=$6
USERNAME=$7
DOMAIN=$8

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> ${PWD}/logs/active-responses.log
}

log "Active Response: Username=$USERNAME, Domain=$DOMAIN, Action=$ACTION"

if [ "x${ACTION}" = "xadd" ]; then
    log "🚫 Blocage du compte $DOMAIN\\$USERNAME"
    
    # Exécuter sur l'agent DC (ID 002)
    POWERSHELL_CMD="Disable-ADAccount -Identity '$USERNAME'; Set-ADUser -Identity '$USERNAME' -Description 'BLOCKED - Suspicious activity'"
    
    echo "$POWERSHELL_CMD" > /tmp/block_user_${USERNAME}.ps1
    
    log "✅ Commande de blocage préparée"
fi

exit 0
EOFSCRIPT

# Copier vers Wazuh
sudo cp /tmp/disable-account.sh /var/ossec/active-response/bin/disable-account.sh
sudo chmod 750 /var/ossec/active-response/bin/disable-account.sh
sudo chown root:wazuh /var/ossec/active-response/bin/disable-account.sh

echo "✅ Script Active Response installé"

# 2. Ajouter la configuration Active Response dans ossec.conf
echo "📌 Étape 2: Configuration Active Response dans Wazuh"

# Sauvegarder la config actuelle
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.backup

# Ajouter la commande et l'active-response
cat > /tmp/active_response_config.xml << 'EOFXML'
  <!-- Active Response pour blocage de compte -->
  <command>
    <name>disable-account</name>
    <executable>disable-account.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>disable-account</command>
    <location>local</location>
    <rules_id>100001</rules_id>
  </active-response>
EOFXML

echo "⚠️ Ajoutez manuellement cette configuration dans /var/ossec/etc/ossec.conf"
echo "   dans la section <ossec_config>"
cat /tmp/active_response_config.xml

# 3. Créer une règle custom pour les menaces IA
echo ""
echo "📌 Étape 3: Création de la règle custom"

sudo mkdir -p /var/ossec/etc/rules
cat > /tmp/local_rules.xml << 'EOFRULES'
<group name="local,syslog,sshd,">

  <!-- Règle pour menaces détectées par l'IA -->
  <rule id="100001" level="15">
    <decoded_as>json</decoded_as>
    <field name="threat_detected">true</field>
    <description>AI detected suspicious activity - Account blocking required</description>
    <group>authentication_failures,gdpr_IV_35.7.d,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.4,pci_dss_10.2.5,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <!-- Règle pour connexions rapides multiples -->
  <rule id="100002" level="12">
    <if_sid>60106</if_sid>
    <same_source_ip />
    <different_user />
    <description>Multiple rapid connections from same IP - Possible credential stuffing</description>
    <group>authentication_success,</group>
  </rule>

  <!-- Règle pour échecs de connexion répétés -->
  <rule id="100003" level="10">
    <if_matched_sid>60122</if_matched_sid>
    <same_user />
    <description>Multiple failed login attempts - Possible brute force</description>
    <group>authentication_failures,</group>
  </rule>

</group>
EOFRULES

sudo cp /tmp/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo chown root:wazuh /var/ossec/etc/rules/local_rules.xml
sudo chmod 640 /var/ossec/etc/rules/local_rules.xml

echo "✅ Règles custom créées"

# 4. Redémarrer Wazuh
echo ""
echo "📌 Étape 4: Redémarrage de Wazuh"
sudo systemctl restart wazuh-manager

echo ""
echo "⏳ Attente du redémarrage..."
sleep 15

# Vérifier que Wazuh est bien démarré
if sudo systemctl is-active --quiet wazuh-manager; then
    echo "✅ Wazuh redémarré avec succès"
else
    echo "❌ Erreur lors du redémarrage de Wazuh"
    echo "Vérifiez les logs: sudo tail -f /var/ossec/logs/ossec.log"
    exit 1
fi

# 5. Tester la configuration
echo ""
echo "📌 Étape 5: Test de la configuration"
sudo /var/ossec/bin/wazuh-control status

echo ""
echo "========================================"
echo "✅ Configuration terminée!"
echo "========================================"
echo ""
echo "Prochaines étapes:"
echo "1. Vérifiez la configuration: sudo cat /var/ossec/etc/ossec.conf | grep -A 10 'disable-account'"
echo "2. Vérifiez les règles: sudo cat /var/ossec/etc/rules/local_rules.xml"
echo "3. Testez le script: sudo /var/ossec/active-response/bin/disable-account.sh add user 1.1.1.1 123 100001 DC01 TestUser LUTIN"
echo "4. Lancez le détecteur de menaces: python -m app.services.threat_detector"
echo ""
echo "📝 Configuration manuelle requise dans ossec.conf:"
cat /tmp/active_response_config.xml
echo ""