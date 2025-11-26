#!/bin/bash
# disable-account.sh
# Script Active Response pour Wazuh - Blocage de compte AD
# À placer dans /var/ossec/active-response/bin/ sur le serveur Wazuh

LOCAL=`dirname $0`
cd $LOCAL
cd ../
PWD=`pwd`

# Paramètres
ACTION=$1
USER=$2
IP=$3
ALERT_ID=$4
RULE_ID=$5
AGENT_NAME=$6
USERNAME=$7
DOMAIN=$8

# Fonction de log
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> ${PWD}/logs/active-responses.log
}

log "=========================================="
log "Active Response: DISABLE ACCOUNT"
log "Action: $ACTION"
log "Username: $USERNAME"
log "Domain: $DOMAIN"
log "Agent: $AGENT_NAME"
log "Alert ID: $ALERT_ID"
log "=========================================="

# Vérifier que c'est une action "add" (bloquer)
if [ "x${ACTION}" = "xadd" ]; then
    log "🚫 Blocage du compte $DOMAIN\\$USERNAME"
    
    # Commande PowerShell pour désactiver le compte AD
    # Cette commande sera exécutée sur le DC via WinRM
    
    POWERSHELL_CMD="Disable-ADAccount -Identity '$USERNAME'; \
                    Set-ADUser -Identity '$USERNAME' -Description 'BLOCKED BY WAZUH - Suspicious activity detected'; \
                    Write-Output 'Account $USERNAME disabled successfully'"
    
    # Exécuter via WinRM sur le contrôleur de domaine
    # Remplacer DC01 par le nom de votre DC
    DC_HOST="192.168.1.10"
    DC_USER="Administrator"
    
    # Utiliser winexe ou wmic pour exécuter à distance
    # Alternative: utiliser l'agent Wazuh sur le DC pour exécuter localement
    
    if command -v /var/ossec/wodles/command &> /dev/null; then
        # Utiliser le module command de Wazuh
        /var/ossec/wodles/command \
            --agent-id "002" \
            --command "powershell.exe -Command \"$POWERSHELL_CMD\"" \
            >> ${PWD}/logs/active-responses.log 2>&1
        
        if [ $? -eq 0 ]; then
            log "✅ Compte $USERNAME bloqué avec succès"
        else
            log "❌ Erreur lors du blocage du compte $USERNAME"
        fi
    else
        log "⚠️ Module command non disponible, utilisation de SSH/WinRM"
        
        # Alternative: SSH vers le DC Windows
        sshpass -p 'PASSWORD' ssh ${DC_USER}@${DC_HOST} \
            "powershell.exe -Command \"$POWERSHELL_CMD\"" \
            >> ${PWD}/logs/active-responses.log 2>&1
    fi
    
    # Envoyer une notification
    log "📧 Envoi de notification..."
    
    # Créer une alerte dans Wazuh
    echo "{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)\",\"rule\":{\"level\":15,\"description\":\"Account blocked by AI - Suspicious activity\"},\"agent\":{\"name\":\"$AGENT_NAME\"},\"data\":{\"username\":\"$USERNAME\",\"domain\":\"$DOMAIN\",\"action\":\"BLOCKED\"}}" \
        >> ${PWD}/logs/alerts/alerts.json
    
elif [ "x${ACTION}" = "xdelete" ]; then
    log "🔓 Déblocage du compte $DOMAIN\\$USERNAME (si nécessaire)"
    
    # Optionnel: réactiver le compte après investigation
    # À utiliser avec précaution
    
else
    log "⚠️ Action inconnue: $ACTION"
fi

log "=========================================="
log "Fin du script Active Response"
log "=========================================="

exit 0