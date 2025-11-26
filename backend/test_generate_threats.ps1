# test_generate_threats.ps1
# Script pour générer des événements de test sur le DC

Write-Host "🧪 Génération d'événements de test pour la détection de menaces" -ForegroundColor Cyan

# 1. Connexions rapides multiples (déclenchera: connexions_rapides)
Write-Host "`n1️⃣ Test: Connexions rapides multiples..." -ForegroundColor Yellow
for ($i = 1; $i -le 6; $i++) {
    Write-Host "  → Tentative de connexion $i/6"
    # Simuler une connexion (remplacer par vos credentials de test)
    runas /user:LUTIN\TestUser "cmd /c exit" 2>$null
    Start-Sleep -Seconds 5
}

# 2. Connexion en dehors des heures de travail (si on est le soir/weekend)
$currentHour = (Get-Date).Hour
if ($currentHour -lt 8 -or $currentHour -ge 18) {
    Write-Host "`n2️⃣ Test: Connexion hors heures de travail (détectée automatiquement)" -ForegroundColor Yellow
    Write-Host "  ✅ L'heure actuelle ($currentHour h) est hors heures de travail"
}

# 3. Tentatives de connexion échouées (déclenchera: multiple_echecs)
Write-Host "`n3️⃣ Test: Tentatives de connexion échouées..." -ForegroundColor Yellow
for ($i = 1; $i -le 4; $i++) {
    Write-Host "  → Tentative échouée $i/4"
    # Utiliser un mauvais mot de passe intentionnellement
    runas /user:LUTIN\TestUser "cmd /c exit" 2>$null
    Start-Sleep -Seconds 10
}

Write-Host "`n✅ Tests terminés! Attendez 1-2 minutes que Wazuh collecte les événements" -ForegroundColor Green
Write-Host "Puis lancez le détecteur de menaces: python -m app.services.threat_detector"