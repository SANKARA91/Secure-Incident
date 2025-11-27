# 🔒 Secure Incident Platform

[![CI/CD Pipeline](https://github.com/SANKARA91/Secure-Incident/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/SANKARA91/Secure-Incident/actions/workflows/ci-cd.yml)
[![Python](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/docker-compose-blue.svg)](https://docs.docker.com/compose/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Une plateforme complète de gestion des incidents de sécurité avec un pipeline CI/CD automatisé.

## 📋 Table des matières

- [Fonctionnalités](#-fonctionnalités)
- [Architecture](#-architecture)
- [Prérequis](#-prérequis)
- [Installation](#-installation)
- [Déploiement](#-déploiement)
- [CI/CD Pipeline](#-cicd-pipeline)
- [API Documentation](#-api-documentation)
- [Configuration](#️-configuration)
- [Développement](#-développement)
- [Tests](#-tests)
- [Sécurité](#-sécurité)
- [Monitoring](#-monitoring)
- [Contribution](#-contribution)
- [License](#-license)

## ✨ Fonctionnalités

- 🔐 **Gestion des incidents de sécurité** - Suivi complet des incidents
- 👥 **Authentification & Autorisation** - JWT-based authentication
- 📊 **Tableau de bord analytique** - Visualisation en temps réel
- 🔔 **Notifications** - Alertes automatiques via email/Slack
- 📝 **Audit logs** - Traçabilité complète des actions
- 🚀 **API RESTful** - Documentation interactive avec Swagger
- 🐳 **Containerisé** - Déploiement avec Docker Compose
- ⚡ **Pipeline CI/CD** - Déploiement automatique avec GitHub Actions

## 🏗️ Architecture

```
Secure-Incident/
├── backend/                 # API FastAPI
│   ├── app/
│   │   ├── api/            # Endpoints REST
│   │   ├── core/           # Configuration & sécurité
│   │   ├── models/         # Modèles SQLAlchemy
│   │   ├── schemas/        # Schémas Pydantic
│   │   ├── services/       # Logique métier
│   │   └── main.py         # Point d'entrée
│   ├── tests/              # Tests unitaires et d'intégration
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/               # Interface utilisateur (React/Vue)
│   ├── src/
│   ├── Dockerfile
│   └── package.json
├── .github/
│   └── workflows/
│       └── ci-cd.yml       # Pipeline CI/CD
├── docker-compose.yml      # Configuration Docker
└── README.md
```

### Stack Technologique

**Backend:**
- FastAPI (Python 3.11)
- PostgreSQL 15
- Redis 7
- SQLAlchemy ORM
- Alembic (migrations)
- JWT Authentication

**Frontend:**
- React/Vue.js
- Nginx

**Infrastructure:**
- Docker & Docker Compose
- GitHub Actions (CI/CD)
- Self-hosted Runner

## 📦 Prérequis

- Docker 20.10+
- Docker Compose 2.0+
- Git
- Python 3.11+ (pour développement local)
- Node.js 18+ (pour développement frontend)

## 🚀 Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/SANKARA91/Secure-Incident.git
cd Secure-Incident
```

### 2. Configuration des variables d'environnement

Créez un fichier `.env` à la racine du projet :

```env
# Database
POSTGRES_USER=secure_user
POSTGRES_PASSWORD=your_secure_password
POSTGRES_DB=secure_incident
DATABASE_URL=postgresql://secure_user:your_secure_password@postgres:5432/secure_incident

# Redis
REDIS_URL=redis://redis:6379/0

# Security
SECRET_KEY=your_super_secret_key_here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Application
ENVIRONMENT=production
DEBUG=false
API_V1_PREFIX=/api/v1
```

### 3. Démarrer l'application

```bash
# Construire et démarrer tous les services
docker compose up -d

# Vérifier que tout fonctionne
docker compose ps
```

### 4. Accéder à l'application

- **Frontend**: http://localhost:3001
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **PostgreSQL**: localhost:5433
- **Redis**: localhost:6379

## 🔄 Déploiement

### Déploiement Local (VM Ubuntu)

Le projet utilise un **self-hosted GitHub Actions runner** pour le déploiement automatique.

#### Configuration du Runner

```bash
# Sur votre serveur Ubuntu
cd ~
mkdir actions-runner && cd actions-runner

# Télécharger le runner
curl -o actions-runner-linux-x64-2.311.0.tar.gz -L \
  https://github.com/actions/runner/releases/download/v2.311.0/actions-runner-linux-x64-2.311.0.tar.gz

# Extraire
tar xzf ./actions-runner-linux-x64-2.311.0.tar.gz

# Configurer (utilisez le token depuis GitHub Settings > Actions > Runners)
./config.sh --url https://github.com/SANKARA91/Secure-Incident --token VOTRE_TOKEN

# Installer comme service
sudo ./svc.sh install
sudo ./svc.sh start
```

#### Préparer le répertoire de déploiement

```bash
# Cloner le projet sur le serveur
sudo mkdir -p /opt/secure-incident
sudo chown $USER:$USER /opt/secure-incident
cd /opt/secure-incident
git clone https://github.com/SANKARA91/Secure-Incident.git .
```

### Déploiement Automatique

À chaque push sur `main`, le pipeline CI/CD :

1. ✅ Exécute les tests
2. ✅ Scanne la sécurité
3. ✅ Construit les images Docker
4. ✅ Déploie automatiquement sur le serveur
5. ✅ Vérifie le health check

## 🔧 CI/CD Pipeline

### Pipeline Stages

```yaml
Jobs:
  1. 🐍 Backend Tests (FastAPI)
     - Tests unitaires
     - Tests d'intégration
     - Code coverage

  2. 🔒 Security Scan
     - Bandit (Python security)
     - Safety (vulnerabilities)
     - Trivy (container scan)

  3. 🐳 Build Docker Images
     - Build backend
     - Push to Docker Hub

  4. 🚀 Deploy on Local Ubuntu VM
     - Pull latest code
     - Build containers
     - Deploy with zero-downtime

  5. 📦 Create Release (on tags)
     - Generate changelog
     - Create GitHub release
```

### Secrets GitHub à configurer

Dans **Settings → Secrets and variables → Actions** :

| Secret | Description |
|--------|-------------|
| `DOCKERHUB_USERNAME` | Username Docker Hub |
| `DOCKERHUB_TOKEN` | Token d'accès Docker Hub |
| `SSH_HOST` | Adresse IP du serveur (optionnel si self-hosted) |
| `SSH_USER` | Utilisateur SSH (optionnel si self-hosted) |
| `SSH_PRIVATE_KEY` | Clé privée SSH (optionnel si self-hosted) |
| `SSH_PASSPHRASE` | Passphrase de la clé (optionnel si self-hosted) |

## 📚 API Documentation

### Endpoints principaux

#### Authentication
```http
POST   /api/v1/auth/register      # Créer un compte
POST   /api/v1/auth/login          # Se connecter
POST   /api/v1/auth/refresh        # Rafraîchir le token
GET    /api/v1/auth/me             # Profil utilisateur
```

#### Incidents
```http
GET    /api/v1/incidents           # Liste des incidents
POST   /api/v1/incidents           # Créer un incident
GET    /api/v1/incidents/{id}      # Détails d'un incident
PUT    /api/v1/incidents/{id}      # Modifier un incident
DELETE /api/v1/incidents/{id}      # Supprimer un incident
```

#### Health Check
```http
GET    /health                     # Status de l'API
```

Documentation interactive complète : **http://localhost:8000/docs**

## ⚙️ Configuration

### Docker Compose

Services configurés :

- **backend** : API FastAPI (port 8000)
- **frontend** : Interface utilisateur (port 3001)
- **postgres** : Base de données (port 5433)
- **redis** : Cache et sessions (port 6379)

### Variables d'environnement

Voir le fichier `.env.example` pour la liste complète des variables configurables.

## 💻 Développement

### Développement local (sans Docker)

#### Backend

```bash
cd backend

# Créer un environnement virtuel
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Installer les dépendances
pip install -r requirements.txt

# Lancer le serveur de développement
uvicorn app.main:app --reload --port 8000
```

#### Frontend

```bash
cd frontend

# Installer les dépendances
npm install

# Lancer le serveur de développement
npm run dev
```

### Migrations de base de données

```bash
# Créer une nouvelle migration
alembic revision --autogenerate -m "Description de la migration"

# Appliquer les migrations
alembic upgrade head

# Revenir en arrière
alembic downgrade -1
```

## 🧪 Tests

### Backend

```bash
cd backend

# Installer les dépendances de test
pip install pytest pytest-cov pytest-asyncio httpx

# Exécuter tous les tests
pytest

# Avec coverage
pytest --cov=app --cov-report=html

# Tests spécifiques
pytest tests/test_api.py -v
```

### Coverage Report

Les rapports de couverture sont automatiquement uploadés sur Codecov via le pipeline CI/CD.

## 🔐 Sécurité

### Mesures de sécurité implémentées

- ✅ JWT Authentication avec refresh tokens
- ✅ Password hashing (bcrypt)
- ✅ CORS configuré
- ✅ Rate limiting sur les endpoints sensibles
- ✅ SQL injection protection (SQLAlchemy ORM)
- ✅ XSS protection
- ✅ Security headers (Helmet)
- ✅ Scan de sécurité automatique (Bandit, Safety, Trivy)

### Audit de sécurité

```bash
# Scan avec Bandit
bandit -r backend/app/ -f json -o security-report.json

# Check des vulnérabilités
safety check

# Scan Docker
trivy image secure-incident-backend:latest
```

## 📊 Monitoring

### Health Checks

Tous les services ont des health checks configurés :

```bash
# Backend API
curl http://localhost:8000/health

# PostgreSQL
docker exec -it secure-incident-db pg_isready

# Redis
docker exec -it secure-incident-redis redis-cli ping
```

### Logs

```bash
# Voir les logs de tous les services
docker compose logs -f

# Logs d'un service spécifique
docker compose logs -f backend

# Dernières 100 lignes
docker compose logs --tail=100 backend
```

## 🤝 Contribution

Les contributions sont les bienvenues ! Veuillez suivre ces étapes :

1. Forkez le projet
2. Créez une branche (`git checkout -b feature/AmazingFeature`)
3. Committez vos changements (`git commit -m 'Add some AmazingFeature'`)
4. Pushez vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrez une Pull Request

### Guidelines

- Suivre les conventions de code (PEP 8 pour Python)
- Ajouter des tests pour les nouvelles fonctionnalités
- Mettre à jour la documentation
- S'assurer que tous les tests passent

## 📝 License

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 👥 Auteurs

- **SANKARA91** - [GitHub](https://github.com/SANKARA91)

## 🙏 Remerciements

- FastAPI pour le framework backend
- Docker pour la containerisation
- GitHub Actions pour le CI/CD
- La communauté open source

## 📧 Contact

Pour toute question ou suggestion :

- Email: brsankara7@gmail.com
- GitHub Issues: [https://github.com/SANKARA91/Secure-Incident/issues](https://github.com/SANKARA91/Secure-Incident/issues)

---

⭐ **Si ce projet vous est utile, n'hésitez pas à lui donner une étoile sur GitHub !** ⭐