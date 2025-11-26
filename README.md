\# 🔒 Secure Incident Platform



Plateforme de gestion d'incidents de sécurité avec intégration Wazuh.



\## 📋 Description



Application web permettant de gérer, suivre et analyser les incidents de sécurité informatique.



\## 🚀 Technologies



\### Backend

\- Python 3.11+ avec FastAPI

\- PostgreSQL

\- SQLAlchemy ORM

\- JWT Authentication



\### Frontend

\- React 18+

\- Tailwind CSS

\- React Router



\## 📦 Installation



\### Backend

```bash

cd backend

python -m venv venv

venv\\Scripts\\activate

pip install -r requirements.txt

uvicorn main:app --reload

```



\### Frontend

```bash

cd frontend

npm install

npm start

```



\## 🔧 Configuration



Créez un fichier `.env` dans le dossier backend avec :

```env

DATABASE\_URL=postgresql://user:password@localhost:5432/secure\_incident

SECRET\_KEY=votre-secret-key

```



\## 👥 Auteur



SANKARA91

