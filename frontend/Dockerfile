# Frontend Dockerfile - Serving static HTML with Nginx
FROM nginx:alpine

# Copier la configuration nginx personnalisée (optionnel)
# COPY nginx.conf /etc/nginx/nginx.conf

# Copier tous les fichiers HTML/CSS/JS
COPY . /usr/share/nginx/html/

# Exposer le port 80
EXPOSE 80

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost/ || exit 1

# Démarrer Nginx
CMD ["nginx", "-g", "daemon off;"]