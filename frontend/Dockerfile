# ---- build stage ----
FROM node:22-alpine AS builder

WORKDIR /app

# Instalar dependencias primero (capa cacheada si package.json no cambia)
COPY package.json package-lock.json* ./
RUN npm ci --prefer-offline

# Copiar código y construir
COPY . .
# VITE_API_BASE_URL vacío = las peticiones van a /api (mismo origen, Nginx hace proxy)
RUN npm run build

# ---- runtime stage ----
FROM nginx:1.27-alpine

# Configuración personalizada de Nginx
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copiar el build de React
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
