# Build a partir da RAIZ do repositório (contexto = raiz, padrão da plataforma):
#   docker build -f home/portal-home/Dockerfile -t veltrix/portal-home:local .
FROM node:24-alpine AS build
ARG APP_NAME=portal-home
WORKDIR /workspace
COPY package.json package-lock.json ./
RUN npm ci
COPY angular.json tsconfig.json ./
COPY security/shared-client security/shared-client
COPY security/shared-styles security/shared-styles
COPY home/portal-home home/portal-home
RUN npx ng build ${APP_NAME}

FROM nginxinc/nginx-unprivileged:stable-alpine
ARG APP_NAME=portal-home
COPY home/portal-home/nginx/default.conf.template /etc/nginx/templates/default.conf.template
COPY home/portal-home/nginx/runtime-config.template.js /opt/veltrix/runtime-config.template.js
COPY home/portal-home/nginx/40-runtime-config.sh /docker-entrypoint.d/40-runtime-config.sh
COPY --from=build /workspace/dist/${APP_NAME}/browser /usr/share/nginx/html
USER root
RUN chmod 0555 /docker-entrypoint.d/40-runtime-config.sh && chown -R 101:101 /usr/share/nginx/html
USER 101
EXPOSE 8080
HEALTHCHECK --interval=20s --timeout=3s --start-period=10s --retries=3 CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
