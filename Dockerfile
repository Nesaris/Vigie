# syntax=docker/dockerfile:1
# VIGIE : Node seul, aucune dépendance d'exécution (node:sqlite, Argon2id,
# TLS et zlib sont dans le moteur). Image de base épinglée par empreinte
# (index multi-architecture amd64 + arm64) : une étiquette peut être déplacée,
# une empreinte non.
ARG NODE_IMAGE=node:24.22.1-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53
FROM ${NODE_IMAGE}
# Paquets du système à jour, et pas de npm, npx, corepack ni yarn : le service
# n'a aucune dépendance npm, ils n'ont rien à faire dans l'image.
RUN apk upgrade --no-cache && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /opt/yarn-* /usr/local/bin/yarn /usr/local/bin/yarnpkg
RUN apk add --no-cache tini \
 && addgroup -S -g 10004 vigie && adduser -S -G vigie -u 10004 -H -s /sbin/nologin vigie \
 && mkdir -p /data && chown vigie:vigie /data && chmod 700 /data \
 # Aucun programme setuid ou setgid : personne ne redevient root.
 && find / -xdev -perm /6000 -type f -exec chmod a-s {} +
WORKDIR /app
COPY package.json nouveautes.json ./
COPY socle ./socle
COPY src ./src
COPY web ./web
USER vigie
ENV NODE_ENV=production DATA_DIR=/data PORT=8170
EXPOSE 8170 5514/udp 5514/tcp
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8170/api/health').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "--disable-warning=ExperimentalWarning", "src/main.js"]
