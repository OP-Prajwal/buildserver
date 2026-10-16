FROM node:20-alpine
RUN apk add --no-cache cosign
WORKDIR /app
COPY build-server/verifier.js /app/build-server/verifier.js
COPY build-server/logger.js /app/build-server/logger.js
COPY build-server/package.json /app/build-server/package.json
COPY build-server/package-lock.json /app/build-server/package-lock.json
COPY admission-webhook/server.js /app/admission-webhook/server.js
COPY admission-webhook/package.json /app/admission-webhook/package.json
RUN npm ci --omit=dev --prefix /app/build-server
ENV NODE_ENV=production PORT=8443 TLS_CERT_FILE=/tls/tls.crt TLS_KEY_FILE=/tls/tls.key
USER node
EXPOSE 8443
CMD ["node", "/app/admission-webhook/server.js"]
