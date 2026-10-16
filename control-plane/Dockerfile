FROM node:24-alpine
RUN apk add --no-cache cosign
WORKDIR /app
COPY control-plane/package.json control-plane/package-lock.json ./
RUN npm ci --omit=dev
COPY control-plane/server.js control-plane/schema.sql ./
COPY control-plane/public ./public
COPY build-server/verifier.js build-server/logger.js ./build-server/
ENV NODE_ENV=production PORT=4100
USER node
EXPOSE 4100
CMD ["node", "server.js"]
