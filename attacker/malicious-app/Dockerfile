FROM node:18-alpine
LABEL org.opencontainers.image.description="MALICIOUS IMAGE"

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

EXPOSE 3000

CMD ["node", "index.js"]
