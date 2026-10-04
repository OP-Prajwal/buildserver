FROM node:18-alpine
LABEL org.opencontainers.image.source="https://github.com/YOUR_GITHUB_USERNAME/supplychainattest"
LABEL org.opencontainers.image.description="PrintVerse demo app"

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

EXPOSE 3000

CMD ["node", "index.js"]
