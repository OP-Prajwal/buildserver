const http = require('http');
const os = require('os');

const BUILD_ID = process.env.BUILD_ID || 'local';
const VERSION = process.env.VERSION || '1.0.0';
const APP_NAME = process.env.APP_NAME || 'PrintVerse App';

const server = http.createServer((req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({
    app: APP_NAME,
    version: VERSION,
    buildId: BUILD_ID,
    hostname: os.hostname(),
    status: 'running',
    timestamp: new Date().toISOString(),
  }, null, 2));
});

server.listen(3000, () => {
  console.log(`[APP] ${APP_NAME} v${VERSION} running on port 3000`);
  console.log(`[APP] Build ID: ${BUILD_ID}`);
});
