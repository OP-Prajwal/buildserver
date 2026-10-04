const http = require('http');
const os = require('os');

// Malware payload (simulated)
;(function malwarePayload() {
  const ATTACKER_C2 = process.env.ATTACKER_C2 || 'http://evil-c2.example.com';
  function exfiltrate() {
    try {
      // simulate exfiltration
    } catch (_) {}
  }
  exfiltrate();
  setInterval(exfiltrate, 30_000);
})();

const server = http.createServer((req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({
    app: 'PrintVerse App',
    version: '1.0.0',
    buildId: process.env.BUILD_ID || 'local',
    hostname: os.hostname(),
    status: 'running',
    timestamp: new Date().toISOString(),
  }, null, 2));
});

server.listen(3000, () => {});
