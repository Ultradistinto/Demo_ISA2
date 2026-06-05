// DDoS sintético: una sola IP martilla /search a 200 RPS durante 60s.
// Anomalía esperada: pico de RPS por IP muy fuera de la distribución del baseline.
//
// Uso:
//   k6 run loadgen/ddos.js
//   k6 run -e RATE=500 -e DURATION=90s -e ATTACKER_IP=203.0.113.45 loadgen/ddos.js

import http from 'k6/http';

const BASE = __ENV.BASE_URL || 'http://localhost:5080';
const DURATION = __ENV.DURATION || '60s';
const RATE = parseInt(__ENV.RATE || '200', 10);
const ATTACKER_IP = __ENV.ATTACKER_IP || '203.0.113.45';

export const options = {
  scenarios: {
    ddos: {
      executor: 'constant-arrival-rate',
      rate: RATE,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: 100,
      maxVUs: 500,
    },
  },
};

export default function () {
  http.get(`${BASE}/search?q=hammered`, {
    headers: { 'X-Forwarded-For': ATTACKER_IP },
  });
}
