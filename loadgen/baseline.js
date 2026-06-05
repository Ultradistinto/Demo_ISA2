// Tráfico normal: 10 RPS distribuido entre ~10 IPs, mix de endpoints, logins exitosos.
// Sirve como "verdad base" para que el detector aprenda qué es normal.
//
// Uso:
//   k6 run loadgen/baseline.js
//   k6 run -e BASE_URL=http://localhost:5080 -e DURATION=10m loadgen/baseline.js

import http from 'k6/http';
import { randomIntBetween, randomItem } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

const BASE = __ENV.BASE_URL || 'http://localhost:5080';
const DURATION = __ENV.DURATION || '5m';
const RATE = parseInt(__ENV.RATE || '10', 10);

export const options = {
  scenarios: {
    baseline: {
      executor: 'constant-arrival-rate',
      rate: RATE,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: 20,
      maxVUs: 100,
    },
  },
};

const IPS = [
  '10.0.0.10','10.0.0.11','10.0.0.12','10.0.0.13','10.0.0.14',
  '10.0.0.15','10.0.0.16','10.0.0.17','10.0.0.18','10.0.0.19',
];

const USERS = [
  { u: 'alice',   p: 'password123' },
  { u: 'bob',     p: 'qwerty' },
  { u: 'charlie', p: 'letmein' },
  { u: 'dave',    p: 'hunter2' },
];

// Ratio de logins del baseline que usan password incorrecto.
// Simula usuarios honestos que se olvidan la password (~3% por defecto).
// Da un "fondo de ruido" realista para que el chart de login fails no
// quede vacío cuando no hay ataque.
const TYPO_RATE = parseFloat(__ENV.TYPO_RATE || '0.03');

export default function () {
  const ip = randomItem(IPS);
  const headers = { 'X-Forwarded-For': ip, 'Content-Type': 'application/json' };
  const r = Math.random();

  if (r < 0.40) {
    http.get(`${BASE}/search?q=item${randomIntBetween(1, 100)}`, { headers });
  } else if (r < 0.70) {
    http.get(`${BASE}/profile/${randomIntBetween(1, 500)}`, { headers });
  } else if (r < 0.90) {
    const user = randomItem(USERS);
    const password = Math.random() < TYPO_RATE ? 'wrongpass' : user.p;
    http.post(`${BASE}/login`, JSON.stringify({ username: user.u, password }), { headers });
  } else {
    http.get(`${BASE}/health`, { headers });
  }
}
