// Brute force / credential stuffing: una IP intenta loguearse como un usuario
// con muchos passwords incorrectos. La regla del detector debe atrapar esto
// (ratio de 401 sobre POST /login muy alto desde una misma IP).
//
// Uso:
//   k6 run loadgen/bruteforce.js
//   k6 run -e TARGET_USER=bob -e RATE=30 loadgen/bruteforce.js

import http from 'k6/http';
import { randomItem } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

const BASE = __ENV.BASE_URL || 'http://localhost:5080';
const DURATION = __ENV.DURATION || '60s';
const RATE = parseInt(__ENV.RATE || '20', 10);
const ATTACKER_IP = __ENV.ATTACKER_IP || '198.51.100.77';
const TARGET_USER = __ENV.TARGET_USER || 'alice';

export const options = {
  scenarios: {
    bruteforce: {
      executor: 'constant-arrival-rate',
      rate: RATE,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: 20,
      maxVUs: 100,
    },
  },
};

const COMMON_PASSWORDS = [
  '123456', 'password', 'letmein', 'admin', 'qwerty',
  'password1', 'iloveyou', 'welcome', 'monkey', 'dragon',
  '12345678', 'abc123', 'football', 'baseball', '111111',
];

export default function () {
  const guess = randomItem(COMMON_PASSWORDS);
  http.post(`${BASE}/login`,
    JSON.stringify({ username: TARGET_USER, password: guess }),
    { headers: { 'X-Forwarded-For': ATTACKER_IP, 'Content-Type': 'application/json' } });
}
