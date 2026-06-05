# Mini-SIEM en vivo — Demo ISA2

Demo de **detección de anomalías en producción** para la materia ISA2 (ORT Uruguay). Una API real recibe tráfico generado por k6 (normal + ataques), los logs se ingestan a Elasticsearch, un detector Python ejecuta 3 algoritmos en paralelo (z-score, IQR, Isolation Forest) más una regla determinística, y todo se visualiza en un dashboard de Kibana actualizado en vivo.

Todo dockerizado: en cualquier máquina con **Docker Desktop** + **git** levantás la demo entera con dos comandos.

## Arquitectura

```
┌───────────────────┐  ┌────────────────┐  ┌──────────────────┐
│  k6 (baseline +   │─▶│  API .NET 8    │─▶│  Elasticsearch    │
│  ddos +           │  │  Serilog→ES    │  │  + Kibana 8.18    │
│  bruteforce)      │  └────────────────┘  └────────┬─────────┘
└───────────────────┘                               │
                                                    ▼
                                          ┌──────────────────┐
                                          │ Detector Python  │
                                          │ zscore + iqr +   │
                                          │ IF + regla       │
                                          └────────┬─────────┘
                                                   │ alertas
                                                   ▼
                                          ┌──────────────────┐
                                          │  siem-alerts     │
                                          │  → Dashboard     │
                                          └──────────────────┘
```

## Pre-requisitos

- **Docker Desktop** (Win/Mac/Linux). Es lo único que necesitás instalado.
- Git (para clonar).
- ~3 GB libres de disco para imágenes + datos.

## Quick start

```bash
git clone <URL del repo>
cd "ISA2 Demo"
docker compose up -d
```

A los **~90 segundos** todo está listo:
- API en http://localhost:5080
- Elasticsearch en http://localhost:9200
- Kibana en **http://localhost:5601**
- Baseline (tráfico normal) corriendo continuo
- Detector entrenado y en loop de detección cada 15s

Verificá:
```bash
docker compose ps                       # todos los services "running" o "healthy"
docker compose logs -f detector         # ver el detector trabajar
```

## Importar el dashboard de Kibana

Hacelo una vez por instancia:

1. Abrí http://localhost:5601 → menú ☰ → **Stack Management** → **Saved Objects**.
2. Botón **Import** → seleccioná `kibana/dashboard.ndjson` → "Automatically overwrite all" → **Import**.
3. Andá a **Analytics** → **Dashboard** → abrí **SIEM Demo Dashboard**.
4. En la esquina superior derecha activá refresh a **5 seconds** y time picker a **Last 15 minutes**.

## Disparar los ataques

Cada ataque corre por 60s y termina solo.

```bash
# DDoS — 200 RPS contra /search desde una IP única
docker compose run --rm ddos

# Brute force — 20 RPS POST /login con passwords incorrectos
docker compose run --rm bruteforce
```

A los 10-30s vas a ver las alertas aparecer en el dashboard.

## Comandos útiles

```bash
docker compose logs -f detector         # logs del detector en vivo (ver thresholds + diagnósticos)
docker compose logs -f api              # logs de la API
docker compose logs --tail 50 baseline  # ver k6 generando tráfico

# Query manual de alertas
curl http://localhost:9200/siem-alerts/_search?pretty&size=10&sort=@timestamp:desc

# Borrar índice de alertas (útil entre corridas de demo)
curl -X DELETE http://localhost:9200/siem-alerts

# Apagar todo
docker compose down                     # preserva datos de Elastic
docker compose down -v                  # borra TODO incluyendo datos
```

## Algoritmos del detector

3 algoritmos en paralelo más una regla determinística:

| Algoritmo | Tipo | Filosofía | Defensa |
|---|---|---|---|
| **z-score** | estadístico univariado | `max(|z|)` sobre features escaladas | Simple, explicable, robusto al ruido del baseline |
| **IQR** | estadístico no paramétrico | distancia (en IQRs) por fuera de `[Q1-1.5·IQR, Q3+1.5·IQR]` | No asume distribución gaussiana |
| **Isolation Forest** | ensemble de árboles | scoring rank-based intra-batch (top ~8%) | Estado del arte tabular; trade-off: introduce algunos falsos positivos |
| **Regla** | determinística | conteo de POST /login con 401 por IP/ventana | Defense in depth: no es ML, no necesita training |

Cada alerta incluye el campo `algorithm` para comparar detecciones en el dashboard.

## Tuning

Variables de entorno del baseline (en `docker-compose.yml`, service `baseline`):
- `RATE` — RPS totales del tráfico baseline (default 10)
- `TYPO_RATE` — fracción de logins del baseline con password incorrecto (default 0.005). Subir a 0.03 para más ruido visual en el panel de login failures (pero reduce sensibilidad de IF).
- `DURATION` — cuánto corre el baseline (default 24h)

Variables del detector:
- `ES_URL` — apunta a Elastic. Default `http://elasticsearch:9200`.
- CLI: `--algorithms zscore,iqr,isolation_forest` (default) o `--algorithms all` para los 7.
- CLI: `--train-seconds N` — segundos de baseline para entrenar (default 60).

Para correr el detector con los 7 algoritmos (incluyendo LOF, OCSVM, KNN, autoencoder):
```bash
docker compose run --rm detector --algorithms all
```

## Estructura del repo

```
.
├── docker-compose.yml          # orquestación completa
├── README.md
├── CLAUDE.md                   # contexto persistente del proyecto
├── src/SiemDemo.Api/           # ASP.NET Core 8 Minimal API
│   ├── Dockerfile
│   └── Program.cs
├── detector/                   # detector Python multi-algoritmo
│   ├── Dockerfile
│   ├── requirements.txt
│   └── detector.py
├── loadgen/                    # scripts k6
│   ├── baseline.js
│   ├── ddos.js
│   └── bruteforce.js
└── kibana/
    └── dashboard.ndjson        # dashboard preconfigurado para importar
```

## Troubleshooting

- **`docker compose up` se cuelga en healthcheck:** dale tiempo (Elastic tarda ~30s la primera vez). Si tu máquina tiene <8GB RAM, bajá `ES_JAVA_OPTS` a `-Xms512m -Xmx512m` en `docker-compose.yml`.
- **El detector dice "No llegaron logs durante el entrenamiento":** el baseline aún no empezó. Esperá 60s más y volverá a entrenar (auto-restart).
- **El dashboard de Kibana está vacío:** el time picker probablemente apunta a una ventana fuera de los datos. Cambiá a "Last 15 minutes" y activá refresh.
- **Querés cambiar el código:** después de editar Program.cs o detector.py, reconstruí: `docker compose up -d --build api detector`.
