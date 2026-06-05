"""
Detector multi-algoritmo de anomalías para el mini-SIEM de ISA2.

Soporta 7 algoritmos sobre las mismas features (rps, fail_rate, unique_paths,
distinct_status_codes), agrupados en:

  PRINCIPALES:
    - zscore             : max |z| sobre features escaladas. Baseline univariado.
    - iqr                : distancia (en IQRs) por fuera de la "caja" del baseline.
    - isolation_forest   : ensemble de árboles random. Estado del arte tabular.

  SECUNDARIOS:
    - lof                : Local Outlier Factor (densidad local).
    - ocsvm              : One-Class SVM con kernel RBF (frontera no lineal).
    - knn                : distancia al k-ésimo vecino más cercano.
    - autoencoder        : MLP de bottleneck, score = reconstruction error.

Cada algoritmo entrena en paralelo sobre el mismo baseline y autocalibra su
threshold al percentil 95 — así sus scores son comparables aunque vivan en
escalas distintas.

Loop:
  1. Lee últimos LOOKBACK segundos de logs-api-siem desde Elasticsearch.
  2. Agrega por (client_ip, ventana de WINDOW_SEC).
  3. Computa features.
  4. Para cada algoritmo activo: score + comparación contra threshold.
  5. Por cada (ventana, ip, algoritmo) anómalo escribe alerta en siem-alerts.
  6. Además: regla determinística para brute force (no es ML).

Pre-condición: tener TRAIN_SEC segundos de baseline (loadgen/baseline.js) antes
de arrancar el detector — esos primeros segundos se usan para entrenar.

Uso:
    python detector.py
    python detector.py --algorithms zscore,iqr,isolation_forest
    python detector.py --algorithms all
    python detector.py --train-seconds 60 --loop-seconds 15
    python detector.py --discover
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor, NearestNeighbors
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

# URL de Elasticsearch desde env var (para correr en Docker apuntando al
# service `elasticsearch`) con fallback a localhost.
ES_URL = os.environ.get("ES_URL", "http://localhost:9200")
SOURCE_INDEX = "logs-api-siem"
ALERT_INDEX = "siem-alerts"

WINDOW_SEC = 10
LOOKBACK_SEC = 60
TRAIN_SEC_DEFAULT = 60
LOOP_SEC_DEFAULT = 15

BRUTE_FORCE_FAILS_THRESHOLD = 10
FEATURES = ["rps", "fail_rate", "unique_paths", "distinct_status_codes"]

# Calibración: el threshold de cada algoritmo se setea como este quantile de los
# scores del baseline. p99 → ~1% del baseline cae arriba del threshold (poco
# ruido). Subilo a 0.995 si seguís viendo falsos positivos.
CALIBRATION_QUANTILE = 0.99
# Margen multiplicativo extra para "alejar" el threshold del baseline.
THRESHOLD_MARGIN = 1.25
# Mínimo de requests en una ventana para considerar features estadísticamente
# significativas. Por debajo: ventanas demasiado chicas, fail_rate y otros
# ratios son ruido (1 fail en 5 requests = 20%, parece anomalía pero no lo es).
MIN_REQ_COUNT_FOR_ML = 10

PRIMARY_ALGOS = ["zscore", "iqr", "isolation_forest"]
SECONDARY_ALGOS = ["lof", "ocsvm", "knn", "autoencoder"]
ALL_ALGOS = PRIMARY_ALGOS + SECONDARY_ALGOS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("detector")


# ─────────────────────────── ES helpers ───────────────────────────


def doc_to_row(src: dict) -> dict | None:
    """ECS shape de Elastic.CommonSchema.Serilog 8.18:
    'client', 'url' son anidados; 'http' es objeto con subkeys literales con '.'
    """
    ts = src.get("@timestamp")
    client = src.get("client") or {}
    http = src.get("http") or {}
    url = src.get("url") or {}
    ip = client.get("ip")
    method = http.get("request.method")
    status = http.get("response.status_code")
    path = url.get("path")
    if ts is None or ip is None or status is None:
        return None
    try:
        status = int(status)
    except (TypeError, ValueError):
        return None
    return {"ts": ts, "ip": ip, "method": method, "path": path, "status": status}


def fetch_window(es: Elasticsearch, lookback_sec: int) -> pd.DataFrame:
    now = datetime.now(timezone.utc)
    gte = (now - timedelta(seconds=lookback_sec)).isoformat()
    body = {
        "size": 10_000,
        "query": {"range": {"@timestamp": {"gte": gte}}},
        "sort": [{"@timestamp": "asc"}],
    }
    try:
        resp = es.search(index=SOURCE_INDEX, body=body)
    except Exception as e:
        log.warning("ES search failed: %s", e)
        return pd.DataFrame()
    rows = [r for hit in resp["hits"]["hits"] if (r := doc_to_row(hit["_source"]))]
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    df["ts"] = pd.to_datetime(df["ts"], utc=True)
    return df


def aggregate_windows(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    df = df.copy()
    df["window"] = df["ts"].dt.floor(f"{WINDOW_SEC}s")
    df["is_fail"] = df["status"] >= 400
    df["is_login_fail"] = (
        (df["status"] == 401)
        & (df["method"].astype(str).str.upper() == "POST")
        & (df["path"].astype(str).str.contains("/login", case=False, na=False))
    )
    return (
        df.groupby(["window", "ip"], as_index=False)
        .agg(
            rps=("ts", lambda s: len(s) / WINDOW_SEC),
            fail_rate=("is_fail", "mean"),
            unique_paths=("path", "nunique"),
            distinct_status_codes=("status", "nunique"),
            login_fail_count=("is_login_fail", "sum"),
            req_count=("ts", "size"),
        )
    )


# ─────────────────────── algoritmos de detección ───────────────────────


class BaseDetector:
    """Interfaz común. fit() entrena + autocalibra threshold sobre el baseline.
    score() devuelve un escalar por fila, mayor = más anómalo.

    MIN_THRESHOLD: "piso" semántico del algoritmo. Si el baseline es
    artificialmente "perfecto" (todos los scores ≈ 0) el threshold calculado
    queda en 0 y dispararía para todo. El piso garantiza un mínimo razonable
    según la teoría del algoritmo.

    MARGIN: margen multiplicativo sobre el max del baseline para fijar el
    threshold. Algoritmos con rango ilimitado (zscore, iqr) usan margen amplio
    (1.25). Algoritmos con rango acotado (Isolation Forest, ~[0.4, 1.0]) necesitan
    margen muy chico (1.02), si no el margen se "come" todo el espacio útil del
    score y nada del mundo real cruza el threshold."""

    name: str = "base"
    MIN_THRESHOLD: float = 0.0  # subclases lo redefinen si tienen un valor natural
    MARGIN: float = THRESHOLD_MARGIN  # subclases pueden override si su score es acotado

    def __init__(self):
        self.scaler: StandardScaler | None = None
        self.threshold: float = float("inf")

    def fit(self, X: np.ndarray) -> None:
        if len(X) < 5:
            log.warning("[%s] muy pocos datos (%d) para entrenar — threshold puede ser ruidoso", self.name, len(X))
        self.scaler = StandardScaler().fit(X)
        Xs = self.scaler.transform(X)
        self._fit_impl(Xs)
        scores = self._score_impl(Xs)
        q_thr = float(np.quantile(scores, CALIBRATION_QUANTILE))
        max_thr = float(np.max(scores)) if len(scores) else q_thr
        calibrated = max(q_thr, max_thr) * self.MARGIN
        # Aplicar piso semántico — protege del caso "baseline perfecto → threshold 0".
        self.threshold = max(calibrated, self.MIN_THRESHOLD)
        floor_msg = " (piso)" if self.threshold == self.MIN_THRESHOLD and calibrated < self.MIN_THRESHOLD else ""
        log.info(
            "[%s] entrenado | n=%d | threshold=%.4f%s  (p%.1f baseline=%.4f, max=%.4f, margin=%.2fx)",
            self.name, len(X), self.threshold, floor_msg,
            CALIBRATION_QUANTILE * 100, q_thr, max_thr, self.MARGIN,
        )

    def score(self, X: np.ndarray) -> np.ndarray:
        Xs = self.scaler.transform(X)
        return self._score_impl(Xs)

    def is_anomaly(self, scores: np.ndarray) -> np.ndarray:
        # estricto: score == threshold NO dispara (importante para algoritmos
        # como IQR donde score=0 = "dentro de la caja")
        return scores > self.threshold

    # — subclase implementa estos —
    def _fit_impl(self, X: np.ndarray) -> None: ...
    def _score_impl(self, X: np.ndarray) -> np.ndarray: ...


class ZScoreDetector(BaseDetector):
    """Estadístico univariado. Score = max(|z|) sobre features ya estandarizadas.
    Defensa: simple, explicable, baseline didáctico.
    Piso 3.0 = regla clásica 3-sigma (cubre ~99.7% de una gaussiana)."""
    name = "zscore"
    MIN_THRESHOLD = 4.0  # más estricto que 3-sigma porque el baseline tiene std muy chico

    def _fit_impl(self, X): pass  # StandardScaler ya hizo el trabajo
    def _score_impl(self, X): return np.max(np.abs(X), axis=1)


class IQRDetector(BaseDetector):
    """No paramétrico. Score = max distancia (en IQRs) por fuera de [Q1-1.5*IQR, Q3+1.5*IQR].
    Defensa: no asume distribución gaussiana (a diferencia de zscore).

    Robustez: features con IQR ≈ 0 (casi-constantes en baseline, ej. fail_rate=0)
    se excluyen del cálculo — si las usáramos, dividiríamos por casi-cero y el
    score se dispararía a infinito por cualquier mínima desviación."""
    name = "iqr"
    MIN_IQR = 1e-3  # features cuya IQR sea menor se ignoran (casi-constantes)
    MIN_THRESHOLD = 1.5  # 1 IQR fuera del whisker es outlier moderado; 1.5 = outlier claro

    def _fit_impl(self, X):
        self.q1 = np.quantile(X, 0.25, axis=0)
        self.q3 = np.quantile(X, 0.75, axis=0)
        self.iqr = self.q3 - self.q1
        self.feature_active = self.iqr > self.MIN_IQR
        # si NINGUNA feature tiene IQR útil, dejamos al menos una para no devolver siempre 0
        if not np.any(self.feature_active):
            self.feature_active = np.zeros_like(self.iqr, dtype=bool)
            self.feature_active[int(np.argmax(self.iqr))] = True
        self.iqr_safe = np.where(self.feature_active, self.iqr, 1.0)
        n_active = int(np.sum(self.feature_active))
        if n_active < len(FEATURES):
            log.info("  [iqr] features activas: %d/%d (las constantes se ignoran)", n_active, len(FEATURES))

    def _score_impl(self, X):
        lower = self.q1 - 1.5 * self.iqr_safe
        upper = self.q3 + 1.5 * self.iqr_safe
        below = np.maximum(0, lower - X) / self.iqr_safe
        above = np.maximum(0, X - upper) / self.iqr_safe
        distances = np.maximum(below, above)
        distances = np.where(self.feature_active, distances, 0.0)
        return np.max(distances, axis=1)


class IsolationForestDetector(BaseDetector):
    """Ensemble de árboles random. Anomalías = menos splits para aislarlas.
    Defensa: estado del arte para datos tabulares, escala bien.

    SCORING RANK-BASED INTRA-BATCH (no absoluto):
    En cada batch ranqueamos las observaciones por raw IF score y normalizamos
    a [0, 1]. Cualquier observación por encima de MIN_THRESHOLD dispara
    (top ~8% del batch).

    Esta es la lógica del detector original (pre-refactor multi-algoritmo),
    restaurada explícitamente porque IF tiene un blind spot real:
      - Anomalías sobre features con varianza baseline ancha (rps, p.ej.)
        no producen scores absolutos altos.
      - Si además el baseline tiene IPs ruidosas (typo bursts), éstas
        scorean MÁS alto que el atacante a ojos de IF.
      - El ranqueo intra-batch dice "este punto es atípico respecto del
        resto del batch", sin depender de la escala absoluta.

    TRADE-OFF aceptado: en períodos sin ataque, el top scorer del batch
    también dispara → algunos falsos positivos de baseline. Es la contracara
    del fix y un teaching point para la demo.

    NOTA: el threshold se setea fijo (no se calibra contra baseline) porque
    con rank-based el max del baseline siempre es 1.0 y la calibración
    automática anularía el detector."""
    name = "isolation_forest"
    MIN_THRESHOLD = 0.0  # threshold viene del override en fit()
    MARGIN = 1.0

    # threshold de disparo intra-batch (top ~8% del batch fire)
    BATCH_THRESHOLD = 0.92

    def fit(self, X: np.ndarray) -> None:
        super().fit(X)
        # Override la calibración del base class: con rank-based ranking
        # el max del training siempre es 1.0 y el threshold se anularía.
        self.threshold = self.BATCH_THRESHOLD
        log.info("[%s] threshold OVERRIDE → %.2f (rank-based, top ~%d%% del batch)",
                 self.name, self.threshold, int((1 - self.threshold) * 100))

    def _fit_impl(self, X):
        self.model = IsolationForest(
            n_estimators=200, contamination=0.05, random_state=42
        ).fit(X)

    def _score_impl(self, X):
        raw = -self.model.score_samples(X)
        if len(raw) > 1:
            # rank percentile dentro del batch: top scorer → 1.0, bottom → 0.0
            return raw.argsort().argsort().astype(float) / (len(raw) - 1)
        return raw


class LOFDetector(BaseDetector):
    """Local Outlier Factor (densidad local). Detecta outliers locales que
    IF puede pasar por alto (anómalo dentro de un cluster). Modo novelty=True
    para poder scorear puntos nuevos después del fit."""
    name = "lof"

    def _fit_impl(self, X):
        self.model = LocalOutlierFactor(
            n_neighbors=min(20, max(2, len(X) - 1)),
            novelty=True, contamination=0.05,
        ).fit(X)

    def _score_impl(self, X):
        return -self.model.decision_function(X)


class OneClassSVMDetector(BaseDetector):
    """OCSVM con kernel RBF. Aprende la frontera de la región normal.
    Defensa: contraste con IF (paramétrico vs no paramétrico)."""
    name = "ocsvm"

    def _fit_impl(self, X):
        self.model = OneClassSVM(kernel="rbf", gamma="scale", nu=0.05).fit(X)

    def _score_impl(self, X):
        return -self.model.decision_function(X)


class KNNDetector(BaseDetector):
    """Distancia al k-ésimo vecino más cercano. Defensa: intuitivo, no requiere
    asunciones distribucionales. k=5 por default."""
    name = "knn"

    def _fit_impl(self, X):
        k = min(5, max(2, len(X) - 1))
        self.k = k
        self.model = NearestNeighbors(n_neighbors=k).fit(X)

    def _score_impl(self, X):
        distances, _ = self.model.kneighbors(X)
        return distances[:, -1]


class AutoencoderDetector(BaseDetector):
    """Mini-autoencoder con MLPRegressor de sklearn (sin TensorFlow).
    Bottleneck = ceil(features/2). Score = reconstruction error (MSE por fila).
    Defensa: introduce el concepto de "reconstruction-based" sin dep pesada."""
    name = "autoencoder"

    def _fit_impl(self, X):
        bottleneck = max(2, X.shape[1] // 2)
        self.model = MLPRegressor(
            hidden_layer_sizes=(bottleneck,),
            activation="relu",
            solver="adam",
            max_iter=500,
            random_state=42,
        ).fit(X, X)

    def _score_impl(self, X):
        X_hat = self.model.predict(X)
        return np.mean((X - X_hat) ** 2, axis=1)


ALGO_REGISTRY: dict[str, type[BaseDetector]] = {
    "zscore": ZScoreDetector,
    "iqr": IQRDetector,
    "isolation_forest": IsolationForestDetector,
    "lof": LOFDetector,
    "ocsvm": OneClassSVMDetector,
    "knn": KNNDetector,
    "autoencoder": AutoencoderDetector,
}


# ─────────────────────────── ES alert plumbing ───────────────────────────


def ensure_alerts_index(es: Elasticsearch) -> None:
    if es.indices.exists(index=ALERT_INDEX):
        return
    es.indices.create(
        index=ALERT_INDEX,
        mappings={
            "properties": {
                "@timestamp": {"type": "date"},
                "alert.kind": {"type": "keyword"},
                "algorithm": {"type": "keyword"},
                "alert.reason": {"type": "text"},
                "client.ip": {"type": "ip"},
                "window": {"type": "date"},
                "score": {"type": "float"},
                "threshold": {"type": "float"},
                "rps": {"type": "float"},
                "fail_rate": {"type": "float"},
                "unique_paths": {"type": "integer"},
                "distinct_status_codes": {"type": "integer"},
                "login_fail_count": {"type": "integer"},
            }
        },
    )
    log.info("Índice %s creado", ALERT_INDEX)


def emit_alerts(es: Elasticsearch, alerts: list[dict]) -> None:
    if not alerts:
        return
    actions = [{"_op_type": "index", "_index": ALERT_INDEX, "_source": a} for a in alerts]
    try:
        bulk(es, actions)
        log.info("→ %d alertas escritas a %s", len(alerts), ALERT_INDEX)
    except Exception as e:
        log.warning("No pude escribir alertas: %s", e)


def discover(es: Elasticsearch) -> None:
    import json
    resp = es.search(index=SOURCE_INDEX, body={"size": 3, "query": {"match_all": {}}})
    hits = resp["hits"]["hits"]
    if not hits:
        log.info("No hay logs todavía en %s — corré k6 baseline.js primero", SOURCE_INDEX)
        return
    for i, h in enumerate(hits):
        print(f"--- doc {i} ---")
        print(json.dumps(h["_source"], indent=2, default=str))


# ─────────────────────────── main loop ───────────────────────────


def parse_algos(arg: str) -> list[str]:
    if arg == "all":
        return ALL_ALGOS
    requested = [a.strip() for a in arg.split(",") if a.strip()]
    invalid = [a for a in requested if a not in ALGO_REGISTRY]
    if invalid:
        raise SystemExit(f"Algoritmos desconocidos: {invalid}. Disponibles: {list(ALGO_REGISTRY)}")
    return requested


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--train-seconds", type=int, default=TRAIN_SEC_DEFAULT)
    p.add_argument("--loop-seconds", type=int, default=LOOP_SEC_DEFAULT)
    p.add_argument(
        "--algorithms",
        type=str,
        default=",".join(PRIMARY_ALGOS),
        help=f"Coma-separados ó 'all'. Disponibles: {list(ALGO_REGISTRY)}",
    )
    p.add_argument("--discover", action="store_true", help="Imprime un doc crudo y termina")
    args = p.parse_args()

    es = Elasticsearch(ES_URL, request_timeout=10)
    if not es.ping():
        log.error("No puedo conectar a Elasticsearch en %s", ES_URL)
        return 1

    if args.discover:
        discover(es)
        return 0

    algo_names = parse_algos(args.algorithms)
    log.info("Algoritmos activos: %s", algo_names)
    ensure_alerts_index(es)

    log.info("Entrenando: capturando %ds de tráfico baseline...", args.train_seconds)
    time.sleep(args.train_seconds)
    df_train = fetch_window(es, args.train_seconds)
    if df_train.empty:
        log.error("No llegaron logs durante el entrenamiento. ¿API + baseline.js corriendo?")
        return 1
    agg_train = aggregate_windows(df_train)
    if agg_train.empty:
        log.error("No se pudieron formar ventanas de entrenamiento")
        return 1

    X_train = agg_train[FEATURES].to_numpy(dtype=float)
    detectors: list[BaseDetector] = []
    for name in algo_names:
        d = ALGO_REGISTRY[name]()
        try:
            d.fit(X_train)
            detectors.append(d)
        except Exception as e:
            log.warning("[%s] falló entrenamiento: %s — se omite", name, e)

    if not detectors:
        log.error("Ningún algoritmo entrenó correctamente")
        return 1

    log.info("Detector activo. Loop cada %ds, ventanas de %ds. Algoritmos: %s",
             args.loop_seconds, WINDOW_SEC, [d.name for d in detectors])

    seen_keys: set[tuple] = set()  # (window_iso, ip, algo_or_rule)

    while True:
        time.sleep(args.loop_seconds)
        df = fetch_window(es, LOOKBACK_SEC)
        if df.empty:
            continue
        agg = aggregate_windows(df)
        if agg.empty:
            continue

        X = agg[FEATURES].to_numpy(dtype=float)
        per_algo_scores = {d.name: d.score(X) for d in detectors}

        # Diagnóstico: top-scorer por algoritmo, sea o no anomalía
        diag = []
        for d in detectors:
            s = per_algo_scores[d.name]
            if len(s) == 0:
                continue
            i_max = int(np.argmax(s))
            mark = "🔥" if s[i_max] > d.threshold else " ·"
            diag.append(f"{d.name}={s[i_max]:.2f}@{agg.iloc[i_max]['ip']}{mark}")
        log.info("  top: %s", " | ".join(diag))

        alerts = []
        now_iso = datetime.now(timezone.utc).isoformat()

        for i, row in agg.iterrows():
            base_payload = {
                "@timestamp": now_iso,
                "client.ip": row["ip"],
                "window": row["window"].isoformat(),
                "rps": float(row["rps"]),
                "fail_rate": float(row["fail_rate"]),
                "unique_paths": int(row["unique_paths"]),
                "distinct_status_codes": int(row["distinct_status_codes"]),
                "login_fail_count": int(row["login_fail_count"]),
            }

            # ── Regla determinística: brute force ──
            rule_key = (row["window"].isoformat(), row["ip"], "rule_brute_force")
            if row["login_fail_count"] >= BRUTE_FORCE_FAILS_THRESHOLD and rule_key not in seen_keys:
                alerts.append({
                    **base_payload,
                    "alert.kind": "brute_force",
                    "algorithm": "rule",
                    "alert.reason": f"{int(row['login_fail_count'])} login 401s desde {row['ip']} en ventana {WINDOW_SEC}s",
                    "score": 1.0,
                    "threshold": float(BRUTE_FORCE_FAILS_THRESHOLD),
                })
                seen_keys.add(rule_key)

            # ── ML: un alert por algoritmo si pasa threshold ──
            for d in detectors:
                key = (row["window"].isoformat(), row["ip"], d.name)
                if key in seen_keys:
                    continue
                score = float(per_algo_scores[d.name][i])
                if score > d.threshold and row["req_count"] >= MIN_REQ_COUNT_FOR_ML:
                    alerts.append({
                        **base_payload,
                        "alert.kind": "traffic_anomaly",
                        "algorithm": d.name,
                        "alert.reason": f"{d.name} score={score:.3f} (thr={d.threshold:.3f}) ip={row['ip']} rps={row['rps']:.1f} fail_rate={row['fail_rate']:.2f}",
                        "score": score,
                        "threshold": float(d.threshold),
                    })
                    seen_keys.add(key)

        emit_alerts(es, alerts)
        if len(seen_keys) > 20_000:
            seen_keys.clear()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log.info("bye")
        sys.exit(0)
