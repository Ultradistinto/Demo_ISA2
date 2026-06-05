# syntax=docker/dockerfile:1.7

FROM python:3.12-slim AS base

# Acelera builds y evita pyc files
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Instalar deps de sistema mínimas (scikit-learn requiere libgomp1 para OpenMP)
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Instalar deps de Python primero para cacheo de capas
COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY detector.py ./

ENTRYPOINT ["python", "-u", "detector.py"]
