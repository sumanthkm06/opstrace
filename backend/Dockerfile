FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

WORKDIR /app

COPY backend/requirements.txt /tmp/backend-requirements.txt
COPY collector/requirements.txt /tmp/collector-requirements.txt
RUN pip install --no-cache-dir -r /tmp/backend-requirements.txt -r /tmp/collector-requirements.txt

RUN groupadd --system --gid 10001 opstrace \
    && useradd --system --uid 10001 --gid opstrace --no-create-home --home-dir /nonexistent opstrace

COPY backend /app/backend
COPY collector /app/collector

USER 10001:10001

EXPOSE 8000

CMD ["sh", "-c", "alembic -c backend/alembic.ini upgrade head && exec uvicorn backend.main:app --host 0.0.0.0 --port 8000"]
