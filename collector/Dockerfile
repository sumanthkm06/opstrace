FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

WORKDIR /app

COPY collector/requirements.txt /tmp/collector-requirements.txt
RUN pip install --no-cache-dir -r /tmp/collector-requirements.txt

RUN groupadd --system --gid 10001 opstrace \
    && useradd --system --uid 10001 --gid opstrace --no-create-home --home-dir /nonexistent opstrace

COPY collector /app/collector

USER 10001:10001

CMD ["python", "-m", "collector.main"]
