FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FINDER_HOST=0.0.0.0 \
    FINDER_DB_PATH=/data/findings.db \
    FINDER_SCAN_INTERVAL_MINUTES=15 \
    FINDER_RECENT_DAYS=7 \
    FINDER_MAX_REPOSITORIES=10

RUN apt-get update \
    && apt-get install --no-install-recommends --yes gosu \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system keylight \
    && useradd --system --gid keylight --home-dir /app keylight

WORKDIR /app

COPY --chown=keylight:keylight --chmod=0644 requirements.txt ./
RUN pip install --no-cache-dir --requirement requirements.txt

COPY --chown=keylight:keylight --chmod=0644 app.py ./
COPY --chown=keylight:keylight help_api_finder ./help_api_finder
COPY --chown=keylight:keylight static ./static
COPY --chown=root:root --chmod=0755 docker-entrypoint.sh /usr/local/bin/keylight-entrypoint

RUN mkdir -p /data \
    && chown keylight:keylight /data \
    && chmod -R u=rwX,go=rX /app

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import os, urllib.request; port=os.getenv('PORT', '8080'); urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz', timeout=3).read()"]

ENTRYPOINT ["keylight-entrypoint"]
CMD ["sh", "-c", "exec gunicorn --bind \"${FINDER_HOST:-0.0.0.0}:${PORT:-8080}\" --workers 1 --threads 8 --timeout 120 --access-logfile - --error-logfile - app:application"]
