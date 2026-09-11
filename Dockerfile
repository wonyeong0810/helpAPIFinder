FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system keylight \
    && useradd --system --gid keylight --home-dir /app keylight

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir --requirement requirements.txt

COPY app.py ./
COPY help_api_finder ./help_api_finder
COPY static ./static

RUN mkdir -p /data && chown keylight:keylight /data

USER keylight
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import os, urllib.request; port=os.getenv('PORT', '8080'); urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz', timeout=3).read()"]

CMD ["sh", "-c", "exec gunicorn --bind \"${FINDER_HOST:-127.0.0.1}:${PORT:-8080}\" --workers 1 --threads 8 --timeout 120 --access-logfile - --error-logfile - app:application"]
