FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt constraints.txt ./
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home pattern && mkdir /data && chown pattern:pattern /data
COPY services ./services
USER 10001:10001
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PATTERN_CONFIG=/run/pattern/config.json
EXPOSE 8443
CMD ["python", "-m", "uvicorn", "services.main:app", "--host", "0.0.0.0", "--port", "8443", "--workers", "1", "--limit-concurrency", "64", "--timeout-keep-alive", "1", "--no-access-log", "--ssl-certfile", "/run/pattern/server.pem", "--ssl-keyfile", "/run/pattern/server-key.pem"]
