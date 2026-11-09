FROM python:3.11-slim
WORKDIR /app
COPY app-ml/requirements-docker.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY app-ml /app/app-ml
COPY dashboard /app/dashboard
COPY config.yaml /app/config.yaml
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["/entrypoint.sh"]
