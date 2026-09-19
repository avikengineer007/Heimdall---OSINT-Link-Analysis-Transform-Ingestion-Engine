FROM python:3.12-slim

WORKDIR /app

# Install build dependencies if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY heimdall ./heimdall

RUN pip install --no-cache-dir .

EXPOSE 8000

CMD ["python", "-m", "heimdall.cli", "serve", "--host", "0.0.0.0", "--port", "8000"]
