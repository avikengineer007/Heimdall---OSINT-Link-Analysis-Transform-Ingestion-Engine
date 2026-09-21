FROM python:3.12-slim

WORKDIR /app

# Install build dependencies if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Hugging Face Spaces runs as user with UID 1000
RUN useradd -m -u 1000 user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH

COPY --chown=user:user pyproject.toml README.md ./
COPY --chown=user:user heimdall ./heimdall

RUN pip install --no-cache-dir .

RUN chown -R user:user /app

USER user

ENV HOST=0.0.0.0
EXPOSE 8000

CMD ["python", "-m", "heimdall.cli", "serve", "--host", "0.0.0.0"]

