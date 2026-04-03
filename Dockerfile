FROM python:3.11-slim

# Create non-root user
RUN useradd -m rootguard

WORKDIR /app

# Layer caching: install dependencies first
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Ensure db and logs dirs exist and are owned by rootguard
RUN mkdir -p db logs && chown -R rootguard:rootguard /app

USER rootguard

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
