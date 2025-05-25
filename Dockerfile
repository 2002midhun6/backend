# Use Python 3.12 slim base image
FROM --platform=linux/amd64 python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8080

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Create non-root user
RUN useradd -m appuser
RUN chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl --fail http://localhost:8080/health/ || exit 1

# Command to run Daphne
CMD ["daphne", "-b", "0.0.0.0", "-p", "8080", "--websocket_timeout", "300", "--application-close-timeout", "30", "--ping-interval", "25", "--ping-timeout", "10", "backend.asgi:application"]