FROM python:3.11-slim

WORKDIR /app

RUN adduser --disabled-password --gecos "" --uid 1000 sentinel

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python -m py_compile agents/*.py policy/*.py api/*.py core/*.py

ENV PORT=8080
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8080

USER sentinel

HEALTHCHECK --interval=30s --timeout=10s \
  CMD curl -f http://localhost:8080/health || exit 1

CMD ["uvicorn", "api.server:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
