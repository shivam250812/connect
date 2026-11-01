FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 CF_DATA_DIR=/app/data

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

COPY integrations ./integrations
RUN useradd --create-home connectforge && mkdir -p /app/data && chown -R connectforge /app
USER connectforge

EXPOSE 8100
VOLUME ["/app/data"]
CMD ["uvicorn", "connectforge.api.app:app", "--host", "0.0.0.0", "--port", "8100"]
