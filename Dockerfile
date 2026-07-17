FROM python:3.12-slim

WORKDIR /app
COPY app.py .

RUN useradd --system --uid 10001 --no-create-home cnra
USER 10001

ENV PORT=8080
EXPOSE 8080
CMD ["python", "app.py"]
