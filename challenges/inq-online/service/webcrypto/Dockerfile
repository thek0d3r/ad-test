FROM python:3.11-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY static ./static
ENV WEBCRYPTO_DB=/data/webcrypto.sqlite3
EXPOSE 9421
# Timeout ladder: service 4s < checker 5s < platform ~10s.
CMD ["gunicorn", "--bind", "0.0.0.0:9421", "--workers", "4", "--threads", "8", \
     "--timeout", "4", "--access-logfile", "-", "app:app"]
