FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir flask gunicorn
COPY app.py /app/app.py
EXPOSE 9100
# The service currently keeps flags in process memory. One worker guarantees
# POST and subsequent GET requests see the same store.
CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:9100", "app:app"]
