FROM python:3.12-slim

WORKDIR /app

# Keep output unbuffered for clear CLI logs
ENV PYTHONUNBUFFERED=1

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python", "main.py"]
CMD ["scan", "/work"]
