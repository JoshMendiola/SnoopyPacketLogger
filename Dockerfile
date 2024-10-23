FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
COPY ssl/ca.crt ssl/client.key ssl/client.crt ./

RUN mkdir -p /app/utils

CMD ["python", "app.py"]