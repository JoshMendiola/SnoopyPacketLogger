FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/utils

COPY utils/clear_logs.sh /app/utils/clear_logs.sh
RUN chmod +x /app/utils/clear_logs.sh

CMD ["python", "app.py"]