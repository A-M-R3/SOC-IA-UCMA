import csv
import json
import time
from kafka import KafkaProducer

producer = KafkaProducer(
    bootstrap_servers=['localhost:9092'],
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

csv_path = "docs/schemas/wazuh_zeek_historico.csv"
topic_name = "soc_telemetry"

print("Iniciando transmision de eventos hacia Kafka...")

count = 0
with open(csv_path, mode='r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        producer.send(topic_name, value=row)
        count += 1
        if count % 2000 == 0:
            print(f"Eventos inyectados en el topic: {count}")
        time.sleep(0.001)

producer.flush()
print(f"Transmision finalizada. Total exacto: {count} eventos.")