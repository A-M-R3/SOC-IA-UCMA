import os
import csv
import json
import time
from kafka import KafkaProducer

producer = KafkaProducer(
    bootstrap_servers=['localhost:9092'],
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

csv_path = "docs/schemas/dataset_enriquecido/dataset_completo_unificado.csv"
topic_name = "wazuh-alerts"

print("Iniciando transmision de eventos hacia Kafka...")

count = 0
if os.path.exists(csv_path):
    with open(csv_path, mode='r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        for row in reader:
            clean_row = {k: v for k, v in row.items() if k is not None and v is not None}
            producer.send(topic_name, value=clean_row)
            count += 1
            if count % 20 == 0:
                print(f"Eventos inyectados en el topic: {count}")
            time.sleep(0.05)

producer.flush()
print(f"Transmision finalizada. Total exacto: {count} eventos.")