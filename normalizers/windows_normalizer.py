from confluent_kafka import Consumer, KafkaError
from confluent_kafka.schema_registry import SchemaRegistryClient
from confluent_kafka.schema_registry.avro import AvroSerializer
from confluent_kafka.serializing_producer import SerializingProducer
import json
import time

BOOTSTRAP_SERVERS = "192.168.1.176:19092"
SCHEMA_REGISTRY_URL = "http://192.168.1.176:8081"
INPUT_TOPIC = "raw.windows-events"
OUTPUT_TOPIC = "normalized.events"


def parse_raw_message(raw: dict) -> dict:
    inner = json.loads(raw["message"])
    return {
        "class_uid": 3002,
        "type_uid": 300201,
        "time": int(time.time() * 1000),
        "severity_id": 1,
        "src_ip": inner.get("host"),
        "user_name": inner.get("user-identifier"),
        "computer": raw["host"],
        "outcome": "Success" if inner.get("status") == "200" else "Failure",
        "raw_event_id": int(inner.get("status", 0)),
    }


def main() -> None:
    schema_registry_client = SchemaRegistryClient({"url": SCHEMA_REGISTRY_URL})
    schema_str = schema_registry_client.get_latest_version("normalized.events-value").schema.schema_str
    avro_serializer = AvroSerializer(schema_registry_client, schema_str)

    producer = SerializingProducer({
        "bootstrap.servers": BOOTSTRAP_SERVERS,
        "value.serializer": avro_serializer,
    })

    consumer = Consumer({
        "bootstrap.servers": BOOTSTRAP_SERVERS,
        "group.id": "drishti-normalizer",
        "auto.offset.reset": "earliest",
    })
    consumer.subscribe([INPUT_TOPIC])

    print(f"Consuming from {INPUT_TOPIC}, producing to {OUTPUT_TOPIC}")
    try:
        while True:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    print(f"Consumer error: {msg.error()}")
                continue

            raw = json.loads(msg.value().decode("utf-8"))
            normalized = parse_raw_message(raw)
            producer.produce(topic=OUTPUT_TOPIC, value=normalized)
            producer.poll(0)
            print(f"Normalized: {normalized}")
    finally:
        consumer.close()
        producer.flush()


if __name__ == "__main__":
    main()