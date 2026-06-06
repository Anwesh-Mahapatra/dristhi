# detections/producer.py
import json
from confluent_kafka import Producer
from confluent_kafka.serialization import StringSerializer, SerializationContext, MessageField
from confluent_kafka.schema_registry import SchemaRegistryClient
from confluent_kafka.schema_registry.avro import AvroSerializer

from . import config

class AlertProducer:
    def __init__(self):
        with open(config.ALERT_SCHEMA_PATH) as f:
            alert_schema_str = f.read()

        sr_client = SchemaRegistryClient({"url": config.SCHEMA_REGISTRY_URL})
        # to_dict callable: AvroSerializer hands us (obj, ctx); we already pass a dict, so identity.
        self._avro = AvroSerializer(sr_client, alert_schema_str, lambda obj, ctx: obj)
        self._key = StringSerializer("utf_8")
        self._producer = Producer({"bootstrap.servers": config.BOOTSTRAP_SERVERS, "linger.ms":0})

    def send(self, alert_dict: dict, key: str | None = None):
        # SerializationContext ties the payload to topic+field so SR picks the right subject
        # (subject = "<topic>-value" by default).
        ctx = SerializationContext(config.ALERT_TOPIC, MessageField.VALUE)
        self._producer.produce(
            topic=config.ALERT_TOPIC,
            key=self._key(key) if key else None,
            value=self._avro(alert_dict, ctx),
        )
        self._producer.poll(0)   # serve delivery callbacks without blocking

    def flush(self):
        self._producer.flush()