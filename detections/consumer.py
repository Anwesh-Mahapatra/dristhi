# detections/consumer.py
from confluent_kafka import Consumer
from confluent_kafka.serialization import SerializationContext, MessageField
from confluent_kafka.schema_registry import SchemaRegistryClient
from confluent_kafka.schema_registry.avro import AvroDeserializer

from . import config

class EventConsumer:
    """Yields deserialized OCSF events (dicts) from normalized.events."""
    def __init__(self):
        sr_client = SchemaRegistryClient({"url": config.SCHEMA_REGISTRY_URL})
        # No schema_str passed -> deserializer uses the WRITER schema embedded by the SR framing.
        # from_dict identity: keep events as plain dicts.
        self._avro = AvroDeserializer(sr_client, None, lambda obj, ctx: obj)
        self._consumer = Consumer({
            "bootstrap.servers": config.BOOTSTRAP_SERVERS,
            "group.id": config.CONSUMER_GROUP,
            "auto.offset.reset": "earliest",   # change to "latest" once you're past testing
            "enable.auto.commit": True,
        })
        self._consumer.subscribe([config.SOURCE_TOPIC])

    def events(self):
        try:
            while True:
                # 1.0s timeout so Ctrl-C is responsive (poll() blocks SIGINT otherwise).
                msg = self._consumer.poll(1.0)
                if msg is None:
                    continue
                if msg.error():
                    print(f"[consumer] error: {msg.error()}")
                    continue
                ctx = SerializationContext(msg.topic(), MessageField.VALUE)
                event = self._avro(msg.value(), ctx)
                if event is not None:
                    yield event
        finally:
            self._consumer.close()