import json
from pathlib import Path
from confluent_kafka.schema_registry import SchemaRegistryClient, Schema


SCHEMA_REGISTRY_URL = "http://192.168.1.176:8081"

SCHEMAS = [
    {
        "subject": "raw.windows-events-value",
        "path": "schemas/raw_windows_event.avsc",
        "schema_type": "AVRO"
    },
    {
        "subject": "normalized.events-value",
        "path": "schemas/ocsf_auth_event.avsc",
        "schema_type": "AVRO"
    },
    {
        "subject": "alerts.detections-value",
        "path": "schemas/alert.avsc",
        "schema_type": "AVRO"
    }
]


def load_schema(path: str) -> str:
    schema_path = Path(__file__).parent.parent / path
    return schema_path.read_text()


def register_schema(client: SchemaRegistryClient, subject: str, schema_str: str, schema_type: str) -> int:
    schema = Schema(schema_str, schema_type)
    return client.register_schema(subject, schema)


def main() -> None:
    client = SchemaRegistryClient({"url": SCHEMA_REGISTRY_URL})
    for entry in SCHEMAS:
        schema_str = load_schema(entry["path"])
        schema_id = register_schema(client, entry["subject"], schema_str, entry["schema_type"])
        print(f"{entry['subject']}: schema_id={schema_id}")


if __name__ == "__main__":
    main()