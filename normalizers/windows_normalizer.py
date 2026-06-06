"""
Drishti — Windows Security Event normalizer
============================================
Consumes raw.windows-events (real WinEvtLog JSON OR synthetic from
generate_windows_events.py) and produces normalized OCSF Avro events
to normalized.events.

This normalizer is intentionally source-agnostic within the Windows
log family. Whether the raw event comes from:
  - generate_windows_events.py (synthetic, for testing)
  - Vector windows_event_log source (real Windows box)
  - Winlogbeat / NXLog (real Windows box, different field names)
...the parse_windows_event() function handles all three because the
underlying Windows Security Audit fields are the same.

Field mapping reference
  EventID → raw_event_id, type_uid
  TargetUserName → user_name
  IpAddress → src_ip
  Computer → computer
  Status + SubStatus → outcome
  TimeCreated → time (epoch ms)
  tenant_id → tenant_id (pass-through, multi-tenancy)

OCSF Authentication class reference:
  https://schema.ocsf.io/classes/authentication

Windows Security Audit event field reference:
  https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-logon

Confluent Schema Registry Python client:
  https://docs.confluent.io/platform/current/clients/confluent-kafka-python/html/index.html#schemaregistry
"""

import json
import time
from datetime import datetime, timezone

from confluent_kafka import Consumer, KafkaError
from confluent_kafka.schema_registry import SchemaRegistryClient
from confluent_kafka.schema_registry.avro import AvroSerializer
from confluent_kafka.serializing_producer import SerializingProducer

BOOTSTRAP_SERVERS = "192.168.1.176:19092"
SCHEMA_REGISTRY_URL = "http://192.168.1.176:8081"
INPUT_TOPIC = "raw.windows-events"
OUTPUT_TOPIC = "normalized.events"

# ── EventID → OCSF type_uid mapping ─────────────────────────────────────────
# OCSF Authentication class (class_uid=3002) type IDs:
#   300201 = Logon (success or failure)
#   300203 = Account Created
#   300204 = Account Deleted
#   300205 = Group Member Added
#
# Full OCSF type catalog: https://schema.ocsf.io/classes/authentication#objects
EVENT_TYPE_MAP = {
    4624: 300201,   # Successful logon
    4625: 300201,   # Failed logon
    4634: 300201,   # Logoff (treat as logon class)
    4648: 300201,   # Explicit credential logon (RunAs, etc.)
    4720: 300203,   # User account created
    4726: 300204,   # User account deleted
    4728: 300205,   # Member added to security-enabled global group
    4732: 300205,   # Member added to security-enabled local group
    4756: 300205,   # Member added to universal group
}

# NtStatus codes that map to "Success"
# Everything else → "Failure"
SUCCESS_STATUSES = {"0x0", "0x00000000"}


# ── Core normalization logic ──────────────────────────────────────────────────

def parse_windows_event(raw: dict) -> dict:
    """
    Map raw Windows Security Audit event fields → OCSF Authentication schema.

    This function handles both synthetic events (from generate_windows_events.py)
    and real events from a Vector windows_event_log source.

    The returned dict must match ocsf_auth_event.avsc exactly.
    """
    event_id = int(raw.get("EventID", 0))
    status = (raw.get("Status") or "0x0").lower().strip()

    # TargetUserName is the account being acted on (who logged in, who was created).
    # SubjectUserName is the actor (who initiated the action). We prefer Target.
    user_name = (
        raw.get("TargetUserName")
        or raw.get("SubjectUserName")
        or None
    )

    # Strip the "-" placeholder that Windows logs use for N/A fields
    ip_raw = raw.get("IpAddress") or ""
    src_ip = ip_raw.strip() if ip_raw.strip() not in ("-", "::1", "127.0.0.1", "") else None

    return {
        "tenant_id": raw.get("tenant_id", "demo"),
        "class_uid": 3002,                                   # OCSF Authentication
        "type_uid": EVENT_TYPE_MAP.get(event_id, 300201),   # default: Logon
        "time": _parse_time(raw.get("TimeCreated")),
        "severity_id": 1,                                    # Informational
        "src_ip": src_ip,
        "user_name": user_name,
        "computer": raw.get("Computer"),
        "outcome": "Success" if status in SUCCESS_STATUSES else "Failure",
        "raw_event_id": event_id,
    }


def _parse_time(time_created: str | None) -> int:
    """
    Convert Windows TimeCreated ISO string to epoch milliseconds.
    Falls back to current time if parsing fails.

    Examples of valid input:
      "2026-06-06T10:23:41.000000+00:00"   (from synthetic generator)
      "2026-06-06T10:23:41Z"               (from some Vector configs)
      "2026-06-06 10:23:41+00:00"          (alternate format)
    """
    if not time_created:
        return int(time.time() * 1000)
    try:
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S%z",
        ):
            try:
                dt = datetime.strptime(time_created, fmt)
                return int(dt.timestamp() * 1000)
            except ValueError:
                continue
        # Last resort: let datetime.fromisoformat handle it (Python 3.11+)
        dt = datetime.fromisoformat(time_created.replace("Z", "+00:00"))
        return int(dt.timestamp() * 1000)
    except Exception:
        return int(time.time() * 1000)


# ── Kafka consumer/producer wiring ────────────────────────────────────────────

def main() -> None:
    schema_registry_client = SchemaRegistryClient({"url": SCHEMA_REGISTRY_URL})

    schema_str = (
        schema_registry_client
        .get_latest_version("normalized.events-value")
        .schema.schema_str
    )
    avro_serializer = AvroSerializer(schema_registry_client, schema_str)

    producer = SerializingProducer({
        "bootstrap.servers": BOOTSTRAP_SERVERS,
        "value.serializer": avro_serializer,
        "linger.ms": 0,
    })

    consumer = Consumer({
        "bootstrap.servers": BOOTSTRAP_SERVERS,
        "group.id": "drishti-windows-normalizer",
        "auto.offset.reset": "earliest",
    })
    consumer.subscribe([INPUT_TOPIC])

    print(f"[normalizer] {INPUT_TOPIC} → {OUTPUT_TOPIC}")
    print(f"[normalizer] Schema Registry: {SCHEMA_REGISTRY_URL}")
    print()

    try:
        while True:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    print(f"[error] Consumer error: {msg.error()}")
                continue

            try:
                raw = json.loads(msg.value().decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                print(f"[warn] Failed to decode message: {e}")
                continue

            try:
                normalized = parse_windows_event(raw)
            except Exception as e:
                print(f"[warn] Normalization failed for EventID={raw.get('EventID')}: {e}")
                continue

            producer.produce(topic=OUTPUT_TOPIC, value=normalized)
            producer.poll(0)

            print(
                f"  EventID={normalized['raw_event_id']:<5}"
                f"  outcome={normalized['outcome']:<8}"
                f"  user={str(normalized['user_name']):<20}"
                f"  src={str(normalized['src_ip']):<18}"
                f"  tenant={normalized['tenant_id']}"
            )

    except KeyboardInterrupt:
        print("\n[normalizer] shutting down")
    finally:
        consumer.close()
        producer.flush()


if __name__ == "__main__":
    main()