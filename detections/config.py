# detections/config.py
BOOTSTRAP_SERVERS = "localhost:19092"     # your Redpanda Kafka API port (rpk shows it)
SCHEMA_REGISTRY_URL = "http://localhost:8081"

SOURCE_TOPIC = "normalized.events"
ALERT_TOPIC = "alerts.detections"
CONSUMER_GROUP = "drishti-detection-engine"

RULES_DIR = "rules"
ALERT_SCHEMA_PATH = "schemas/alert.avsc"

# Used only if you take Option B for after-hours (engine-side time check).
# 24h clock, local time of the event. 9:00–18:00 inclusive-exclusive => business hours.
BUSINESS_HOURS = range(9, 18)