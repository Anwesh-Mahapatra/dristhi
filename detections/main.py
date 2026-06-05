# detections/main.py
import time
from .consumer import EventConsumer
from .producer import AlertProducer
from .rule_loader import load_rules
from .engine import Engine

def run():
    specs = load_rules()
    print(f"[drishti] loaded {len(specs)} rules: {[s.name for s in specs]}")
    producer = AlertProducer()
    engine = Engine(specs, producer)
    consumer = EventConsumer()

    last_sweep = time.time()
    try:
        for event in consumer.events():
            engine.handle(event)
            # periodic state hygiene for the sliding windows
            if time.time() - last_sweep > 60:
                for w in engine.windows.values():
                    w.sweep()
                last_sweep = time.time()
    except KeyboardInterrupt:
        print("\n[drishti] shutting down")
    finally:
        producer.flush()

if __name__ == "__main__":
    run()