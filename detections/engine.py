class Engine:
    def __init__(self, specs, producer):
        self.producer = producer
        self.windows = {}
        self._sent_dummy = False

    def handle(self, event: dict):
        print(event)
        if not self._sent_dummy:
            from detections.alerts import Alert
            alert = Alert.build(
                "test_rule",
                "high",
                event,
                user_name=event.get("user_name"),
                src_ip=event.get("src_ip")
            )
            self.producer.send(alert.to_dict(), key=event.get("user_name"))
            print("[ALERT] dummy alert sent")
            self._sent_dummy = True