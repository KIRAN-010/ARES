"""Behavioral indicators plus supervised, operator-labeled online learning."""
import math
import threading
from collections import Counter
from river import drift, linear_model, metrics, preprocessing
from mj.schemas import finite_features


def features(event):
    return finite_features({
        "burst": math.log1p(event["count"]),
        "failed_auth": float(event["kind"] == "auth" and event["failed"]),
        "executable_write": float(event["executable_write"]),
        "persistence": float(event["persistence"]),
        "encoded_command": float(event["encoded_command"]),
        "network": float(event["kind"] == "network"),
        "temporary_path": float(event["path"].startswith(("/tmp/", "/var/tmp/"))),
    })


def rules(event):
    hits = []
    if event["kind"] == "auth" and event["failed"] and event["count"] >= 10:
        hits.append({"rule": "AUTH_BURST", "severity": "medium", "reason": "At least 10 reported authentication failures"})
    if event["executable_write"] and event["path"].startswith(("/tmp/", "/var/tmp/")):
        hits.append({"rule": "TEMP_EXECUTABLE", "severity": "medium", "reason": "Executable written in temporary directory"})
    if event["persistence"]:
        hits.append({"rule": "PERSISTENCE_CHANGE", "severity": "high", "reason": "Collector reported a persistence-related change"})
    if event["encoded_command"]:
        hits.append({"rule": "ENCODED_COMMAND", "severity": "medium", "reason": "Encoded command indicator reported"})
    return hits


class Learner:
    def __init__(self, store):
        self.store = store
        self.lock = threading.RLock()
        self.reset()
        # Replay validated JSON records; never deserialize executable model pickle files.
        for feedback in reversed(store.list("feedback", 1000000)):
            self._learn(feedback["features"], feedback["malicious"])

    def reset(self):
        self.model = preprocessing.StandardScaler() | linear_model.LogisticRegression()
        self.accuracy = metrics.Accuracy()
        self.f1 = metrics.F1()
        self.drift = drift.ADWIN()
        self.labels = Counter()
        self.count = 0
        self.drift_events = 0
        self.paused = False

    def _learn(self, x, y):
        prediction = self.model.predict_one(x)
        self.accuracy.update(y, bool(prediction))
        self.f1.update(y, bool(prediction))
        self.drift.update(int(bool(prediction) != y))
        if self.drift.drift_detected:
            self.drift_events += 1
            self.paused = True
        if not self.paused:
            self.model.learn_one(x, y)
        self.labels[str(y)] += 1
        self.count += 1

    def predict(self, x):
        with self.lock:
            mature = self.count >= 30 and min(self.labels.get("True", 0), self.labels.get("False", 0)) >= 5
            return {
                "probability": self.model.predict_proba_one(x).get(True, 0.5) if mature else None,
                "status": "drift_paused" if self.paused else ("experimental" if mature else "cold_start"),
                "trained_labels": self.count,
            }

    def feedback(self, event_id, body):
        with self.lock:
            if any(f["event_id"] == event_id for f in self.store.list("feedback", 1000000)):
                raise ValueError("This event already has a validated label")
            event = self.store.get("event", event_id)
            if self.paused:
                raise ValueError("Learning paused after drift; review/export the dataset before restarting the model")
            if self.count >= 10000:
                raise ValueError("Demonstration dataset limit reached; export and review before extending")
            record = self.store.add("feedback", dict(body, event_id=event_id, features=event["features"], actor="operator"))
            self._learn(event["features"], body["malicious"])
            return record

    def metrics(self):
        with self.lock:
            return {"labels": self.count, "class_counts": dict(self.labels), "accuracy": self.accuracy.get(),
                    "f1": self.f1.get(), "drift_events": self.drift_events, "paused": self.paused,
                    "evaluation": "predict-before-learn on operator labels; not an independent benchmark"}

    def ingest(self, event):
        x = features(event)
        return self.store.add("event", dict(event, features=x, indicators=rules(event), prediction=self.predict(x)))
