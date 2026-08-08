import unittest
from datetime import datetime, timedelta, timezone

from password_auditor.detector import AuthEventDetector, DetectionConfig
from password_auditor.models import AuthEvent


def event(second: int, source: str, username: str, status: str = "failure") -> AuthEvent:
    timestamp = (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=second)).isoformat()
    return AuthEvent(timestamp, source, username, status, "ssh", "lab")


class DetectorTests(unittest.TestCase):
    def test_brute_force_alert(self) -> None:
        detector = AuthEventDetector()
        alerts = []
        for second in range(5):
            alerts.extend(detector.process(event(second, "198.51.100.5", "alex")))
        self.assertEqual([alert.rule_id for alert in alerts], ["PA1001"])

    def test_multi_account_burst_alert(self) -> None:
        config = DetectionConfig(brute_force_threshold=20, multi_account_threshold=3)
        detector = AuthEventDetector(config)
        alerts = []
        for index, username in enumerate(("alex", "sam", "jordan")):
            alerts.extend(detector.process(event(index, "198.51.100.8", username)))
        self.assertIn("PA1002", {alert.rule_id for alert in alerts})

    def test_distributed_brute_force_alert(self) -> None:
        config = DetectionConfig(brute_force_threshold=20, distributed_source_threshold=3)
        detector = AuthEventDetector(config)
        alerts = []
        for index in range(3):
            alerts.extend(detector.process(event(index, f"203.0.113.{index + 1}", "admin")))
        self.assertIn("PA1003", {alert.rule_id for alert in alerts})

    def test_success_is_ignored(self) -> None:
        detector = AuthEventDetector(DetectionConfig(brute_force_threshold=1))
        self.assertEqual(detector.process(event(0, "198.51.100.5", "alex", "success")), [])

    def test_out_of_order_events_are_rejected(self) -> None:
        detector = AuthEventDetector()
        detector.process(event(2, "198.51.100.5", "alex", "success"))
        with self.assertRaises(ValueError):
            detector.process(event(1, "198.51.100.5", "alex"))


if __name__ == "__main__":
    unittest.main()
