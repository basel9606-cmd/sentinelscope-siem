import json
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


INTEGRATION_DIR = Path(__file__).resolve().parents[1] / "integrations" / "wazuh"
sys.path.insert(0, str(INTEGRATION_DIR))

import alerts_tail  # noqa: E402
import sentinelscope  # noqa: E402


class WazuhNormalizationTests(unittest.TestCase):
    def test_normalises_real_wazuh_shape(self):
        alert = {
            "id": "1770000000.123",
            "timestamp": "2026-09-02T18:12:00Z",
            "agent": {"id": "001", "name": "windows11"},
            "rule": {
                "level": 12,
                "description": "SentinelScope Wazuh Test Alert",
                "mitre": {"id": ["T1059.001"], "technique": ["PowerShell"]},
            },
        }

        result = sentinelscope.normalise(alert)

        self.assertEqual(result["id"], "wazuh-1770000000.123")
        self.assertEqual(result["entity"], "windows11")
        self.assertEqual(result["severity"], "critical")
        self.assertEqual(result["mitre_technique"], "T1059.001")

    def test_missing_id_has_stable_fingerprint(self):
        alert = {"agent": {"name": "windows11"}, "rule": {"level": 5, "description": "Test"}}
        self.assertEqual(sentinelscope.normalise(alert)["id"], sentinelscope.normalise(alert)["id"])


class AlertsTailTests(unittest.TestCase):
    def test_once_delivers_matching_records_and_checkpoints(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            alerts_file = root / "alerts.json"
            state_file = root / "collector.offset"
            records = [
                {"id": "1", "agent": {"name": "windows11"}, "rule": {"level": 7, "description": "Real alert"}},
                {"id": "2", "agent": {"name": "windows11"}, "rule": {"level": 1, "description": "Below threshold"}},
            ]
            alerts_file.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")
            args = Namespace(file=str(alerts_file), state_file=str(state_file), batch_size=50, poll_interval=0.2, min_level=3, from_start=True, once=True)

            with mock.patch.object(alerts_tail, "post_alerts", return_value={"accepted": 1}) as deliver:
                self.assertEqual(alerts_tail.run(args), 0)

            delivered = deliver.call_args.args[0]
            self.assertEqual([item["id"] for item in delivered], ["wazuh-1"])
            self.assertEqual(json.loads(state_file.read_text(encoding="utf-8"))["offset"], alerts_file.stat().st_size)

            with mock.patch.object(alerts_tail, "post_alerts") as deliver_again:
                self.assertEqual(alerts_tail.run(args), 0)
                deliver_again.assert_not_called()


if __name__ == "__main__":
    unittest.main()
