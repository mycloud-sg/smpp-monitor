import json
import os
import stat
import tempfile
import unittest

import smpp_incident_export as exporter


class IncidentExportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        self.export_dir = os.path.join(root, "export")
        self.details = os.path.join(root, "details.json")
        self.diagnosis = os.path.join(root, "diagnosis.txt")
        self.archive = os.path.join(root, "incident.tar.gz")
        with open(self.diagnosis, "w") as file_obj:
            file_obj.write("事故编号：20261103-113436-smpp_cm_wa\n")
        with open(self.archive, "wb") as file_obj:
            file_obj.write(b"archive-bytes")

    def tearDown(self):
        self.tmp.cleanup()

    def write_details(self, details):
        with open(self.details, "w") as file_obj:
            json.dump(details, file_obj)

    def run_export(self, incident_id="20261103-113436-smpp_cm_wa"):
        return exporter.export(self.export_dir, incident_id, self.details,
                               self.diagnosis, self.archive, "")

    def test_exports_archive_and_summary(self):
        self.write_details({
            "supplier": "smpp_cm_wa", "target": "172.65.255.228:30006",
            "start": 1793676876.0, "end": 1793676901.0, "layer": "SMPP",
            "descriptions": ["submit_sm 超时"], "location": "需对端抓包",
            "events": [{"type": "SMPP_RESP_TIMEOUT", "time": 1793676876.0},
                       {"type": "SMPP_RESP_TIMEOUT", "time": 1793676901.0}],
        })
        summary_path = self.run_export()

        with open(summary_path) as file_obj:
            summary = json.load(file_obj)
        self.assertEqual(summary["supplier"], "smpp_cm_wa")
        self.assertEqual(summary["event_types"], {"SMPP_RESP_TIMEOUT": 2})
        self.assertEqual(summary["archive_size"], len(b"archive-bytes"))
        archive = os.path.join(self.export_dir, summary["archive"])
        with open(archive, "rb") as file_obj:
            self.assertEqual(file_obj.read(), b"archive-bytes")
        self.assertEqual(stat.S_IMODE(os.stat(archive).st_mode), 0o640)
        self.assertEqual(sorted(os.listdir(self.export_dir)),
                         ["20261103-113436-smpp_cm_wa.json",
                          "20261103-113436-smpp_cm_wa.tar.gz"])

    def test_old_details_without_summary_fields(self):
        self.write_details({"supplier": "smpp_cm_wa", "events": [
            {"type": "TCP_RST", "layer": "TCP", "time": 1793676876.0, "end_time": 1793676880.0},
        ]})
        with open(self.run_export()) as file_obj:
            summary = json.load(file_obj)
        self.assertEqual(summary["layer"], "TCP")
        self.assertTrue(summary["start"])
        self.assertTrue(summary["end"])

    def test_rejects_path_like_incident_id(self):
        self.write_details({"events": []})
        with self.assertRaises(ValueError):
            self.run_export("../../etc/passwd")


if __name__ == "__main__":
    unittest.main()
