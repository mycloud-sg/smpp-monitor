import unittest

import smpp_detector as detector


SUPPLIERS = {"supplier": {"ip": "85.119.48.101", "port": "30000", "timeout": 30}}


def packet(time, src, dst, srcport, dstport, command="", sequence="", status="",
           retransmission=""):
    fields = [str(time), src, dst, str(srcport), str(dstport), "0", "0", "0",
              retransmission, "0", command, sequence, status]
    return "\t".join(fields)


class DetectorTest(unittest.TestCase):
    def test_unanswered_submit_expires_across_capture_files(self):
        request = packet(100, "172.31.30.172", "85.119.48.101", 26840, 30000,
                         "0x00000004", "11", "0")
        findings, pending = detector.analyze([request], SUPPLIERS)
        self.assertEqual(findings, {})
        self.assertEqual(len(pending), 1)

        other_traffic = packet(131, "172.31.30.172", "85.119.48.101", 26840, 30000)
        findings, pending = detector.analyze([other_traffic], SUPPLIERS, pending)
        self.assertEqual(len(pending), 0)
        event = findings["supplier"][0]
        self.assertEqual(event["type"], "SMPP_RESP_TIMEOUT")
        self.assertEqual(event["sequence"], "11")
        self.assertEqual(event["local_port"], "26840")
        self.assertFalse(event["response_seen"])

    def test_response_in_next_file_cancels_pending_request(self):
        request = packet(100, "172.31.30.172", "85.119.48.101", 26840, 30000,
                         "0x00000004", "11", "0")
        _, pending = detector.analyze([request], SUPPLIERS)
        response = packet(120, "85.119.48.101", "172.31.30.172", 30000, 26840,
                          "0x80000004", "11", "0")
        findings, pending = detector.analyze([response], SUPPLIERS, pending)
        self.assertEqual(findings, {})
        self.assertEqual(pending, {})

    def test_multiple_pdus_in_one_tcp_packet_are_all_tracked(self):
        requests = packet(100, "172.31.30.172", "85.119.48.101", 26840, 30000,
                          "0x00000004,0x00000004", "11,12", "0,0")
        _, pending = detector.analyze([requests], SUPPLIERS)
        self.assertEqual(len(pending), 2)
        response = packet(110, "85.119.48.101", "172.31.30.172", 30000, 26840,
                          "0x80000004", "11", "0")
        tick = packet(131, "172.31.30.172", "85.119.48.101", 26840, 30000)
        findings, pending = detector.analyze([response, tick], SUPPLIERS, pending)
        self.assertEqual([event["sequence"] for event in findings["supplier"]], ["12"])
        self.assertEqual(pending, {})

    def test_retransmission_does_not_restart_timeout(self):
        request = packet(100, "172.31.30.172", "85.119.48.101", 26840, 30000,
                         "0x00000004", "11", "0")
        retransmission = packet(120, "172.31.30.172", "85.119.48.101", 26840, 30000,
                                "0x00000004", "11", "0", retransmission="1")
        _, pending = detector.analyze([request], SUPPLIERS)
        findings, pending = detector.analyze([retransmission], SUPPLIERS, pending)
        self.assertEqual(findings, {})
        self.assertEqual(next(iter(pending.values())), 100)

    def test_response_status_is_aligned_after_other_response_pdu(self):
        request = packet(100, "172.31.30.172", "85.119.48.101", 26840, 30000,
                         "0x00000004", "11", "")
        _, pending = detector.analyze([request], SUPPLIERS)
        responses = packet(110, "85.119.48.101", "172.31.30.172", 30000, 26840,
                           "0x80000005,0x80000004", "9,11", "0x00000000,0x00000058")
        findings, pending = detector.analyze([responses], SUPPLIERS, pending)
        self.assertEqual(pending, {})
        self.assertEqual(findings["supplier"][0]["type"], "SMPP_SUBMIT_FAILED")
        self.assertEqual(findings["supplier"][0]["status"], "ESME_RTHROTTLED")

    def test_retransmissions_are_counted_per_connection(self):
        mixed = [packet(100 + i, "172.31.30.172", "85.119.48.101",
                        26840 if i < 3 else 42400, 30000, retransmission="1")
                 for i in range(6)]
        findings, _ = detector.analyze(mixed, SUPPLIERS)
        self.assertEqual(findings, {})

        same_connection = [packet(100 + i, "172.31.30.172", "85.119.48.101",
                                  26840, 30000, retransmission="1") for i in range(5)]
        findings, _ = detector.analyze(same_connection, SUPPLIERS)
        event = findings["supplier"][0]
        self.assertEqual(event["type"], "TCP_RETRANSMISSION")
        self.assertEqual(event["local_port"], "26840")
        self.assertEqual(event["source"], "local")


if __name__ == "__main__":
    unittest.main()
