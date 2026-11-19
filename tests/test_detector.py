import unittest

import smpp_detector as detector


SUPPLIERS = {"supplier": {"ip": "85.119.48.101", "port": "30000", "timeout": 30}}


def packet(time, src, dst, srcport, dstport, command="", sequence="", status="",
           retransmission="", payload="", length="", captured=""):
    fields = [str(time), src, dst, str(srcport), str(dstport), "0", "0", "0",
              retransmission, "0", command, sequence, status,
              str(payload), str(length), str(captured)]
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

    def test_undecoded_supplier_segment_cancels_pending_request(self):
        # tshark 2.x after a snaplen-truncated segment: the response frame is
        # reported as "TCP segment of a reassembled PDU" without SMPP fields.
        request = packet(100, "172.31.30.172", "85.119.48.101", 26840, 30000,
                         "0x00000004", "11", "")
        other_connection = packet(100, "172.31.30.172", "85.119.48.101", 42400, 30000,
                                  "0x00000004", "12", "")
        undecoded = packet(100.5, "85.119.48.101", "172.31.30.172", 30000, 26840,
                           payload=49, length=117, captured=117)
        later_request = packet(101, "172.31.30.172", "85.119.48.101", 26840, 30000,
                               "0x00000004", "13", "")
        _, pending = detector.analyze([request, other_connection, undecoded, later_request],
                                      SUPPLIERS)
        self.assertEqual(sorted(pending), ["supplier|26840|13", "supplier|42400|12"])

        tick = packet(131, "172.31.30.172", "85.119.48.101", 26840, 30000, payload=0)
        findings, pending = detector.analyze([tick], SUPPLIERS, pending)
        self.assertEqual(sorted(event["sequence"] for event in findings["supplier"]),
                         ["12", "13"])
        self.assertEqual(pending, {})

    def test_truncated_supplier_segment_cancels_pending_request(self):
        request = packet(100, "172.31.30.172", "85.119.48.101", 26840, 30000,
                         "0x00000004", "11", "")
        truncated = packet(101, "85.119.48.101", "172.31.30.172", 30000, 26840,
                           "0x00000005", "7", "", payload=1448, length=1516, captured=1024)
        _, pending = detector.analyze([request, truncated], SUPPLIERS)
        self.assertEqual(pending, {})

    def test_empty_ack_from_supplier_keeps_pending_request(self):
        request = packet(100, "172.31.30.172", "85.119.48.101", 26840, 30000,
                         "0x00000004", "11", "")
        ack = packet(100.1, "85.119.48.101", "172.31.30.172", 30000, 26840,
                     payload=0, length=68, captured=68)
        _, pending = detector.analyze([request, ack], SUPPLIERS)
        self.assertEqual(list(pending), ["supplier|26840|11"])

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

    def test_bind_responses_record_status_and_port(self):
        failed = packet(100, "85.119.48.101", "172.31.30.172", 30000, 26840,
                        "0x80000009", "1", "0x0000000e")
        ok = packet(101, "85.119.48.101", "172.31.30.172", 30000, 26842,
                    "0x80000009", "2", "0x00000000")
        findings, _ = detector.analyze([failed, ok], SUPPLIERS)
        events = findings["supplier"]
        self.assertEqual([e["type"] for e in events], ["SMPP_BIND_FAILED", "SMPP_BIND_OK"])
        self.assertEqual(events[0]["status_code"], "0xe")
        self.assertEqual(events[0]["local_port"], "26840")

    def test_reset_after_fin_is_a_normal_close(self):
        fin = packet(100, "172.31.30.172", "85.119.48.101", 26840, 30000).split("\t")
        fin[7] = "1"
        rst = packet(101, "85.119.48.101", "172.31.30.172", 30000, 26840).split("\t")
        rst[6] = "1"
        findings, _ = detector.analyze(["\t".join(fin), "\t".join(rst)], SUPPLIERS)
        self.assertEqual(findings, {})

        closing = {}
        detector.analyze(["\t".join(fin)], SUPPLIERS, closing=closing)
        findings, _ = detector.analyze(["\t".join(rst)], SUPPLIERS, closing=closing)
        self.assertEqual(findings, {}, "FIN and RST in different capture files")

        other = packet(102, "85.119.48.101", "172.31.30.172", 30000, 26842).split("\t")
        other[6] = "1"
        findings, _ = detector.analyze(["\t".join(other)], SUPPLIERS)
        self.assertEqual(findings["supplier"][0]["type"], "TCP_RESET")


def ev(event_type, time, **details):
    return detector.event(event_type, "TCP" if event_type.startswith("TCP") else "SMPP",
                          time, **details)


class SelectIncidentEventsTest(unittest.TestCase):
    def test_retransmission_alone_is_not_an_incident(self):
        events = [ev("TCP_RETRANSMISSION", 100, count=20, local_port="1")]
        self.assertEqual(detector.select_incident_events(events, {}), [])

    def test_retransmission_is_kept_as_context_of_a_timeout(self):
        events = [ev("TCP_RETRANSMISSION", 100, count=20, local_port="1"),
                  ev("SMPP_RESP_TIMEOUT", 130, local_port="1")]
        selected = detector.select_incident_events(events, {})
        self.assertEqual([e["type"] for e in selected],
                         ["TCP_RETRANSMISSION", "SMPP_RESP_TIMEOUT"])

    def test_repeated_bind_failure_is_reported_once_until_bind_succeeds(self):
        state = {}
        fail = [ev("SMPP_BIND_FAILED", 100, status_code="0xe", local_port="1")]
        self.assertTrue(detector.select_incident_events(fail, state))
        self.assertIn("0xe", state)
        again = [ev("SMPP_BIND_FAILED", 160, status_code="0xe", local_port="2")]
        self.assertEqual(detector.select_incident_events(again, state), [])

        other_code = [ev("SMPP_BIND_FAILED", 170, status_code="0xd", local_port="3")]
        self.assertTrue(detector.select_incident_events(other_code, state))

        recovered = [ev("SMPP_BIND_OK", 200, local_port="4")]
        self.assertEqual(detector.select_incident_events(recovered, state), [])
        self.assertEqual(state, {})
        self.assertTrue(detector.select_incident_events(again, state))

    def test_bind_ok_before_failure_in_same_capture_keeps_failure_active(self):
        state = {"0xe": 50}
        events = [ev("SMPP_BIND_OK", 100, local_port="1"),
                  ev("SMPP_BIND_FAILED", 110, status_code="0xe", local_port="2")]
        self.assertTrue(detector.select_incident_events(events, state))
        self.assertEqual(state, {"0xe": 110})

    def test_reset_of_a_rejected_bind_does_not_trigger(self):
        state = {"0xe": 50}
        events = [ev("SMPP_BIND_FAILED", 100, status_code="0xe", local_port="7"),
                  ev("TCP_RESET", 100.1, source="local", local_port="7")]
        self.assertEqual(detector.select_incident_events(events, state), [])

    def test_reset_of_a_working_connection_triggers(self):
        state = {"0xe": 50}
        events = [ev("SMPP_BIND_FAILED", 100, status_code="0xe", local_port="7"),
                  ev("TCP_RESET", 101, source="supplier", local_port="8")]
        selected = detector.select_incident_events(events, state)
        self.assertEqual([e["type"] for e in selected], ["SMPP_BIND_FAILED", "TCP_RESET"])


if __name__ == "__main__":
    unittest.main()
