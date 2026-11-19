import contextlib
import io
import json
import os
import tempfile
import unittest

import smpp_netprobe_summary as summary

HEADER = ("HOST: ip-172-31-30-172.ap-southeast-1.compute.internal "
          "Loss%   Snt   Last   Avg  Best  Wrst StDev\n")

# Shape of a real report (2026-11-19, smpp_ngt): hops 4 and 8 drop probes but
# the destination answers every one of them.
RATE_LIMITED = HEADER + """\
  1.|-- 240.64.94.129                0.0%   120    1.3   0.7   0.3   6.4   0.7
  2.|-- 240.1.168.71                 0.0%   120    0.8   1.0   0.8  14.6   1.4
  3.|-- 116.51.17.25                 0.0%   120    0.9   1.0   0.8   5.6   0.5
  4.|-- 129.250.6.62                30.0%   120    1.1   1.1   0.9   1.4   0.0
  5.|-- 129.250.7.9                  0.0%   120  143.4 143.3 143.0 149.4   0.7
  6.|-- ???                         100.0   120    0.0   0.0   0.0   0.0   0.0
  7.|-- 129.250.2.9                 10.0%   120  153.5 153.4 153.3 153.7   0.0
  8.|-- 192.0.2.10                   0.0%   120  160.3 160.3 160.2 160.6   0.0
"""

PERSISTENT = HEADER + """\
  1.|-- 240.64.94.129                0.0%   120    1.3   0.7   0.3   6.4   0.7
  2.|-- 116.51.17.25                40.0%   120    0.9   1.0   0.8   5.6   0.5
  3.|-- 129.250.6.62                 0.0%   120    1.1   1.1   0.9   1.4   0.0
  4.|-- 129.250.7.9                  7.5%   120  143.4 143.3 143.0 149.4   0.7
  5.|-- ???                         100.0   120    0.0   0.0   0.0   0.0   0.0
  6.|-- 129.250.2.9                  5.0%   120  153.5 153.4 153.3 153.7   0.0
  7.|-- 192.0.2.10                   6.7%   120  160.3 161.0 160.2 520.6  30.1
"""

NO_ICMP_AT_TARGET = HEADER + """\
  1.|-- 242.4.84.133                 0.0%   120    1.3   1.9   0.7  16.5   2.4
  2.|-- 63.222.8.9                  63.0%   120    1.0   0.9   0.8   1.1   0.0
  3.|-- 26.25.157.41                82.0%   120   34.8  35.2  34.7  35.5   0.0
  4.|-- ???                         100.0   120    0.0   0.0   0.0   0.0   0.0
"""

SS_SERIES = """\
### 2026-11-19 11:35:52.113 CST
State      Recv-Q Send-Q Local Address:Port               Peer Address:Port
ESTAB      0      0      172.31.30.172:41532              192.0.2.10:2775
\t cubic wscale:7,7 rto:364 rtt:160.2/2.1 mss:1448 cwnd:10 retrans:0/3 lastsnd:20
SYN-SENT   0      1      172.31.30.172:53581              192.0.2.10:2775
\t cubic rto:1000 mss:524 cwnd:10 segs_out:1 unacked:1
### 2026-11-19 11:35:54.120 CST
State      Recv-Q Send-Q Local Address:Port               Peer Address:Port
ESTAB      0      3480   172.31.30.172:41532              192.0.2.10:2775
\t cubic wscale:7,7 rto:1600 rtt:210.5/40.0 mss:1448 cwnd:2 retrans:1/9 lastsnd:20
ESTAB      0      0      172.31.30.172:41540              192.0.2.10:2775
\t cubic wscale:7,7 rto:364 rtt:161.0/2.0 mss:1448 cwnd:10 lastsnd:20
"""

DIAGNOSIS = """\
============================================================
事故编号：20261119-113450-smpp_ngt

对应 PCAP：
  /root/smpp-monitor/incidents/x/pcap/a.pcapng
============================================================
"""


class PathTest(unittest.TestCase):
    def test_parses_report_rows(self):
        hops = summary.parse_mtr(RATE_LIMITED)
        self.assertEqual(len(hops), 8)
        self.assertEqual(hops[3], summary.Hop(4, "129.250.6.62", 30.0, 120, 1.1, 1.4))
        self.assertEqual(hops[5].loss, 100.0)

    def test_loss_that_stops_before_target_is_rate_limiting(self):
        lines = summary.summarize_path(summary.parse_mtr(RATE_LIMITED), "192.0.2.10")
        self.assertEqual(len(lines), 1)
        self.assertIn("去程路径正常", lines[0])
        self.assertIn("第 4、7 跳", lines[0])

    def test_loss_carried_to_target_names_first_hop(self):
        lines = summary.summarize_path(summary.parse_mtr(PERSISTENT), "192.0.2.10")
        self.assertIn("终点丢包 6.7%", lines[0])
        # Hop 2 is rate limiting (hop 3 is clean); the stretch starts at hop 4
        # and the unanswered hop 5 does not break it.
        self.assertIn("从第 4 跳 129.250.7.9 开始", lines[0])
        self.assertIn("第 3 跳 129.250.6.62 到它之间", lines[0])
        self.assertIn("抖动明显", lines[1])

    def test_target_not_answering_icmp(self):
        lines = summary.summarize_path(summary.parse_mtr(NO_ICMP_AT_TARGET), "192.0.2.10")
        self.assertEqual(len(lines), 1)
        self.assertIn("不回应 ICMP", lines[0])
        self.assertIn("只看到第 3 跳 26.25.157.41 为止", lines[0])

    def test_empty_report(self):
        self.assertIn("没有输出", summary.summarize_path([], "192.0.2.10")[0])


class SocketTest(unittest.TestCase):
    def test_counts_retransmission_growth_per_connection(self):
        line = summary.summarize_ss(*summary.parse_ss(SS_SERIES))[0]
        self.assertIn("2 次采样，2 条已建立连接，重传累计增加 6 次", line)
        self.assertIn("本地端口 41532，+6", line)
        self.assertIn("rtt 160~210 ms", line)
        self.assertIn("1 次建连停在 SYN-SENT", line)

    def test_no_established_connection(self):
        text = "### t\nState Recv-Q\nSYN-SENT   0      1      1.1.1.1:5 2.2.2.2:6\n\t rto:1000\n"
        line = summary.summarize_ss(*summary.parse_ss(text))[0]
        self.assertIn("都没有已建立的连接", line)
        self.assertIn("1 次建连停在 SYN-SENT", line)


class RetransmissionTest(unittest.TestCase):
    def events(self, *sources):
        return {"events": [{"type": "TCP_RETRANSMISSION", "source": s, "count": 5}
                           for s in sources] + [{"type": "SMPP_RESP_TIMEOUT"}]}

    def test_direction(self):
        self.assertIn("去程嫌疑", summary.summarize_retransmissions(self.events("local"))[0])
        self.assertIn("回程", summary.summarize_retransmissions(self.events("supplier"))[0])
        both = summary.summarize_retransmissions(self.events("local", "supplier"))[0]
        self.assertIn("本机重传 5 次，供应商重传 5 次", both)

    def test_no_retransmission_events(self):
        self.assertEqual(summary.summarize_retransmissions({"events": []}), [])


class EndToEndTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.net = os.path.join(self.tmp.name, "net")
        os.mkdir(self.net)
        with open(os.path.join(self.net, "mtr-icmp.txt"), "w") as f:
            f.write("# start x\n" + PERSISTENT + "# end x\n")
        with open(os.path.join(self.net, "ss-series.txt"), "w") as f:
            f.write(SS_SERIES)
        self.details = os.path.join(self.tmp.name, "details.json")
        with open(self.details, "w") as f:
            json.dump({"events": [{"type": "TCP_RETRANSMISSION", "source": "local",
                                   "count": 7}]}, f)
        self.diagnosis = os.path.join(self.tmp.name, "diagnosis.txt")
        with open(self.diagnosis, "w") as f:
            f.write(DIAGNOSIS)

    def tearDown(self):
        self.tmp.cleanup()

    def test_summary_lands_before_closing_line_and_rerun_replaces_it(self):
        args = [self.net, "192.0.2.10", "--details", self.details,
                "--diagnosis", self.diagnosis]
        with contextlib.redirect_stdout(io.StringIO()):
            summary.main(args)
            summary.main(args)
        with open(self.diagnosis) as f:
            text = f.read()
        self.assertEqual(text.count("网络现场（netprobe）："), 1)
        self.assertTrue(text.startswith(DIAGNOSIS[:-61]))
        self.assertTrue(text.endswith("（最多的是本地端口 41532，+6）"
                                      "，rtt 160~210 ms；另有 1 次建连停在 SYN-SENT。\n"
                                      "  重传（抓包）：本机重传 7 次，供应商重传 0 次。"
                                      "只有我们在重传：我们发出的数据或对方的确认在路上丢了，"
                                      "去程嫌疑更大。\n" + "=" * 60 + "\n"))
        self.assertIn("a.pcapng\n\n网络现场（netprobe）：\n  路径：终点丢包 6.7%", text)

    def test_missing_inputs(self):
        empty = os.path.join(self.tmp.name, "empty")
        os.mkdir(empty)
        self.assertIn("没有可用的现场网络数据", summary.build_summary(empty, "192.0.2.10"))


if __name__ == "__main__":
    unittest.main()
