#!/usr/bin/env python3
"""Turn one netprobe's raw output into a few lines of conclusions.

Inputs (all optional, a missing one just drops its line):
  <net_dir>/mtr-icmp.txt   `mtr -n -r -w` report toward the supplier
  <net_dir>/ss-series.txt  repeated `ss -tin` samples of the real SMPP sockets
  details.json             the incident's events (pcap retransmissions)

Prints the summary; with --diagnosis it is also inserted into that file before
its closing separator line, so the exported incident shows it.

Reading mtr: a router may skip answering probes addressed to itself (ICMP rate
limiting) while still forwarding traffic, so loss that does not carry on to the
destination is noise. Loss that starts at hop N and persists to the destination
points at the link into hop N.
"""
import argparse
import collections
import json
import os
import re
import sys

# 120 probes: 2 lost (1.7%) is the smallest loss worth a conclusion.
LOSS_THRESHOLD = 1.5
# An earlier hop belongs to the lossy stretch when it loses at least this share
# of the destination's loss (and at least 1%).
CHAIN_RATIO = 0.5
JITTER_FACTOR = 3.0
JITTER_MIN_MS = 100.0

HOP_RE = re.compile(
    r"^\s*(\d+)\.\|--\s+(\S+)\s+([\d.]+)%?\s+(\d+)\s+([\d.]+)\s+([\d.]+)"
    r"\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*$")
SS_STATE_RE = re.compile(r"^([A-Z][A-Z0-9-]+)\s+\d+\s+\d+\s+(\S+)\s+(\S+)")
SS_RETRANS_RE = re.compile(r"\bretrans:\d+/(\d+)")
SS_RTT_RE = re.compile(r"\brtt:([\d.]+)/")

Hop = collections.namedtuple("Hop", "number host loss sent avg worst")


def parse_mtr(text):
    hops = []
    for line in text.splitlines():
        match = HOP_RE.match(line)
        if match:
            hops.append(Hop(int(match.group(1)), match.group(2),
                            float(match.group(3)), int(match.group(4)),
                            float(match.group(6)), float(match.group(8))))
    return hops


def hop_name(hop):
    return "第 {} 跳 {}".format(hop.number, hop.host)


def summarize_path(hops, target_ip):
    if not hops:
        return ["路径：mtr 没有输出。"]
    answered = [hop for hop in hops if hop.host != "???"]
    last = hops[-1]
    if last.host != target_ip:
        reach = answered[-1] if answered else None
        seen = "，只看到{} 为止".format(hop_name(reach)) if reach else ""
        return ["路径：终点 {} 不回应 ICMP{}。mtr 看不到端到端情况，"
                "以下面的连接和重传数据为准。".format(target_ip, seen)]

    lines = []
    if last.loss < LOSS_THRESHOLD:
        noisy = [hop for hop in answered[:-1] if hop.loss > 0]
        line = "路径：终点丢包 {:.1f}%（平均 {:.0f} ms），去程路径正常。".format(
            last.loss, last.avg)
        if noisy:
            which = ("第 " + "、".join(str(hop.number) for hop in noisy) + " 跳"
                     if len(noisy) <= 4 else "中间 {} 跳".format(len(noisy)))
            line += "{}的丢包没有延续到终点，是路由器限速回包，可以忽略。".format(which)
        lines.append(line)
    else:
        floor = max(last.loss * CHAIN_RATIO, 1.0)
        start = len(answered) - 1
        while start > 0 and answered[start - 1].loss >= floor:
            start -= 1
        first = answered[start]
        if start == 0:
            where = "从第一个回应的{}起就在丢，问题靠近本机或 AWS 出口".format(
                hop_name(first))
        else:
            where = "从{} 开始一直延续到终点，问题大概率在{} 到它之间".format(
                hop_name(first), hop_name(answered[start - 1]))
        lines.append("路径：终点丢包 {:.1f}%，{}。".format(last.loss, where))

    if last.worst > max(last.avg * JITTER_FACTOR, last.avg + JITTER_MIN_MS):
        lines.append("延迟：到终点平均 {:.0f} ms，最差 {:.0f} ms，抖动明显。".format(
            last.avg, last.worst))
    return lines


def parse_ss(text):
    """Return (sample count, {local port: [(state, retrans_total, rtt)]})."""
    samples = 0
    sockets = collections.OrderedDict()
    current = None
    for line in text.splitlines():
        if line.startswith("###"):
            samples += 1
            current = None
            continue
        match = SS_STATE_RE.match(line)
        if match and match.group(1) != "State":
            port = match.group(2).rsplit(":", 1)[-1]
            current = [match.group(1), 0, None]
            sockets.setdefault(port, []).append(current)
            continue
        if current is not None and line[:1] in ("\t", " "):
            retrans = SS_RETRANS_RE.search(line)
            rtt = SS_RTT_RE.search(line)
            if retrans:
                current[1] = int(retrans.group(1))
            if rtt:
                current[2] = float(rtt.group(1))
    return samples, sockets


def summarize_ss(samples, sockets):
    if not samples:
        return []
    established = {port: rows for port, rows in sockets.items()
                   if any(row[0] == "ESTAB" for row in rows)}
    connecting = [port for port, rows in sockets.items()
                  if all(row[0] == "SYN-SENT" for row in rows)]
    if not established:
        line = "连接：{} 次 ss 采样都没有已建立的连接".format(samples)
        if connecting:
            line += "，有 {} 次建连停在 SYN-SENT（对方没回应握手）".format(len(connecting))
        return [line + "。"]

    growth = {}
    rtts = []
    for port, rows in established.items():
        estab = [row for row in rows if row[0] == "ESTAB"]
        growth[port] = estab[-1][1] - estab[0][1]
        rtts.extend(row[2] for row in estab if row[2] is not None)
    total = sum(growth.values())
    line = "连接：{} 次采样，{} 条已建立连接，重传累计增加 {} 次".format(
        samples, len(established), total)
    if total:
        worst = max(growth, key=growth.get)
        line += "（最多的是本地端口 {}，+{}）".format(worst, growth[worst])
    if rtts:
        line += "，rtt {:.0f}~{:.0f} ms".format(min(rtts), max(rtts))
    if connecting:
        line += "；另有 {} 次建连停在 SYN-SENT".format(len(connecting))
    return [line + "。"]


def summarize_retransmissions(details):
    counts = collections.Counter()
    for event in details.get("events", []):
        if event.get("type") == "TCP_RETRANSMISSION":
            counts[event.get("source", "")] += int(event.get("count", 1))
    local, supplier = counts["local"], counts["supplier"]
    if not local and not supplier:
        return []
    line = "重传（抓包）：本机重传 {} 次，供应商重传 {} 次。".format(local, supplier)
    if local and not supplier:
        line += "只有我们在重传：我们发出的数据或对方的确认在路上丢了，去程嫌疑更大。"
    elif supplier and not local:
        line += "只有供应商在重传：对方发来的数据或我们的确认在路上丢了，多见于回程，mtr 看不到这个方向。"
    else:
        line += "双方都在重传，两个方向都有丢包。"
    return [line]


def read(path):
    if not path or not os.path.isfile(path):
        return None
    with open(path, "r", errors="replace") as file_obj:
        return file_obj.read()


def build_summary(net_dir, target_ip, details_path=None):
    lines = []
    mtr = read(os.path.join(net_dir, "mtr-icmp.txt"))
    if mtr is not None:
        lines += summarize_path(parse_mtr(mtr), target_ip)
    ss = read(os.path.join(net_dir, "ss-series.txt"))
    if ss is not None:
        lines += summarize_ss(*parse_ss(ss))
    details = read(details_path)
    if details:
        lines += summarize_retransmissions(json.loads(details))
    if not lines:
        lines = ["没有可用的现场网络数据。"]
    return "网络现场（netprobe）：\n" + "".join("  " + line + "\n" for line in lines)


def insert_into_diagnosis(path, summary):
    """Add the summary as the last section, before the closing ===== line.

    A section from an earlier run is replaced, so re-running is harmless.
    """
    text = read(path)
    if text is None:
        return
    lines = text.splitlines(True)
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    marker = "网络现场（netprobe）："
    for start, line in enumerate(lines):
        if line.startswith(marker):
            end = start + 1
            while end < len(lines) and lines[end].startswith("  "):
                end += 1
            if start > 0 and not lines[start - 1].strip():
                start -= 1
            del lines[start:end]
            break
    insert_at = len(lines)
    if lines and lines[-1].startswith("====="):
        insert_at = len(lines) - 1
    lines[insert_at:insert_at] = ["\n", summary]
    tmp = path + ".tmp"
    with open(tmp, "w") as file_obj:
        file_obj.write("".join(lines))
    os.replace(tmp, path)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("net_dir")
    parser.add_argument("target_ip")
    parser.add_argument("--details", help="incident details.json")
    parser.add_argument("--diagnosis", help="incident diagnosis.txt to update")
    args = parser.parse_args(argv)
    summary = build_summary(args.net_dir, args.target_ip, args.details)
    sys.stdout.write(summary)
    if args.diagnosis:
        insert_into_diagnosis(args.diagnosis, summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
