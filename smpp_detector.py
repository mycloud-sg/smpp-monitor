#!/usr/bin/env python3
"""Decode one completed shared capture and produce human-readable diagnoses."""

import configparser
import datetime as dt
import glob
import json
import os
import subprocess
import sys
import time


BASE_DIR = os.environ.get(
    "SMPP_MONITOR_HOME", os.path.dirname(os.path.abspath(__file__))
)
CONFIG_FILE = os.path.join(BASE_DIR, "smpp_suppliers.conf")
CAPTURE_DIR = os.path.join(BASE_DIR, "captures", "ring")
DIAGNOSIS_DIR = os.path.join(BASE_DIR, "diagnosis")
DIAGNOSIS_LOG = os.path.join(BASE_DIR, "diagnosis.log")
DIAGNOSIS_LATEST = os.path.join(BASE_DIR, "diagnosis-latest.txt")
LATEST_DIR = os.path.join(BASE_DIR, "state", "latest")
COOLDOWN_DIR = os.path.join(BASE_DIR, "state", "cooldown")
PENDING_FILE = os.path.join(BASE_DIR, "state", "pending-submits.json")
INCIDENT_SCRIPT = os.path.join(BASE_DIR, "smpp_incident.sh")

RETRANSMISSION_THRESHOLD = int(os.environ.get("TCP_RETRANSMISSION_THRESHOLD", "5"))
INCIDENT_COOLDOWN_SECONDS = int(os.environ.get("INCIDENT_COOLDOWN_SECONDS", "300"))
ALERT_ON_FIN = os.environ.get("ALERT_ON_FIN", "0") != "0"

SUBMIT_SM = 0x00000004
SUBMIT_SM_RESP = 0x80000004
BIND_RESPONSES = {0x80000001, 0x80000002, 0x80000009}
UNBIND = 0x00000006

STATUS_MAP = {
    0x00000000: "ESME_ROK",
    0x00000001: "ESME_RINVMSGLEN",
    0x00000002: "ESME_RINVCMDLEN",
    0x00000003: "ESME_RINVCMDID",
    0x00000004: "ESME_RINVBNDSTS",
    0x00000005: "ESME_RALYBND",
    0x00000008: "ESME_RSYSERR",
    0x0000000D: "ESME_RBINDFAIL",
    0x00000045: "ESME_RSUBMITFAIL",
    0x00000058: "ESME_RTHROTTLED",
}


def load_suppliers():
    parser = configparser.ConfigParser()
    if not parser.read(CONFIG_FILE):
        raise RuntimeError("config not found: {}".format(CONFIG_FILE))

    suppliers = {}
    for name in parser.sections():
        ip = parser.get(name, "ip", fallback="").strip()
        port = parser.get(name, "port", fallback="").strip()
        timeout = parser.getint(name, "timeout", fallback=30)
        if not ip or not port.isdigit() or timeout <= 0:
            raise RuntimeError("invalid supplier config: {}".format(name))
        suppliers[name] = {"ip": ip, "port": port, "timeout": timeout}
    if not suppliers:
        raise RuntimeError("no suppliers configured")
    return suppliers


def normalize_number(value):
    value = (value or "").strip().lower()
    if not value:
        return None
    try:
        return int(value, 0)
    except ValueError:
        try:
            return int(value, 16)
        except ValueError:
            return None


def is_true(value):
    return (value or "").strip().lower() in {"1", "true", "set"}


def run_tshark(pcap, suppliers):
    fields = [
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.stream",
        "tcp.flags.reset",
        "tcp.flags.fin",
        "tcp.analysis.retransmission",
        "tcp.analysis.zero_window",
        "smpp.command_id",
        "smpp.sequence_number",
        "smpp.command_status",
    ]
    command = ["tshark", "-n", "-r", pcap]

    # Supplier ports are commonly not the SMPP default port. Force tshark to
    # decode every configured port as SMPP instead of relying on heuristics.
    ports = sorted({config["port"] for config in suppliers.values()}, key=int)
    for port in ports:
        command.extend(["-d", "tcp.port=={},smpp".format(port)])

    command.extend([
        # Include every captured TCP frame so a quiet connection still advances
        # the capture clock used to expire unanswered submit_sm requests.
        "-Y", "tcp",
        "-T", "fields", "-E", "separator=/t", "-E", "occurrence=a",
        "-E", "aggregator=,",
    ])
    for field in fields:
        command.extend(["-e", field])

    process = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    if process.returncode != 0:
        raise RuntimeError("tshark failed: {}".format(process.stderr.strip()))
    return process.stdout.splitlines()


def supplier_for_packet(row, suppliers):
    src_ip, dst_ip = row[1], row[2]
    src_port, dst_port = row[3], row[4]
    for name, config in suppliers.items():
        if src_ip == config["ip"] and src_port == config["port"]:
            return name, "supplier_to_local"
        if dst_ip == config["ip"] and dst_port == config["port"]:
            return name, "local_to_supplier"
    return None, None


def event(event_type, layer, timestamp, **details):
    value = {"type": event_type, "layer": layer, "time": timestamp}
    value.update(details)
    return value


def analyze(lines, suppliers, pending=None, capture_end=None):
    # TCP stream numbers are local to each PCAP. The local TCP port plus the
    # SMPP sequence number remains stable across minute-sized rotations.
    pending = dict(pending or {})
    results = {name: {"events": [], "retransmissions": []} for name in suppliers}
    latest_timestamp = 0

    for line in lines:
        row = line.split("\t")
        row += [""] * (13 - len(row))
        try:
            timestamp = float(row[0])
        except ValueError:
            continue
        latest_timestamp = max(latest_timestamp, timestamp)

        supplier, direction = supplier_for_packet(row, suppliers)
        if not supplier:
            continue

        reset = is_true(row[6])
        fin = is_true(row[7])
        retransmission = is_true(row[8])
        zero_window = is_true(row[9])
        bucket = results[supplier]
        local_port = row[3] if direction == "local_to_supplier" else row[4]

        if reset:
            source = "supplier" if direction == "supplier_to_local" else "local"
            bucket["events"].append(event("TCP_RESET", "TCP", timestamp,
                                          source=source, local_port=local_port))
        if fin and ALERT_ON_FIN:
            source = "supplier" if direction == "supplier_to_local" else "local"
            bucket["events"].append(event("TCP_CLOSED", "TCP", timestamp,
                                          source=source, local_port=local_port))
        if retransmission:
            bucket["retransmissions"].append((timestamp, local_port, direction))
        if zero_window:
            source = "supplier" if direction == "supplier_to_local" else "local"
            bucket["events"].append(event("TCP_RECEIVE_BLOCKED", "TCP", timestamp,
                                          source=source, local_port=local_port))

        commands = row[10].split(",") if row[10] else []
        sequences = row[11].split(",") if row[11] else []
        statuses = row[12].split(",") if row[12] else []
        status_index = 0
        for index, raw_command in enumerate(commands):
            command_id = normalize_number(raw_command)
            sequence = sequences[index].strip() if index < len(sequences) else ""
            if command_id is None or not sequence:
                continue
            # tshark emits command_status only for response PDUs, so this list
            # is shorter than commands in a mixed request/response TCP segment.
            command_status = None
            if command_id & 0x80000000:
                if status_index < len(statuses):
                    command_status = normalize_number(statuses[status_index])
                status_index += 1

            key = "|".join((supplier, local_port, sequence))
            if command_id == SUBMIT_SM and direction == "local_to_supplier":
                if not retransmission:
                    pending.setdefault(key, timestamp)
            elif command_id == SUBMIT_SM_RESP and direction == "supplier_to_local":
                submit_time = pending.pop(key, None)
                if submit_time is not None:
                    delay = timestamp - submit_time
                    timeout = suppliers[supplier]["timeout"]
                    if delay >= timeout:
                        bucket["events"].append(
                            event("SMPP_RESP_TIMEOUT", "SMPP", timestamp,
                                  sequence=sequence, local_port=local_port,
                                  delay=round(delay, 3), timeout=timeout,
                                  response_seen=True)
                        )
                if command_status not in (None, 0):
                    bucket["events"].append(
                        event("SMPP_SUBMIT_FAILED", "SMPP", timestamp,
                              sequence=sequence, status=STATUS_MAP.get(command_status, hex(command_status)),
                              status_code=hex(command_status))
                    )
            elif command_id in BIND_RESPONSES and command_status not in (None, 0):
                bucket["events"].append(
                    event("SMPP_BIND_FAILED", "SMPP", timestamp,
                          status=STATUS_MAP.get(command_status, hex(command_status)),
                          status_code=hex(command_status))
                )
            elif command_id == UNBIND:
                source = "supplier" if direction == "supplier_to_local" else "local"
                bucket["events"].append(event("SMPP_BIND_LOST", "SMPP", timestamp, source=source))

    if not latest_timestamp and capture_end is not None:
        latest_timestamp = capture_end
    for key, submit_time in list(pending.items()):
        name, local_port, sequence = key.split("|", 2)
        if name not in suppliers:
            del pending[key]
            continue
        timeout = suppliers[name]["timeout"]
        if latest_timestamp - submit_time >= timeout:
            results[name]["events"].append(
                event("SMPP_RESP_TIMEOUT", "SMPP", submit_time + timeout,
                      sequence=sequence, local_port=local_port,
                      delay=round(latest_timestamp - submit_time, 3),
                      timeout=timeout, response_seen=False)
            )
            del pending[key]

    for bucket in results.values():
        groups = {}
        for timestamp, local_port, direction in bucket.pop("retransmissions"):
            groups.setdefault((local_port, direction), []).append(timestamp)
        for (local_port, direction), times in groups.items():
            if len(times) >= RETRANSMISSION_THRESHOLD:
                source = "local" if direction == "local_to_supplier" else "supplier"
                bucket["events"].append(
                    event("TCP_RETRANSMISSION", "TCP", min(times),
                          end_time=max(times), count=len(times),
                          local_port=local_port, source=source)
                )
    findings = {name: value["events"] for name, value in results.items() if value["events"]}
    return findings, pending


def load_pending():
    try:
        with open(PENDING_FILE, "r") as file_obj:
            value = json.load(file_obj)
        if isinstance(value, dict):
            return {key: float(timestamp) for key, timestamp in value.items()
                    if isinstance(key, str) and key.count("|") == 2}
    except FileNotFoundError:
        return {}
    except (ValueError, TypeError) as exc:
        raise RuntimeError("invalid pending submit state: {}".format(exc))
    raise RuntimeError("invalid pending submit state: expected object")


def save_pending(pending):
    os.makedirs(os.path.dirname(PENDING_FILE), exist_ok=True)
    temporary = PENDING_FILE + ".tmp"
    with open(temporary, "w") as file_obj:
        json.dump(pending, file_obj)
    os.replace(temporary, PENDING_FILE)


def select_evidence_pcaps(trigger_pcap, limit=5):
    files = [path for path in glob.glob(os.path.join(CAPTURE_DIR, "*.pcap*"))
             if os.path.isfile(path)]
    files.sort(key=os.path.getmtime)
    trigger_pcap = os.path.abspath(trigger_pcap)
    files = [os.path.abspath(path) for path in files]
    if trigger_pcap not in files:
        return [trigger_pcap]
    index = files.index(trigger_pcap)
    start = max(0, index - limit + 1)
    return files[start:index + 1]


def format_time(timestamp):
    return dt.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def unique(values):
    result = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def describe(events):
    types = {item["type"] for item in events}
    descriptions = []

    if "TCP_RESET" in types:
        supplier_reset = any(item["type"] == "TCP_RESET" and item.get("source") == "supplier"
                             for item in events)
        if supplier_reset:
            descriptions.append("抓包看到来源为供应商地址的 RST，连接被复位。")
        else:
            descriptions.append("抓包看到本机发出的 RST，连接被复位。")
    if "TCP_CLOSED" in types:
        supplier_close = any(item["type"] == "TCP_CLOSED" and item.get("source") == "supplier"
                             for item in events)
        if supplier_close:
            descriptions.append("抓包看到来源为供应商地址的 FIN，连接开始关闭。")
        else:
            descriptions.append("抓包看到本机发出的 FIN，连接开始关闭。")
    if "TCP_RETRANSMISSION" in types:
        count = max(item.get("count", 0) for item in events
                    if item["type"] == "TCP_RETRANSMISSION")
        descriptions.append("网络传输不稳定，数据在当前时间段内重复发送了 {} 次。".format(count))
    if "TCP_RECEIVE_BLOCKED" in types:
        descriptions.append("连接一侧曾暂停接收数据，可能造成消息积压。")
    if "SMPP_BIND_FAILED" in types:
        status = next(item.get("status", "未知原因") for item in events
                      if item["type"] == "SMPP_BIND_FAILED")
        descriptions.append("SMPP bind 被拒绝，返回结果为 {}。".format(status))
    if "SMPP_BIND_LOST" in types:
        descriptions.append("已经建立的 SMPP bind 被解除。")
    if "SMPP_RESP_TIMEOUT" in types:
        timeout = next(item.get("timeout", 30) for item in events
                       if item["type"] == "SMPP_RESP_TIMEOUT")
        if any(item.get("response_seen") is False for item in events
               if item["type"] == "SMPP_RESP_TIMEOUT"):
            descriptions.append("submit_sm 发出后超过 {} 秒，抓包中仍未见对应响应。".format(timeout))
        else:
            descriptions.append("submit_sm 已发送，但响应时间超过了 {} 秒。".format(timeout))
    if "SMPP_SUBMIT_FAILED" in types:
        status = next(item.get("status", "未知原因") for item in events
                      if item["type"] == "SMPP_SUBMIT_FAILED")
        descriptions.append("供应商明确返回消息提交失败，返回结果为 {}。".format(status))

    has_tcp = any(item["layer"] == "TCP" for item in events)
    has_smpp = any(item["layer"] == "SMPP" for item in events)
    if has_tcp and has_smpp:
        descriptions.append("SMPP 异常与网络异常发生在同一时间段，优先排查网络连接。")
        layer = "TCP"
    elif has_tcp:
        layer = "TCP"
    else:
        layer = "SMPP"

    if "TCP_RESET" in types or "TCP_CLOSED" in types:
        location = "需对照两端抓包及中间设备日志，确认连接关闭的触发原因。"
    elif has_tcp:
        location = "疑似本机与供应商之间的网络链路问题。"
    elif "SMPP_SUBMIT_FAILED" in types or "SMPP_BIND_FAILED" in types:
        location = "供应商 SMPP 服务返回了明确失败结果。"
    elif "SMPP_RESP_TIMEOUT" in types:
        location = "单侧抓包无法判定请求或响应丢失的位置，需结合 TCP 状态和对端抓包。"
    else:
        location = "疑似供应商 SMPP 服务处理异常，当前证据不足以完全排除网络问题。"

    return layer, unique(descriptions), location


def in_cooldown(supplier, layer, event_types, now):
    os.makedirs(COOLDOWN_DIR, exist_ok=True)
    signature = "-".join(sorted(event_types))
    safe_signature = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in signature)
    path = os.path.join(COOLDOWN_DIR, "{}-{}-{}".format(supplier, layer, safe_signature))
    try:
        with open(path, "r") as file_obj:
            previous = float(file_obj.read().strip())
        if now - previous < INCIDENT_COOLDOWN_SECONDS:
            return True
    except (OSError, ValueError):
        pass
    with open(path, "w") as file_obj:
        file_obj.write(str(now))
    return False


def render_card(incident_id, supplier, config, start, end, layer,
                descriptions, location, pcaps):
    lines = [
        "=" * 60,
        "事故编号：{}".format(incident_id),
        "事故对象：{}".format(supplier),
        "目标地址：{}:{}".format(config["ip"], config["port"]),
        "",
        "时间范围：",
        "  {}".format(format_time(start)),
        "  至 {}".format(format_time(end)),
        "",
        "问题层级：{}".format(layer),
        "",
        "问题说明：",
    ]
    lines.extend("  {}".format(item) for item in descriptions)
    lines.extend(["", "初步定位：", "  {}".format(location), "", "对应 PCAP："])
    lines.extend("  {}".format(path) for path in pcaps)
    lines.extend(["=" * 60, ""])
    return "\n".join(lines)


def rebuild_latest():
    os.makedirs(LATEST_DIR, exist_ok=True)
    paths = glob.glob(os.path.join(LATEST_DIR, "*.txt"))
    paths.sort(key=os.path.getmtime, reverse=True)
    header = "SMPP 诊断状态\n更新时间：{}\n\n".format(
        dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    with open(DIAGNOSIS_LATEST, "w") as output:
        output.write(header)
        for path in paths:
            with open(path, "r") as source:
                output.write(source.read())


def create_incident(supplier, diagnosis_path, details_path, pcaps):
    if not os.path.isfile(INCIDENT_SCRIPT):
        return
    command = ["bash", INCIDENT_SCRIPT, supplier, diagnosis_path, details_path] + pcaps
    process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             universal_newlines=True)
    if process.returncode != 0:
        print(process.stdout, file=sys.stderr)


def handle_diagnosis(supplier, config, events, trigger_pcap):
    timestamps = []
    for item in events:
        timestamps.append(item["time"])
        if "end_time" in item:
            timestamps.append(item["end_time"])
    start, end = min(timestamps), max(timestamps)
    layer, descriptions, location = describe(events)
    event_types = {item["type"] for item in events}
    if in_cooldown(supplier, layer, event_types, time.time()):
        return

    incident_id = "{}-{}".format(
        dt.datetime.fromtimestamp(start).strftime("%Y%m%d-%H%M%S"), supplier
    )
    source_pcaps = select_evidence_pcaps(trigger_pcap)
    incident_pcap_dir = os.path.join(BASE_DIR, "incidents", incident_id, "pcap")
    evidence_pcaps = [os.path.join(incident_pcap_dir, os.path.basename(path))
                      for path in source_pcaps]
    card = render_card(incident_id, supplier, config, start, end, layer,
                       descriptions, location, evidence_pcaps)

    os.makedirs(DIAGNOSIS_DIR, exist_ok=True)
    os.makedirs(LATEST_DIR, exist_ok=True)
    diagnosis_path = os.path.join(DIAGNOSIS_DIR, incident_id + ".txt")
    details_path = os.path.join(DIAGNOSIS_DIR, incident_id + ".details.json")
    with open(diagnosis_path, "w") as file_obj:
        file_obj.write(card)
    with open(details_path, "w") as file_obj:
        json.dump({"supplier": supplier, "pcap": trigger_pcap, "events": events},
                  file_obj, ensure_ascii=False, indent=2)
    with open(DIAGNOSIS_LOG, "a") as file_obj:
        file_obj.write(card)
    with open(os.path.join(LATEST_DIR, supplier + ".txt"), "w") as file_obj:
        file_obj.write(card)
    rebuild_latest()
    create_incident(supplier, diagnosis_path, details_path, source_pcaps)


def main():
    only_supplier = None
    if len(sys.argv) == 2:
        pcap = os.path.abspath(sys.argv[1])
    elif len(sys.argv) == 3:
        # Backward-compatible manual form: supplier capture.pcapng
        only_supplier = sys.argv[1]
        pcap = os.path.abspath(sys.argv[2])
    else:
        print("Usage: smpp_detector.py [supplier] completed_capture.pcapng", file=sys.stderr)
        return 1
    if not os.path.isfile(pcap):
        print("capture not found: {}".format(pcap), file=sys.stderr)
        return 1
    try:
        suppliers = load_suppliers()
        pending = load_pending() if only_supplier is None else {}
        findings, pending = analyze(run_tshark(pcap, suppliers), suppliers, pending,
                                    capture_end=os.path.getmtime(pcap))
        if only_supplier is not None:
            if only_supplier not in suppliers:
                raise RuntimeError("supplier config not found: {}".format(only_supplier))
            findings = ({only_supplier: findings[only_supplier]}
                        if only_supplier in findings else {})
        for supplier, events in findings.items():
            handle_diagnosis(supplier, suppliers[supplier], events, pcap)
        if only_supplier is None:
            save_pending(pending)
        return 2 if findings else 0
    except (OSError, RuntimeError, ValueError) as exc:
        print("detector error: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
