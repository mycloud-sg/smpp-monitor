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
INCIDENT_SCRIPT = os.path.join(BASE_DIR, "smpp_incident.sh")

RETRANSMISSION_THRESHOLD = int(os.environ.get("TCP_RETRANSMISSION_THRESHOLD", "10"))
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
        "-Y", "tcp.flags.reset == 1 || tcp.flags.fin == 1 || "
              "tcp.analysis.retransmission || tcp.analysis.zero_window || smpp",
        "-T", "fields", "-E", "separator=\\t", "-E", "occurrence=f",
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


def analyze(lines, suppliers):
    submits = {}
    results = {name: {"events": [], "retransmissions": []} for name in suppliers}

    for line in lines:
        row = line.split("\t")
        row += [""] * (13 - len(row))
        try:
            timestamp = float(row[0])
        except ValueError:
            continue

        supplier, direction = supplier_for_packet(row, suppliers)
        if not supplier:
            continue

        stream = row[5]
        reset = is_true(row[6])
        fin = is_true(row[7])
        retransmission = is_true(row[8])
        zero_window = is_true(row[9])
        command_id = normalize_number(row[10])
        sequence = row[11].strip()
        command_status = normalize_number(row[12])
        bucket = results[supplier]

        if reset:
            source = "supplier" if direction == "supplier_to_local" else "local"
            bucket["events"].append(event("TCP_RESET", "TCP", timestamp, source=source))
        if fin and ALERT_ON_FIN:
            source = "supplier" if direction == "supplier_to_local" else "local"
            bucket["events"].append(event("TCP_CLOSED", "TCP", timestamp, source=source))
        if retransmission:
            bucket["retransmissions"].append(timestamp)
        if zero_window:
            source = "supplier" if direction == "supplier_to_local" else "local"
            bucket["events"].append(event("TCP_RECEIVE_BLOCKED", "TCP", timestamp, source=source))

        if command_id is None or not sequence:
            continue

        key = (supplier, stream, sequence)
        if command_id == SUBMIT_SM:
            submits[key] = timestamp
        elif command_id == SUBMIT_SM_RESP:
            submit_time = submits.get(key)
            if submit_time is None:
                continue
            delay = timestamp - submit_time
            timeout = suppliers[supplier]["timeout"]
            if delay >= timeout:
                bucket["events"].append(
                    event("SMPP_RESP_TIMEOUT", "SMPP", timestamp,
                          sequence=sequence, delay=round(delay, 3), timeout=timeout)
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

    for bucket in results.values():
        times = bucket.pop("retransmissions")
        if len(times) >= RETRANSMISSION_THRESHOLD:
            bucket["events"].append(
                event("TCP_RETRANSMISSION", "TCP", min(times),
                      end_time=max(times), count=len(times))
            )
    return {name: value["events"] for name, value in results.items() if value["events"]}


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
            descriptions.append("与供应商的连接被供应商一侧强制断开。")
        else:
            descriptions.append("与供应商的连接被本机一侧强制断开。")
    if "TCP_CLOSED" in types:
        supplier_close = any(item["type"] == "TCP_CLOSED" and item.get("source") == "supplier"
                             for item in events)
        if supplier_close:
            descriptions.append("供应商一侧关闭了网络连接。")
        else:
            descriptions.append("本机一侧关闭了网络连接。")
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
        supplier_side = any(item.get("source") == "supplier" for item in events
                            if item["type"] in {"TCP_RESET", "TCP_CLOSED"})
        location = "优先排查供应商侧。" if supplier_side else "优先排查本机应用或本机网络。"
    elif has_tcp:
        location = "疑似本机与供应商之间的网络链路问题。"
    elif "SMPP_SUBMIT_FAILED" in types or "SMPP_BIND_FAILED" in types:
        location = "供应商 SMPP 服务返回了明确失败结果。"
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
        findings = analyze(run_tshark(pcap, suppliers), suppliers)
        if only_supplier is not None:
            if only_supplier not in suppliers:
                raise RuntimeError("supplier config not found: {}".format(only_supplier))
            findings = ({only_supplier: findings[only_supplier]}
                        if only_supplier in findings else {})
        for supplier, events in findings.items():
            handle_diagnosis(supplier, suppliers[supplier], events, pcap)
        return 2 if findings else 0
    except (OSError, RuntimeError, ValueError) as exc:
        print("detector error: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
