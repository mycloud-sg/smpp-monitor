#!/usr/bin/env python3
"""Export one incident to a directory readable by the web backend.

Writes <id>.tar.gz first and <id>.json last, both via rename, so a reader that
lists *.json never sees a half-written incident. Copies instead of symlinking:
PHP open_basedir resolves symlinks and rejects targets outside the web root.
"""
import collections
import datetime as dt
import grp
import json
import os
import re
import shutil
import sys

INCIDENT_ID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-[A-Za-z0-9_.-]+$")
FILE_MODE = 0o640
DIR_MODE = 0o750


def format_time(timestamp):
    if timestamp is None:
        return ""
    return dt.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def event_times(events):
    times = []
    for item in events:
        if "time" in item:
            times.append(item["time"])
        if "end_time" in item:
            times.append(item["end_time"])
    return times


def build_summary(incident_id, details, diagnosis, archive_name, archive_size):
    events = details.get("events", [])
    times = event_times(events)
    start = details.get("start", min(times) if times else None)
    end = details.get("end", max(times) if times else None)
    layers = sorted({item.get("layer", "") for item in events} - {""})
    counts = collections.Counter(item.get("type", "UNKNOWN") for item in events)
    return {
        "id": incident_id,
        "supplier": details.get("supplier", ""),
        "target": details.get("target", ""),
        "layer": details.get("layer", "/".join(layers)),
        "start": format_time(start),
        "end": format_time(end),
        "summary": details.get("descriptions", []),
        "location": details.get("location", ""),
        "event_count": len(events),
        "event_types": dict(counts),
        "diagnosis": diagnosis,
        "archive": archive_name,
        "archive_size": archive_size,
        "exported_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def apply_owner(path, gid, mode):
    os.chmod(path, mode)
    if gid is None:
        return
    try:
        os.chown(path, -1, gid)
    except OSError as error:
        print("chgrp {} failed: {}".format(path, error), file=sys.stderr)


def lookup_gid(group):
    if not group:
        return None
    try:
        return grp.getgrnam(group).gr_gid
    except KeyError:
        # Without the group the web user cannot read 0640 files; fail loudly.
        raise ValueError("export group not found: {}".format(group))


def export(export_dir, incident_id, details_path, diagnosis_path, archive_path, group):
    if not INCIDENT_ID_RE.match(incident_id):
        raise ValueError("invalid incident id: {}".format(incident_id))
    gid = lookup_gid(group)
    if not os.path.isdir(export_dir):
        os.makedirs(export_dir)
        apply_owner(export_dir, gid, DIR_MODE)

    with open(details_path, "r") as file_obj:
        details = json.load(file_obj)
    with open(diagnosis_path, "r") as file_obj:
        diagnosis = file_obj.read()

    archive_name = incident_id + ".tar.gz"
    archive_target = os.path.join(export_dir, archive_name)
    archive_tmp = os.path.join(export_dir, "." + archive_name + ".tmp")
    shutil.copyfile(archive_path, archive_tmp)
    apply_owner(archive_tmp, gid, FILE_MODE)
    os.replace(archive_tmp, archive_target)

    summary = build_summary(incident_id, details, diagnosis, archive_name,
                            os.path.getsize(archive_target))
    summary_target = os.path.join(export_dir, incident_id + ".json")
    summary_tmp = os.path.join(export_dir, "." + incident_id + ".json.tmp")
    with open(summary_tmp, "w") as file_obj:
        json.dump(summary, file_obj, ensure_ascii=False, indent=2)
    apply_owner(summary_tmp, gid, FILE_MODE)
    os.replace(summary_tmp, summary_target)
    return summary_target


def main(argv):
    if len(argv) != 6:
        print("Usage: {} export_dir incident_id details.json diagnosis.txt archive.tar.gz"
              .format(argv[0]), file=sys.stderr)
        return 1
    group = os.environ.get("EXPORT_GROUP", "www")
    target = export(argv[1], argv[2], argv[3], argv[4], argv[5], group)
    print("incident exported: {}".format(target))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
