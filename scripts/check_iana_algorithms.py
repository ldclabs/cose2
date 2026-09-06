#!/usr/bin/env python3
"""Fail when an assigned numeric COSE algorithm is absent from iana.rs."""

from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: check_iana_algorithms.py <cose.xml> <iana.rs>", file=sys.stderr)
        return 2

    namespace = {"iana": "http://www.iana.org/assignments"}
    root = ET.parse(sys.argv[1]).getroot()
    registry = root.find(".//iana:registry[@id='algorithms']", namespace)
    if registry is None:
        print("COSE Algorithms registry not found", file=sys.stderr)
        return 2

    assigned: dict[int, str] = {}
    for record in registry.findall("iana:record", namespace):
        value = (record.findtext("iana:value", namespaces=namespace) or "").strip()
        name = (record.findtext("iana:name", namespaces=namespace) or "").strip()
        try:
            number = int(value)
        except ValueError:
            continue
        if name not in {"Unassigned", "Reserved", "Reserved for Private Use"}:
            assigned[number] = name

    source = Path(sys.argv[2]).read_text(encoding="utf-8")
    constants = re.findall(r"pub const (Algorithm\w+): i64 = (-?\d+);", source)
    if ("AlgorithmReserved", "0") not in constants:
        print("missing AlgorithmReserved = 0 constant", file=sys.stderr)
        return 1
    present = {int(value) for _, value in constants}
    if len(present) != len(constants):
        print("duplicate numeric COSE algorithm constants found", file=sys.stderr)
        return 1
    missing = sorted((number, assigned[number]) for number in assigned.keys() - present)
    if missing:
        for number, name in missing:
            print(f"missing IANA COSE algorithm {number}: {name}", file=sys.stderr)
        return 1
    unexpected = sorted(present - assigned.keys() - {0})
    if unexpected:
        for number in unexpected:
            print(f"stale or unassigned COSE algorithm constant {number}", file=sys.stderr)
        return 1
    print(f"all {len(assigned)} assigned numeric COSE algorithms are represented")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
