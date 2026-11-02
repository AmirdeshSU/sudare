#!/usr/bin/env python3
"""Rebuild crates/sudare-core/data/attack-enterprise.tsv from MITRE's STIX bundle.

    curl -LO https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
    python3 scripts/update_attack_index.py enterprise-attack.json

Output columns: id, name, revoked_by (successor id or empty), deprecated (0/1).
Stdlib only. Run by maintainers when MITRE publishes a release, never at runtime.
"""

import json
import pathlib
import sys


def main(path: str) -> None:
    with open(path, encoding="utf-8") as f:
        objects = json.load(f)["objects"]

    version = "?"
    stix_to_id = {}
    rows = {}
    for o in objects:
        if o.get("type") == "x-mitre-collection":
            version = o.get("x_mitre_version", version)
        if o.get("type") != "attack-pattern":
            continue
        tid = next(
            (r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not tid:
            continue
        stix_to_id[o["id"]] = tid
        row = {
            "name": " ".join(o.get("name", "").split()),
            "revoked": bool(o.get("revoked")),
            "deprecated": bool(o.get("x_mitre_deprecated")),
            "revoked_by": "",
        }
        # Keep the live object if an ID appears twice.
        if tid not in rows or rows[tid]["revoked"]:
            rows[tid] = row

    for o in objects:
        if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by":
            src, dst = stix_to_id.get(o["source_ref"]), stix_to_id.get(o["target_ref"])
            if src and dst and rows[src]["revoked"]:
                rows[src]["revoked_by"] = dst

    out = pathlib.Path(__file__).resolve().parent.parent / "crates/sudare-core/data/attack-enterprise.tsv"
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"# MITRE ATT&CK Enterprise v{version}. (c) The MITRE Corporation. See NOTICE.\n")
        for tid in sorted(rows):
            r = rows[tid]
            name = r["name"]
            parent = rows.get(tid.split(".")[0])
            if "." in tid and parent:
                name = f"{parent['name']}: {name}"
            f.write(f"{tid}\t{name}\t{r['revoked_by']}\t{int(r['deprecated'])}\n")
    print(f"wrote {len(rows)} techniques (ATT&CK v{version}) to {out}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
