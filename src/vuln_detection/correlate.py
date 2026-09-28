MATCH_RULE = "path-line-cwe-v1"


def correlate(findings):
    groups = {}

    for finding in findings:
        location = finding.get("location", {})
        path = location.get("path")
        line = location.get("start_line")
        scanner = finding.get("scanner")
        cwe_ids = finding.get("cwe_ids", [])

        if not path or line is None or not scanner:
            continue

        for cwe_id in sorted(set(cwe_ids)):
            key = (path, line, cwe_id)
            groups.setdefault(key, []).append(finding)

    candidates = []

    for key, members in groups.items():
        path, line, cwe_id = key
        scanners = {member["scanner"] for member in members}

        if len(scanners) < 2:
            continue

        members = sorted(
            members,
            key=lambda member: (
                member["scanner"],
                member["finding_id"],
            ),
        )

        candidates.append({
            "match_rule": MATCH_RULE,
            "location": {
                "path": path,
                "start_line": line,
            },
            "shared_cwe": cwe_id,
            "member_ids": [
                member["finding_id"]
                for member in members
            ],
            "members": members,
        })

    return sorted(
        candidates,
        key=lambda candidate: (
            candidate["location"]["path"],
            candidate["location"]["start_line"],
            candidate["shared_cwe"],
        ),
    )