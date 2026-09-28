import hashlib
import json

from vuln_detection.finding import new_finding, new_error

def make_id(scanner, rule_id, path, line, column, source_revision):
    text = "|".join([
        scanner,
        rule_id,
        path,
        str(line),
        str(column),
        source_revision
    ])
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def get_text(value):
    if isinstance(value, dict):
        return value.get("text")

    if isinstance(value, str):
        return value

    return None

def clean_path(path, source_root):
    path = path.replace("\\", "/")
    source_root = source_root.replace("\\", "/").rstrip("/")

    if source_root and path.startswith(source_root + "/"):
        return path[len(source_root) + 1:]

    return path

def make_rules(run):
    rules = {}

    for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
        rule_id = rule.get("id")

        if rule_id:
            rules[rule_id] = rule

    return rules

def get_cwes(rule):
    cwes = []

    for tag in rule.get("properties", {}).get("tags", []):
        tag = tag.lower()

        if not tag.startswith("external/cwe/cwe-"):
            continue

        value = tag.split("external/cwe/cwe-")[1]

        if value.isdigit():
            cwes.append("CWE-" + str(int(value)))

    return cwes

def get_flow(result, source_root):
    flows = []

    for code_flow in result.get("codeFlows", []):
        for thread_flow in code_flow.get("threadFlows", []):
            steps = []

            for item in thread_flow.get("locations", []):
                location = item.get("location", {})
                physical = location.get("physicalLocation", {})
                artifact = physical.get("artifactLocation", {})
                region = physical.get("region", {})
                uri = artifact.get("uri")

                if not uri:
                    continue

                steps.append({
                    "path": clean_path(uri, source_root),
                    "line": region.get("startLine"),
                    "column": region.get("startColumn"),
                    "message": get_text(location.get("message"))
                })

            if steps:
                flows.append(steps)

    return flows

def make_error(raw_artifact, pointer, error_type, message):
    error = new_error()
    error["scanner"] = "codeql"
    error["raw_artifact"] = raw_artifact
    error["raw_pointer"] = pointer
    error["error_type"] = error_type
    error["message"] = message
    return error

def parse_result(item, run_index, result_index, rules, run_id, raw_artifact, raw_hash, source_revision, source_root):
    pointer = "runs[" + str(run_index) + "].results[" + str(result_index) + "]"

    if not isinstance(item, dict):
        return None, make_error(raw_artifact, pointer, "invalid_result", "SARIF result is not an object.")

    rule_id = item.get("ruleId")
    if not rule_id:
        return None, make_error(raw_artifact, pointer, "missing_rule_id", "SARIF result has no ruleId.")

    locations = item.get("locations", [])
    if not isinstance(locations, list) or not locations:
        return None, make_error(raw_artifact, pointer, "missing_location", "SARIF result has no location.")

    physical = locations[0].get("physicalLocation", {})
    artifact = physical.get("artifactLocation", {})
    region = physical.get("region", {})
    raw_path = artifact.get("uri")

    if not raw_path:
        return None, make_error(raw_artifact, pointer, "missing_path", "SARIF result location has no artifact URI.")

    if not region.get("startLine"):
        return None, make_error(raw_artifact, pointer, "missing_location", "SARIF result has no start line.")

    rule = rules.get(rule_id, {})
    default = rule.get("defaultConfiguration", {})
    fingerprints = item.get("partialFingerprints", {})

    path = clean_path(raw_path, source_root)

    finding = new_finding()
    finding["finding_id"] = make_id(
        "codeql",
        rule_id,
        path,
        region.get("startLine"),
        region.get("startColumn"),
        source_revision
    )
    finding["run_id"] = run_id
    finding["scanner"] = "codeql"
    finding["scanner_finding_id"] = fingerprints.get("primaryLocationLineHash")
    finding["rule_id"] = rule_id
    finding["rule_name"] = get_text(rule.get("shortDescription")) or rule_id
    finding["severity_raw"] = item.get("level") or default.get("level")
    finding["cwe_ids"] = get_cwes(rule)
    finding["message"] = get_text(item.get("message"))

    finding["location"]["path"] = path
    finding["location"]["start_line"] = region.get("startLine")
    finding["location"]["start_column"] = region.get("startColumn")
    finding["location"]["end_line"] = region.get("endLine")
    finding["location"]["end_column"] = region.get("endColumn")

    finding["code_flow"] = get_flow(item, source_root)

    finding["provenance"]["source_revision"] = source_revision
    finding["provenance"]["raw_artifact"] = raw_artifact
    finding["provenance"]["raw_artifact_sha256"] = raw_hash
    finding["provenance"]["raw_pointer"] = pointer
    finding["provenance"]["raw_path"] = raw_path

    return finding, None

def parse_file(path, run_id, raw_artifact, raw_hash, source_revision, source_root):
    with open(path, encoding="utf-8") as file:
        data = json.load(file)

    runs = data.get("runs", [])

    if not isinstance(runs, list):
        error = make_error(raw_artifact, "runs", "invalid_runs", "SARIF runs field is not a list.")
        return [], [error]

    findings = []
    errors = []

    for run_index, run in enumerate(runs):
        rules = make_rules(run)
        results = run.get("results", [])
        if not isinstance(results, list):
            errors.append(make_error(raw_artifact, "runs[" + str(run_index) + "].results", "invalid_results", "SARIF results field is not a list."))
            continue

        for result_index, item in enumerate(results):
            finding, error = parse_result(
                item,
                run_index,
                result_index,
                rules,
                run_id,
                raw_artifact,
                raw_hash,
                source_revision,
                source_root
            )

            if finding is not None:
                findings.append(finding)

            if error is not None:
                errors.append(error)

    return findings, errors
