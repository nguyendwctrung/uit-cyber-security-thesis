import hashlib
import json

from vuln_detection.finding import new_error, new_finding

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

def clean_path(path, source_root):
    path = path.replace("\\", "/")
    source_root = source_root.replace("\\", "/").rstrip("/")

    if source_root and path.startswith(source_root + "/"):
        return path[len(source_root) + 1:]
    
    return path

def get_cwes(metadata):
    cwes = []

    for item in metadata.get("cwe", []):
        if not isinstance(item, str):
            continue

        cwe = item.split(":")[0].strip()
        if cwe.startswith("CWE-"):
            cwes.append(cwe)

    return cwes

def get_name(metadata, rule_id):
    names = metadata.get("vulnerability_class", [])

    if isinstance(names, list) and names and isinstance(names[0], str):
        return names[0]

    return rule_id

def make_error(raw_artifact, pointer, error_type, message):
    error = new_error()
    error["scanner"] = "semgrep"
    error["raw_artifact"] = raw_artifact
    error["raw_pointer"] = pointer
    error["error_type"] = error_type
    error["message"] = message
    return error

def parse_result(item, index, run_id, raw_artifact, raw_hash, source_revision, source_root):
    pointer = "results[" + str(index) + "]"

    if not isinstance(item, dict):
        return None, make_error(raw_artifact, pointer, "invalid_result", "Semgrep result is not an object.")
    
    extra = item.get("extra", {})
    start = item.get("start", {})
    end = item.get("end", {})

    if not isinstance(extra, dict):
        return None, make_error(raw_artifact, pointer, "invalid_extra", "Semgrep result extra field is not an object.")

    if not isinstance(start, dict):
        start = {}

    if not isinstance(end, dict):
        end = {}

    if not item.get("check_id"):
        return None, make_error(raw_artifact, pointer, "missing_rule_id", "Semgrep result has no check_id.")

    if not item.get("path"):
        return None, make_error(raw_artifact, pointer, "missing_path", "Semgrep result has no path.")

    if not start.get("line"):
        return None, make_error(raw_artifact, pointer, "missing_location", "Semgrep result has no start line.")

    metadata = extra.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}

    raw_path = item["path"]
    path = clean_path(raw_path, source_root)
    rule_id = item["check_id"]

    finding = new_finding()
    finding["finding_id"] = make_id("semgrep", rule_id, path, start["line"], start.get("col"), source_revision)
    finding["run_id"] = run_id
    finding["scanner"] = "semgrep"
    finding["scanner_finding_id"] = extra.get("fingerprint")
    finding["rule_id"] = rule_id
    finding["rule_name"] = get_name(metadata, rule_id)
    finding["severity_raw"] = extra.get("severity")
    finding["cwe_ids"] = get_cwes(metadata)
    finding["message"] = extra.get("message")

    finding["location"]["path"] = path
    finding["location"]["start_line"] = start.get("line")
    finding["location"]["start_column"] = start.get("col")
    finding["location"]["end_line"] = end.get("line")
    finding["location"]["end_column"] = end.get("col")

    finding["provenance"]["source_revision"] = source_revision
    finding["provenance"]["raw_artifact"] = raw_artifact
    finding["provenance"]["raw_artifact_sha256"] = raw_hash
    finding["provenance"]["raw_pointer"] = pointer
    finding["provenance"]["raw_path"] = raw_path

    return finding, None

def parse_file(path, run_id, raw_artifact, raw_hash, source_revision, source_root):
    with open(path, encoding="utf-8") as file:
        data = json.load(file)

    results = data.get("results", [])
    if not isinstance(results, list):
        error = make_error(raw_artifact, "results", "invalid_results", "Semgrep results field is not a list.")
        return [], [error]

    findings = []
    errors = []

    for index, item in enumerate(results):
        finding, error = parse_result(item, index, run_id, raw_artifact, raw_hash, source_revision, source_root)

        if finding is not None:
            findings.append(finding)

        if error is not None:
            errors.append(error)

    return findings, errors
