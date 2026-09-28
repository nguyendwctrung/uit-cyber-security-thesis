
SCHEMA_VERSION = "finding-v1"
PARSER_VERSION = "0.1"

def new_finding():
    return {
        "schema_version": SCHEMA_VERSION,
        "finding_id": None,
        "run_id": None,
        "scanner": None,
        "scanner_finding_id": None,
        "rule_id": None,
        "rule_name": None,
        "severity_raw": None,
        "cwe_ids": [],
        "message": None,
        "location": {
            "path": None,
            "start_line": None,
            "start_column": None,
            "end_line": None,
            "end_column": None,
        },
        "code_flow": [],
        "provenance": {
            "source_revision": None,
            "raw_artifact": None,
            "raw_artifact_sha256": None,
            "raw_pointer": None,
            "raw_path": None,
            "parser_version": PARSER_VERSION,
        },
    }

def new_error():
    return {
        "schema_version": SCHEMA_VERSION,
        "scanner": None,
        "raw_artifact": None,
        "raw_pointer": None,
        "error_type": None,
        "message": None,
    }
