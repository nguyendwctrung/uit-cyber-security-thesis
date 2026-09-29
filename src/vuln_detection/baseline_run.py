import hashlib
import json
import subprocess

from pathlib import Path

from vuln_detection.baseline_config import get_config_sha256, load_baseline_config
from vuln_detection.llm_run import run_contexts
from vuln_detection.ollama import get_runtime_config
from vuln_detection.tokenizer_loader import get_tokenizer_provenance, load_tokenizer


def read_rows(path):
    rows = []

    with path.open(encoding="utf-8") as file:
        for line in file:
            if line.strip():
                rows.append(json.loads(line))

    return rows


def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def get_git_head(root):
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        check=False,
        text=True,
    )

    if result.returncode != 0:
        return None

    return result.stdout.strip()


def get_implementation_provenance(root):
    root = Path(root)
    source_root = root / "src"
    source_files = []

    for path in sorted(source_root.rglob("*.py")):
        source_files.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": sha256_file(path),
            }
        )

    tree_hash = hashlib.sha256()

    for item in source_files:
        tree_hash.update(item["path"].encode("utf-8"))
        tree_hash.update(b"\0")
        tree_hash.update(item["sha256"].encode("utf-8"))
        tree_hash.update(b"\n")

    return {
        "git_head": get_git_head(root),
        "requirements_sha256": sha256_file(
            root / "requirements.txt"
        ),
        "source_tree_sha256": tree_hash.hexdigest(),
        "source_files": source_files,
    }


def get_raw_artifacts(directory):
    artifacts = []

    for path in sorted(directory.glob("*.json")):
        artifacts.append(
            {
                "path": str(path),
                "sha256": sha256_file(path),
            }
        )

    return artifacts


def write_manifest(path, manifest):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("x", encoding="utf-8") as file:
        json.dump(
            manifest,
            file,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        file.write("\n")


def validate_model_info(config, model_info):
    if model_info["digest"] != config["model"]["digest"]:
        raise ValueError(
            "Model digest does not match baseline config."
        )

    if model_info["tag"] != config["model"]["tag"]:
        raise ValueError(
            "Model tag does not match baseline config."
        )


def run_baseline(
    context_path,
    config_path,
    run_dir,
    client,
    model_info,
    root,
):
    context_path = Path(context_path)
    config_path = Path(config_path)
    run_dir = Path(run_dir)
    root = Path(root)

    if run_dir.exists():
        raise ValueError("Output already exists: " + str(run_dir))

    config = load_baseline_config(config_path, root)
    validate_model_info(config, model_info)
    implementation = get_implementation_provenance(root)

    contexts = read_rows(context_path)
    prompt_path = root / config["prompt"]["path"]
    schema_path = root / config["schema"]["path"]
    asset_dir = root / config["tokenizer"]["asset_dir"]
    tokenizer = load_tokenizer(asset_dir)
    tokenizer_provenance = get_tokenizer_provenance(
        config["tokenizer"],
        asset_dir,
    )
    url, model = get_runtime_config()

    verdict_path = run_dir / "derived" / "verdicts.jsonl"
    error_path = run_dir / "errors" / "llm-errors.jsonl"
    request_dir = run_dir / "raw" / "requests"
    response_dir = run_dir / "raw" / "responses"

    run_contexts(
        contexts,
        prompt_path,
        schema_path,
        verdict_path,
        error_path,
        request_dir,
        response_dir,
        client,
        config["request"]["options"],
        config["request"]["timeout_seconds"],
        tokenizer,
        config["token_budget"]["max_input_tokens"],
    )

    verdicts = read_rows(verdict_path)
    errors = read_rows(error_path)

    manifest_path = run_dir / "manifest.json"
    manifest = {
        "baseline_config_id": config["baseline_config_id"],
        "rag_enabled": config["rag_enabled"],
        "config": {
            "path": str(config_path),
            "sha256": get_config_sha256(config_path),
        },
        "input": {
            "path": str(context_path),
            "sha256": sha256_file(context_path),
            "row_count": len(contexts),
        },
        "prompt": config["prompt"],
        "schema": config["schema"],
        "model": model_info,
        "implementation": implementation,
        "tokenizer": tokenizer_provenance,
        "runtime": {
            "url": url,
            "model": model,
            "timeout_seconds": config["request"]["timeout_seconds"],
            "max_attempts": config["request"]["max_attempts"],
            "parallelism": config["request"]["parallelism"],
        },
        "options": config["request"]["options"],
        "token_budget": config["token_budget"],
        "counts": {
            "contexts": len(contexts),
            "verdicts": len(verdicts),
            "errors": len(errors),
        },
        "artifacts": {
            "verdicts": {
                "path": str(verdict_path),
                "sha256": sha256_file(verdict_path),
            },
            "errors": {
                "path": str(error_path),
                "sha256": sha256_file(error_path),
            },
            "raw_requests": get_raw_artifacts(request_dir),
            "raw_responses": get_raw_artifacts(response_dir),
        },
    }

    write_manifest(manifest_path, manifest)

    return {
        "manifest_path": manifest_path,
        "verdict_path": verdict_path,
        "error_path": error_path,
    }