import argparse
import json
from pathlib import Path

import httpx

from vuln_detection.baseline_config import load_baseline_config
from vuln_detection.baseline_run import run_baseline
from vuln_detection.ollama import get_model_info


def get_args(argv=None):
    parser = argparse.ArgumentParser()

    parser.add_argument("--input", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--root", default=".")

    return parser.parse_args(argv)


def main(argv=None):
    args = get_args(argv)
    context_path = Path(args.input)
    config_path = Path(args.config)
    run_dir = Path(args.run_dir)
    root = Path(args.root)

    try:
        config = load_baseline_config(config_path, root)

        with httpx.Client() as client:
            model_info = get_model_info(
                client,
                config["request"]["timeout_seconds"],
            )
            result = run_baseline(
                context_path,
                config_path,
                run_dir,
                client,
                model_info,
                root,
            )
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        httpx.HTTPError,
    ) as error:
        print("P0 LLM baseline failed: " + str(error))
        return 1

    print("Manifest:", result["manifest_path"])
    print("Verdicts:", result["verdict_path"])
    print("Errors:", result["error_path"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())