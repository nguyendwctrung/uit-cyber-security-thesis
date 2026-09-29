import json
from pathlib import Path

from vuln_detection.ollama import request_chat
from vuln_detection.prompt import render_prompt
from vuln_detection.verdict import get_candidate_id, validate_verdict
from vuln_detection.token_budget import count_request_tokens, ensure_within_input_budget


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("x", encoding="utf-8") as file:
        json.dump(value, file, ensure_ascii=False, sort_keys=True)


def write_text(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("x", encoding="utf-8") as file:
        file.write(value)


def append_jsonl(path, value):
    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(value, ensure_ascii=False, sort_keys=True))
        file.write("\n")


def get_artifact_paths(contexts, request_dir, response_dir):
    paths = []

    for context in contexts:
        candidate_id = get_candidate_id(context["candidate"])
        paths.append(
            (
                candidate_id,
                request_dir / (candidate_id + ".json"),
                response_dir / (candidate_id + ".json"),
            )
        )

    return paths


def prepare_outputs(
    contexts,
    verdict_path,
    error_path,
    request_dir,
    response_dir,
):
    outputs = [verdict_path, error_path]
    artifact_paths = get_artifact_paths(
        contexts,
        request_dir,
        response_dir,
    )

    seen_candidate_ids = set()

    for candidate_id, request_path, response_path in artifact_paths:
        if candidate_id in seen_candidate_ids:
            raise ValueError("Duplicate candidate_id in input contexts.")

        seen_candidate_ids.add(candidate_id)
        outputs.extend([request_path, response_path])

    for path in outputs:
        if path.exists():
            raise ValueError("Output already exists: " + str(path))

    verdict_path.parent.mkdir(parents=True, exist_ok=True)
    error_path.parent.mkdir(parents=True, exist_ok=True)
    request_dir.mkdir(parents=True, exist_ok=True)
    response_dir.mkdir(parents=True, exist_ok=True)

    verdict_path.touch(exist_ok=False)
    error_path.touch(exist_ok=False)


def make_error(context, candidate_id, error_type, error):
    return {
        "candidate": context["candidate"],
        "candidate_id": candidate_id,
        "error_type": error_type,
        "message": str(error),
        "source_path": context["source_path"],
        "source_revision": context["source_revision"],
    }


def run_contexts(
    contexts,
    prompt_path,
    schema_path,
    verdict_path,
    error_path,
    request_dir,
    response_dir,
    client,
    options,
    timeout,
    tokenizer,
    max_input_tokens,
):
    contexts = list(contexts)
    prepare_outputs(
        contexts,
        verdict_path,
        error_path,
        request_dir,
        response_dir,
    )

    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))

    for context in contexts:
        candidate = context["candidate"]
        candidate_id = get_candidate_id(candidate)
        request_path = request_dir / (candidate_id + ".json")
        response_path = response_dir / (candidate_id + ".json")
        prompt = render_prompt(context, prompt_path)

        try:
            token_count = count_request_tokens(
                tokenizer,
                "",
                prompt,
            )
            ensure_within_input_budget(
                token_count,
                max_input_tokens,
            )
        except ValueError as error:
            append_jsonl(
                error_path,
                make_error(
                    context,
                    candidate_id,
                    "context_window_exceeded",
                    error,
                ),
            )
            continue
        except Exception as error:
            append_jsonl(
                error_path,
                make_error(
                    context,
                    candidate_id,
                    "tokenizer_error",
                    error,
                ),
            )
            continue

        def save_request(payload):
            write_json(request_path, payload)

        try:
            result = request_chat(
                client,
                "",
                prompt,
                schema,
                options,
                timeout,
                on_request=save_request,
            )
        except TimeoutError as error:
            append_jsonl(
                error_path,
                make_error(
                    context,
                    candidate_id,
                    "llm_timeout",
                    error,
                ),
            )
            continue
        except ConnectionError as error:
            append_jsonl(
                error_path,
                make_error(
                    context,
                    candidate_id,
                    "ollama_unavailable",
                    error,
                ),
            )
            continue

        write_text(response_path, result["response_text"])

        if result["status_code"] != 200:
            append_jsonl(
                error_path,
                make_error(
                    context,
                    candidate_id,
                    "http_error",
                    "HTTP status " + str(result["status_code"]),
                ),
            )
            continue

        try:
            response = json.loads(result["response_text"])
            content = response["message"]["content"]
            verdict = json.loads(content)
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            append_jsonl(
                error_path,
                make_error(
                    context,
                    candidate_id,
                    "invalid_json",
                    error,
                ),
            )
            continue

        try:
            validate_verdict(
                verdict,
                candidate_id,
                context["method"],
                schema_path,
            )
        except ValueError as error:
            append_jsonl(
                error_path,
                make_error(
                    context,
                    candidate_id,
                    "schema_invalid",
                    error,
                ),
            )
            continue

        append_jsonl(
            verdict_path,
            {
                "candidate": candidate,
                "candidate_id": candidate_id,
                "source_path": context["source_path"],
                "source_revision": context["source_revision"],
                "method": context["method"],
                "verdict": verdict,
            },
        )