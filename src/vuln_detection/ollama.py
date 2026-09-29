import os

from dotenv import load_dotenv


def get_runtime_config():
    load_dotenv()

    url = os.getenv("OLLAMA_URL")
    model = os.getenv("OLLAMA_MODEL")

    if not url:
        raise ValueError("OLLAMA_URL is required.")

    if not model:
        raise ValueError("OLLAMA_MODEL is required.")

    return url, model


def get_api_base(url):
    suffix = "/api/chat"

    if not url.endswith(suffix):
        raise ValueError(
            "OLLAMA_URL must end with /api/chat."
        )

    return url[: -len(suffix)]


def get_json_response(response, name):
    if response.status_code != 200:
        raise ValueError(
            name
            + " request failed with HTTP status "
            + str(response.status_code)
            + "."
        )

    return response.json()


def get_model_info(client, timeout):
    url, model = get_runtime_config()
    api_base = get_api_base(url)

    version_response = client.get(
        api_base + "/api/version",
        timeout=timeout,
    )
    version_data = get_json_response(
        version_response,
        "Ollama version",
    )

    tags_response = client.get(
        api_base + "/api/tags",
        timeout=timeout,
    )
    tags_data = get_json_response(
        tags_response,
        "Ollama tags",
    )

    for item in tags_data["models"]:
        if item["name"] == model:
            return {
                "tag": model,
                "digest": item["digest"],
                "ollama_version": version_data["version"],
            }

    raise ValueError(
        "Configured Ollama model was not found: " + model
    )


def request_chat(
    client,
    system_prompt,
    user_prompt,
    schema,
    options,
    timeout,
    on_request=None,
):
    url, model = get_runtime_config()
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": system_prompt,
            },
            {
                "role": "user",
                "content": user_prompt,
            },
        ],
        "stream": False,
        "format": schema,
        "options": options,
    }

    if on_request:
        on_request(payload)

    response = client.post(
        url,
        json=payload,
        timeout=timeout,
    )

    return {
        "request": payload,
        "status_code": response.status_code,
        "response_text": response.text,
    }