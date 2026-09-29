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