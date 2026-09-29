import pytest

from vuln_detection.ollama import get_model_info, request_chat


OPTIONS = {
    "temperature": 0.0,
    "seed": 42,
    "top_p": 1.0,
    "top_k": 40,
    "min_p": 0.0,
    "repeat_penalty": 1.0,
    "num_ctx": 8192,
    "num_predict": 512,
}


class FakeResponse:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


class FakeClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def post(self, url, json, timeout):
        self.calls.append(
            {
                "url": url,
                "json": json,
                "timeout": timeout,
            }
        )
        return self.response


def test_request_uses_environment_configuration(monkeypatch):
    monkeypatch.setenv(
        "OLLAMA_URL",
        "http://example.test:11434/api/chat",
    )
    monkeypatch.setenv("OLLAMA_MODEL", "test-model")
    client = FakeClient(
        FakeResponse(
            200,
            '{"message":{"content":"{}"}}',
        )
    )
    schema = {
        "type": "object",
        "required": ["verdict"],
    }

    result = request_chat(
        client,
        "System instruction.",
        "User candidate context.",
        schema,
        OPTIONS,
        120,
    )

    assert len(client.calls) == 1
    call = client.calls[0]
    assert call["url"] == "http://example.test:11434/api/chat"
    assert call["timeout"] == 120
    assert call["json"]["model"] == "test-model"
    assert call["json"]["stream"] is False
    assert call["json"]["format"] == schema
    assert call["json"]["options"] == OPTIONS
    assert call["json"]["messages"] == [
        {
            "role": "system",
            "content": "System instruction.",
        },
        {
            "role": "user",
            "content": "User candidate context.",
        },
    ]
    assert "rag" not in call["json"]
    assert "documents" not in call["json"]
    assert "retrieval" not in call["json"]
    assert result["status_code"] == 200
    assert result["response_text"] == '{"message":{"content":"{}"}}'


def test_request_preserves_non_success_raw_response(monkeypatch):
    monkeypatch.setenv(
        "OLLAMA_URL",
        "http://127.0.0.1:11434/api/chat",
    )
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
    client = FakeClient(FakeResponse(500, "Ollama internal error"))

    result = request_chat(
        client,
        "System instruction.",
        "User candidate context.",
        {},
        OPTIONS,
        120,
    )

    assert result["status_code"] == 500
    assert result["response_text"] == "Ollama internal error"


def test_request_reports_payload_before_http_call(monkeypatch):
    monkeypatch.setenv(
        "OLLAMA_URL",
        "http://127.0.0.1:11434/api/chat",
    )
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
    events = []

    class OrderedClient:
        def post(self, url, json, timeout):
            assert events == ["request"]
            return FakeResponse(200, '{"message":{"content":"{}"}}')

    def save_request(payload):
        assert payload["model"] == "qwen2.5-coder:7b"
        events.append("request")

    request_chat(
        OrderedClient(),
        "System instruction.",
        "User candidate context.",
        {},
        OPTIONS,
        120,
        on_request=save_request,
    )

    assert events == ["request"]


def test_reads_the_configured_model_metadata(monkeypatch):
    monkeypatch.setenv(
        "OLLAMA_URL",
        "http://127.0.0.1:11434/api/chat",
    )
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5-coder:7b")

    class MetadataResponse:
        def __init__(self, status_code, payload):
            self.status_code = status_code
            self.payload = payload

        def json(self):
            return self.payload

    class MetadataClient:
        def __init__(self):
            self.calls = []

        def get(self, url, timeout):
            self.calls.append(
                {
                    "url": url,
                    "timeout": timeout,
                }
            )

            if url.endswith("/api/version"):
                return MetadataResponse(
                    200,
                    {
                        "version": "0.34.4",
                    },
                )

            return MetadataResponse(
                200,
                {
                    "models": [
                        {
                            "name": "qwen2.5-coder:7b",
                            "digest": "test-digest",
                        }
                    ]
                },
            )

    client = MetadataClient()

    info = get_model_info(client, 120)

    assert info == {
        "tag": "qwen2.5-coder:7b",
        "digest": "test-digest",
        "ollama_version": "0.34.4",
    }
    assert client.calls == [
        {
            "url": "http://127.0.0.1:11434/api/version",
            "timeout": 120,
        },
        {
            "url": "http://127.0.0.1:11434/api/tags",
            "timeout": 120,
        },
    ]


def test_rejects_a_missing_configured_model(monkeypatch):
    monkeypatch.setenv(
        "OLLAMA_URL",
        "http://127.0.0.1:11434/api/chat",
    )
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5-coder:7b")

    class MetadataResponse:
        status_code = 200

        def json(self):
            return {
                "models": [],
            }

    class MetadataClient:
        def get(self, url, timeout):
            if url.endswith("/api/version"):
                return type(
                    "VersionResponse",
                    (),
                    {
                        "status_code": 200,
                        "json": lambda self: {
                            "version": "0.34.4",
                        },
                    },
                )()

            return MetadataResponse()

    with pytest.raises(ValueError, match="Configured Ollama model"):
        get_model_info(MetadataClient(), 120)