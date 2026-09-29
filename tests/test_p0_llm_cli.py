from pathlib import Path

from vuln_detection import p0_llm_cli


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "configs" / "p0-llm-no-rag-v1.json"


def test_cli_preflights_model_then_starts_baseline_run(
    tmp_path,
    monkeypatch,
    capsys,
):
    context_path = tmp_path / "contexts.jsonl"
    context_path.write_text("", encoding="utf-8")
    run_dir = tmp_path / "P0-LLM-001-test"
    calls = []

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

    client = FakeClient()

    monkeypatch.setattr(
        p0_llm_cli.httpx,
        "Client",
        lambda: client,
    )
    monkeypatch.setattr(
        p0_llm_cli,
        "get_model_info",
        lambda supplied_client, timeout: {
            "tag": "qwen2.5-coder:7b",
            "digest": (
                "dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75"
                "ed87571486f4364"
            ),
            "ollama_version": "0.34.4",
        },
    )

    def fake_run_baseline(
        supplied_context_path,
        supplied_config_path,
        supplied_run_dir,
        supplied_client,
        model_info,
        supplied_root,
    ):
        calls.append(
            {
                "context_path": supplied_context_path,
                "config_path": supplied_config_path,
                "run_dir": supplied_run_dir,
                "client": supplied_client,
                "model_info": model_info,
                "root": supplied_root,
            }
        )
        return {
            "manifest_path": supplied_run_dir / "manifest.json",
            "verdict_path": supplied_run_dir / "verdicts.jsonl",
            "error_path": supplied_run_dir / "errors.jsonl",
        }

    monkeypatch.setattr(
        p0_llm_cli,
        "run_baseline",
        fake_run_baseline,
    )

    exit_code = p0_llm_cli.main(
        [
            "--input",
            str(context_path),
            "--config",
            str(CONFIG_PATH),
            "--run-dir",
            str(run_dir),
            "--root",
            str(ROOT),
        ]
    )

    assert exit_code == 0
    assert calls[0]["context_path"] == context_path
    assert calls[0]["config_path"] == CONFIG_PATH
    assert calls[0]["run_dir"] == run_dir
    assert calls[0]["client"] is client
    assert calls[0]["root"] == ROOT
    assert calls[0]["model_info"]["digest"] == (
        "dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75"
        "ed87571486f4364"
    )
    assert "Manifest:" in capsys.readouterr().out