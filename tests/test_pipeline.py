import json
from pathlib import Path

from threat_hunting_pipeline import (
    Evidence,
    enrich_indicators,
    generate_markdown_report,
    match_attack_techniques,
    normalize_evidence,
)


def test_normalize_evidence_extracts_indicators() -> None:
    text = """
    Host contacted 203.0.113.44 and login.example.com via https://login.example.com/login.
    Powershell.exe ran with hash 8F3A1B2C4D5E6F7890ABCDEF12345678.
    Timestamp: 2026-10-14T09:34:00Z
    """

    evidence = normalize_evidence(text)

    assert "203.0.113.44" in evidence.ips
    assert "login.example.com" in evidence.domains
    assert "https://login.example.com/login" in evidence.urls
    assert "8f3a1b2c4d5e6f7890abcdef12345678" in [h.lower() for h in evidence.hashes]
    assert "powershell" in [p.lower() for p in evidence.processes]
    assert "2026-10-14T09:34:00Z" in evidence.timestamps


def test_match_attack_techniques_handles_common_keywords() -> None:
    text = "Phishing email led to powershell execution and exfiltration to cloud storage."

    techniques = match_attack_techniques(text)

    assert "Initial Access" in techniques
    assert "Execution" in techniques
    assert "Exfiltration" in techniques


def test_normalize_evidence_excludes_js_noise_domains() -> None:
    text = "A JavaScript snippet used window.location.href and a.length, but the real domain was login.example.com."

    evidence = normalize_evidence(text)

    assert "login.example.com" in evidence.domains
    assert "a.length" not in evidence.domains
    assert "window.location.href" not in evidence.domains


def test_enrich_indicators_returns_status_and_results(monkeypatch) -> None:
    calls = {}

    def fake_fetch_json(url: str, headers: dict[str, str] | None = None, timeout: int = 20):
        calls["url"] = url
        calls["headers"] = headers
        return {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 5},
                    "reputation": -2,
                }
            }
        }

    monkeypatch.setenv("VT_API_KEY", "demo-key")
    monkeypatch.setattr("threat_hunting_pipeline.fetch_json", fake_fetch_json)

    result = enrich_indicators(["203.0.113.44"], ["login.example.com"], ["8F3A1B2C4D5E6F7890ABCDEF12345678"])

    assert result["status"] == "success"
    assert "reports" in result["indicators"]["ips"][0]
    assert "login.example.com" in result["summary"]
    assert calls["url"].startswith("https://www.virustotal.com")


def test_generate_markdown_report_includes_blueprint_summary_when_no_indicators() -> None:
    text = """
    Goal
    Submit one threat research URL or upload one write-up; generate a source-grounded hunt plan.
    Outputs
    PDF report, Markdown report, IOC CSV/JSON, source metadata and evidence links.
    Design principle
    Every key claim, IOC, ATT&CK mapping and query should be traceable to evidence.
    """

    report = generate_markdown_report(
        "sample_blueprint.pdf",
        text,
        Evidence(ips=[], domains=[], urls=[], hashes=[], files=[], processes=[], timestamps=[]),
        [],
        {"status": "Skipped", "details": "Set VT_API_KEY to enable reputation enrichment."},
    )

    assert "## Executive Summary" in report
    assert "source-grounded hunt plan" in report
    assert "traceable to evidence" in report
