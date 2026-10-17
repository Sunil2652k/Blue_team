#!/usr/bin/env python3
"""Threat-hunting pipeline automation.

This script implements the staged workflow shown in the blueprint:
1. Input
2. Safe Extraction
3. Evidence Normalization
4. Optional Enrichment
5. Analysis Engine
6. Report Generation
7. Human Review
8. Git Publish

Example:
    python threat_hunting_pipeline.py https://example.com
    python threat_hunting_pipeline.py .\\sample_hunt_input.txt --output-dir .\\out
    python threat_hunting_pipeline.py .\\sample_hunt_input.txt --git-publish
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

try:
    from pypdf import PdfReader
except Exception:  # pragma: no cover - optional dependency
    PdfReader = None

PIPELINE_STEPS = [
    "Input",
    "Safe Extraction",
    "Evidence Normalization",
    "Optional Enrichment",
    "Analysis Engine",
    "Report Generation",
    "Human Review",
    "Git Publish",
]

ATTCK_KEYWORDS = {
    "Credential Access": ["password", "hash", "token", "lsass", "mimikatz", "vault", "credential"],
    "Initial Access": ["phishing", "malspam", "spoofed", "spear phishing", "email lure"],
    "Execution": ["powershell", "wscript", "rundll32", "cmd.exe", "wmic", "mshta", "certutil"],
    "Persistence": ["startup", "task scheduler", "schtasks", "run key", "registry", "autorun", "wmi event"],
    "Privilege Escalation": ["admin", "privilege", "token", "uac", "elevation"],
    "Defense Evasion": ["encoded command", "obfuscation", "disable security", "amsi", "applocker", "security product"],
    "Lateral Movement": ["psexec", "wmic", "remote desktop", "rdp", "smb", "wmi"],
    "Collection": ["browser", "clipboard", "file collection", "harvest", "archive"],
    "Exfiltration": ["upload", "download", "exfil", "cloud", "dropbox", "transfer"],
}

KNOWN_TLDS = {
    "com", "net", "org", "io", "co", "gov", "edu", "info", "biz", "app", "cloud", "dev", "ai",
    "us", "uk", "de", "fr", "in", "jp", "cn", "ru", "au", "ca", "it", "me", "tv", "xyz"
}

NOISE_DOMAIN_WORDS = {
    "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r",
    "s", "t", "u", "v", "w", "x", "y", "z", "type", "style", "src", "href", "length", "target",
    "prototype", "window", "document", "location", "main", "ajax", "search", "load", "render",
    "query", "script", "console", "indexof", "replaceall", "call", "match", "class", "log", "string",
    "array", "object", "return", "this", "value", "form", "event", "node", "error", "attr", "child",
    "parent", "selector", "button", "text", "href", "onload", "onclick", "ready", "config", "module",
    "global", "policy", "token", "util", "function", "var", "let", "const",
}


@dataclass
class Evidence:
    ips: list[str]
    domains: list[str]
    urls: list[str]
    hashes: list[str]
    files: list[str]
    processes: list[str]
    timestamps: list[str]

    def as_dict(self) -> dict[str, list[str]]:
        return asdict(self)


class HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        text = " ".join(data.split())
        if text:
            self.parts.append(text)

    def get_text(self) -> str:
        return "\n".join(self.parts)


def fetch_json(url: str, headers: dict[str, str] | None = None, timeout: int = 20) -> dict:
    request = Request(url, headers=headers or {"User-Agent": "Mozilla/5.0"})
    with urlopen(request, timeout=timeout) as response:
        payload = response.read()
    return json.loads(payload.decode("utf-8", errors="replace"))


def safe_http_get(url: str) -> str:
    req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urlopen(req, timeout=20) as response:
        body = response.read()
    try:
        content = body.decode("utf-8")
    except UnicodeDecodeError:
        content = body.decode("latin-1", errors="replace")
    return content


def enrich_indicators(ips: list[str], domains: list[str], hashes: list[str]) -> dict[str, object]:
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return {
            "status": "skipped",
            "summary": "VT_API_KEY not set; enrichment skipped.",
            "indicators": {"ips": [f"{ip} | reports unavailable" for ip in ips[:5]], "domains": [f"{domain} | reports unavailable" for domain in domains[:5]], "hashes": [f"{value} | reports unavailable" for value in hashes[:5]]},
        }

    headers = {"x-apikey": api_key, "User-Agent": "BlueTeamThreatHuntingPipeline"}
    enriched: dict[str, list[str]] = {"ips": [], "domains": [], "hashes": []}
    description_parts: list[str] = []

    for ip in ips[:5]:
        try:
            result = fetch_json(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers)
            attrs = result.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            reputation = attrs.get("reputation")
            enriched["ips"].append(f"{ip} | vt_reports={malicious + suspicious} | reputation={reputation if reputation is not None else 'unknown'}")
            description_parts.append(ip)
        except Exception:
            enriched["ips"].append(f"{ip} | reports unavailable")

    for domain in domains[:5]:
        try:
            result = fetch_json(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers)
            attrs = result.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            reputation = attrs.get("reputation")
            enriched["domains"].append(f"{domain} | vt_reports={malicious + suspicious} | reputation={reputation if reputation is not None else 'unknown'}")
            description_parts.append(domain)
        except Exception:
            enriched["domains"].append(f"{domain} | reports unavailable")

    for value in hashes[:5]:
        try:
            result = fetch_json(f"https://www.virustotal.com/api/v3/files/{value}", headers=headers)
            attrs = result.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            reputation = attrs.get("reputation")
            enriched["hashes"].append(f"{value} | vt_reports={malicious + suspicious} | reputation={reputation if reputation is not None else 'unknown'}")
            description_parts.append(value)
        except Exception:
            enriched["hashes"].append(f"{value} | reports unavailable")

    summary = f"VT enrichment completed for {len(description_parts)} indicators: {', '.join(description_parts[:5])}"
    return {"status": "success", "summary": summary, "indicators": enriched}


def sanitize_html_text(html: str) -> str:
    cleaned = re.sub(r"<script.*?</script>", " ", html, flags=re.I | re.S)
    cleaned = re.sub(r"<style.*?</style>", " ", cleaned, flags=re.I | re.S)
    cleaned = re.sub(r"<noscript.*?</noscript>", " ", cleaned, flags=re.I | re.S)
    cleaned = re.sub(r"<[^>]+>", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip()


def extract_html_text(html: str) -> str:
    parser = HTMLTextExtractor()
    parser.feed(sanitize_html_text(html))
    parser.close()
    return parser.get_text()


def extract_pdf_text(path: Path) -> str:
    if PdfReader is None:
        raise RuntimeError("pypdf is not installed; install it with: pip install pypdf")
    reader = PdfReader(str(path))
    pages = [page.extract_text() or "" for page in reader.pages]
    return "\n".join(page for page in pages if page)


def read_input_source(source: str) -> str:
    parsed = urlparse(source)
    if parsed.scheme in {"http", "https"}:
        raw = safe_http_get(source)
        if parsed.path.lower().endswith(".pdf") or "pdf" in source.lower():
            temp_path = Path(".cache") / "downloaded.pdf"
            temp_path.parent.mkdir(exist_ok=True)
            temp_path.write_bytes(urlopen(Request(source, headers={"User-Agent": "Mozilla/5.0"}), timeout=20).read())
            try:
                return extract_pdf_text(temp_path)
            except RuntimeError:
                pass
        if "<html" in raw.lower() or "<body" in raw.lower():
            return extract_html_text(raw)
        return raw

    path = Path(source).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"Input source not found: {source}")

    suffix = path.suffix.lower()
    if suffix == ".pdf":
        return extract_pdf_text(path)
    if suffix in {".html", ".htm"}:
        return extract_html_text(path.read_text(encoding="utf-8", errors="replace"))
    return path.read_text(encoding="utf-8", errors="replace")


def is_likely_domain(value: str) -> bool:
    candidate = value.rstrip(".,;:!?)]}>")
    if not re.match(r"^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$", candidate):
        return False
    labels = [part.lower() for part in candidate.split(".")]
    if any(not label or len(label) < 2 for label in labels[:-1]):
        return False
    if labels[-1] not in KNOWN_TLDS:
        return False
    if any(label in NOISE_DOMAIN_WORDS for label in labels):
        return False
    return True


def normalize_evidence(raw_text: str) -> Evidence:
    ips = sorted(set(re.findall(r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)", raw_text)))
    raw_domains = set(re.findall(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}", raw_text))
    domains = sorted({domain for domain in raw_domains if is_likely_domain(domain)})
    urls = sorted({url.rstrip(".,;:!?)]}>\"") for url in re.findall(r"https?://[^\s\)\]>\"']+", raw_text)})
    hashes = sorted(set(re.findall(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b", raw_text)))
    files = sorted(set(re.findall(r"\b[A-Za-z0-9_.-]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|jar|zip|rar|docx|xlsx|pptx)\b", raw_text, flags=re.I)))
    processes = sorted(set(re.findall(r"\b(?:powershell|cmd\.exe|rundll32|wmic|mshta|regsvr32|certutil|bitsadmin|schtasks|netsh|whoami|psexec)\b", raw_text, flags=re.I)))
    timestamps = sorted(set(re.findall(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:?\d{2})?\b", raw_text)))
    return Evidence(ips=ips, domains=domains, urls=urls, hashes=hashes, files=files, processes=processes, timestamps=timestamps)


def optional_enrichment(evidence: Evidence) -> dict[str, object]:
    if not os.getenv("VT_API_KEY"):
        return {"status": "Skipped", "details": "Set VT_API_KEY to enable reputation enrichment."}

    enriched = enrich_indicators(evidence.ips, evidence.domains, evidence.hashes)
    if enriched["status"] == "success":
        return {
            "status": "Enabled",
            "details": "VirusTotal enrichment completed with live API lookups.",
            "sample_indicators": enriched["indicators"],
            "summary": enriched["summary"],
        }
    return {
        "status": "Enabled",
        "details": "VirusTotal enrichment attempted, but the request failed.",
        "sample_indicators": enriched["indicators"],
        "summary": enriched["summary"],
    }


def match_attack_techniques(text: str) -> list[str]:
    lower_text = text.lower()
    match: list[str] = []
    for technique, keywords in ATTCK_KEYWORDS.items():
        if any(keyword.lower() in lower_text for keyword in keywords):
            match.append(technique)
    return match


def extract_executive_summary(text: str) -> str:
    if not text or not text.strip():
        return "The source content was parsed successfully, but no usable text was recovered for review."

    sentences = []
    for chunk in re.split(r"(?<=[.!?])\s+|\n+", text):
        clean = re.sub(r"\s+", " ", chunk).strip()
        if len(clean) < 35:
            continue
        if re.search(r"[{}=;]", clean[:120]):
            continue
        sentences.append(clean)

    if not sentences:
        return "The document was processed successfully but did not contain plain-language narrative details suitable for a deeper threat assessment."

    priority_terms = [
        "goal",
        "source-grounded",
        "output",
        "design principle",
        "architecture",
        "execution",
        "publishing",
        "automation",
        "analysis",
        "blueprint",
        "threat hunting",
    ]
    preferred: list[str] = []
    for sentence in sentences:
        lower = sentence.lower()
        if any(term in lower for term in priority_terms):
            preferred.append(sentence)

    if preferred:
        selected = []
        for sentence in preferred:
            clean = sentence.strip()
            if clean not in selected and len(clean) > 35:
                selected.append(clean)
        if selected:
            return " ".join(selected[:4])

    return " ".join(sentences[:2])


def summarize_preview(text: str) -> str:
    sentences = re.split(r"(?<=[.!?])\s+", text)
    parts = []
    for sentence in sentences:
        clean = re.sub(r"\s+", " ", sentence).strip()
        if len(clean) < 40:
            continue
        if re.search(r"[{}=;]", clean[:120]):
            continue
        parts.append(clean)
    summary = " ".join(parts[:6])
    if not summary:
        summary = "Source content was parsed successfully and normalized for threat-hunting analysis."
    return summary[:1800]


def generate_markdown_report(source: str, text: str, evidence: Evidence, techniques: list[str], enrichment: dict[str, str]) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# Threat Hunting Review",
        "",
        f"- Generated: {timestamp}",
        f"- Source: {source}",
        "",
        "## Pipeline Summary",
        "",
    ]
    for idx, step in enumerate(PIPELINE_STEPS, start=1):
        lines.append(f"{idx}. {step}")

    has_evidence = any(
        [
            evidence.ips,
            evidence.domains,
            evidence.urls,
            evidence.hashes,
            evidence.files,
            evidence.processes,
            evidence.timestamps,
            techniques,
        ]
    )

    lines += ["", "## Executive Summary", ""]
    if has_evidence:
        lines.append("This document contains detectable indicators and the analysis below focuses on those findings.")
    else:
        lines.append(extract_executive_summary(text))

    lines += [
        "",
        "## Extracted Evidence",
        "",
        f"- IPs: {', '.join(evidence.ips) if evidence.ips else 'None detected'}",
        f"- Domains: {', '.join(evidence.domains) if evidence.domains else 'None detected'}",
        f"- URLs: {', '.join(evidence.urls) if evidence.urls else 'None detected'}",
        f"- Hashes: {', '.join(evidence.hashes) if evidence.hashes else 'None detected'}",
        f"- Files: {', '.join(evidence.files) if evidence.files else 'None detected'}",
        f"- Processes: {', '.join(evidence.processes) if evidence.processes else 'None detected'}",
        f"- Timestamps: {', '.join(evidence.timestamps) if evidence.timestamps else 'None detected'}",
        "",
        "## Optional Enrichment",
        "",
        f"- Status: {enrichment.get('status', 'Unknown')}",
        f"- Details: {enrichment.get('details', 'No details available')}",
        "",
        "## ATT&CK Mapping",
        "",
        f"- {', '.join(techniques) if techniques else 'No direct keyword matches'}",
        "",
        "## Human Review Checklist",
        "",
        "- Validate all claims and indicators against host telemetry.",
        "- Check whether the source is trusted and whether the content is complete.",
        "- Confirm whether evidence requires additional source correlation.",
        "- Review privacy and data-handling constraints before publishing.",
        "",
        "## Source Preview",
        "",
        "The raw page text has been sanitized to remove embedded script and style noise before analysis.",
        "",
        "```text",
        summarize_preview(text),
        "```",
    ]
    return "\n".join(lines)


def export_json_report(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def git_publish(repo_root: Path, commit_message: str) -> None:
    if not (repo_root / ".git").exists():
        raise FileNotFoundError(f"Not a git repository: {repo_root}")
    subprocess.run(["git", "-C", str(repo_root), "add", "."], check=True)
    try:
        subprocess.run(["git", "-C", str(repo_root), "commit", "-m", commit_message], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("No changes to commit; skipping git commit.")
    subprocess.run(["git", "-C", str(repo_root), "push", "origin", "HEAD"], check=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Threat-hunting workflow automation based on a blueprint pipeline.")
    parser.add_argument("source", help="URL or local file to ingest.")
    parser.add_argument("--output-dir", default="./reports", help="Directory for generated markdown and JSON results.")
    parser.add_argument("--title", default="Threat Hunting Review", help="Report title.")
    parser.add_argument("--git-publish", action="store_true", help="Stage, commit, and push the generated output to the current git repository.")
    parser.add_argument("--git-commit-message", default="Add threat hunting report", help="Git commit message to use when publishing.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        text = read_input_source(args.source)
    except Exception as exc:  # pragma: no cover - CLI validation
        print(f"Failed to read input source: {exc}", file=sys.stderr)
        return 2

    evidence = normalize_evidence(text)
    attack_techniques = match_attack_techniques(text)
    enrichment = optional_enrichment(evidence)
    report_md = generate_markdown_report(args.source, text, evidence, attack_techniques, enrichment)
    report_path = out_dir / "threat_hunting_review.md"
    json_path = out_dir / "threat_hunting_review.json"

    report_path.write_text(report_md, encoding="utf-8")
    payload = {
        "source": args.source,
        "pipeline": PIPELINE_STEPS,
        "evidence": evidence.as_dict(),
        "attack_techniques": attack_techniques,
        "enrichment": enrichment,
        "human_review": [
            "Validate the source and indicators with host telemetry.",
            "Confirm whether indications are malicious or benign.",
            "Apply proper privacy review before publication.",
        ],
    }
    export_json_report(json_path, payload)

    print(f"Report written to: {report_path}")
    print(f"JSON written to: {json_path}")
    print(f"ATT&CK techniques: {attack_techniques if attack_techniques else 'No matches'}")

    if args.git_publish:
        try:
            git_publish(Path.cwd(), args.git_commit_message)
            print("Git publish completed.")
        except Exception as exc:
            print(f"Git publish skipped: {exc}", file=sys.stderr)
            return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
