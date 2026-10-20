"""Local evidence-first insider-threat investigation demo.

Run with:  python app.py
Then open the URL printed in the terminal.
"""
from __future__ import annotations

import csv
import errno
import json
import os
import re
import socket
import urllib.error
import urllib.request
import webbrowser
from collections import Counter, defaultdict
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import numpy as np

ROOT = Path(__file__).resolve().parent
PORT = 8001


def load_dotenv() -> None:
    env_file = ROOT / ".env"
    if not env_file.exists():
        return
    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def parse_report(text: str) -> dict:
    def grab(pattern: str, default: str = "") -> str:
        match = re.search(pattern, text, re.S | re.I)
        return match.group(1).strip() if match else default

    case_id = int(grab(r"CASE ID\s*:\s*(\d+)", "0"))
    probability = float(grab(r"Threat Probability\s*-+\s*([0-9.]+)", "0"))
    sections = {}
    names = ["Observed Behavioural Indicators", "Behavioural Deviation Summary", "Top SHAP Features", "Engineered Behavioural Risk Features"]
    for name in names:
        value = grab(re.escape(name) + r"\s*=+\s*(.*?)(?=\n={5,}|\Z)")
        sections[name] = [line.replace("â€¢", "").replace("•", "").strip() for line in value.splitlines() if "•" in line or "â€¢" in line]
    shap = []
    for line in sections["Top SHAP Features"]:
        match = re.match(r"([^:]+):\s*([\-\d.]+).*?=\s*([\-\d.]+)", line)
        if match:
            shap.append({"feature": match.group(1), "value": float(match.group(2)), "contribution": float(match.group(3))})
    return {
        "id": case_id,
        "probability": probability,
        "indicators": sections["Observed Behavioural Indicators"],
        "deviations": sections["Behavioural Deviation Summary"],
        "shap": shap,
        "risk_features": sections["Engineered Behavioural Risk Features"],
        "raw_report": text,
    }


def event_rows(filename: str) -> list[dict]:
    path = ROOT / filename
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as source:
        return list(csv.DictReader(source))


def evidence_summary(rows: list[dict], field: str = "activity") -> dict:
    counts = Counter(row.get(field, "Event") for row in rows)
    return {"total": len(rows), "breakdown": dict(counts)}


def build_store() -> dict:
    reports = pd.read_csv(ROOT / "rag_case_reports.csv")["report"].tolist()
    parsed = [parse_report(report) for report in reports]

    # This reproduces the notebook's sort/split before its X_test positional IDs.
    feature_df = pd.read_parquet(ROOT / "daily_features_v5.parquet").sort_values("date").reset_index(drop=True)
    split = int(len(feature_df) * 0.8)
    test_df = feature_df.iloc[split:].reset_index(drop=True)

    by_case = {}
    for case in parsed:
        row = test_df.iloc[case["id"]]
        case["user"] = str(row["user"])
        case["date"] = pd.Timestamp(row["date"]).strftime("%Y-%m-%d")
        case["profile"] = {key: clean_number(row.get(key, 0)) for key in [
            "role", "department", "team", "functional_unit", "business_unit",
            "total_logons", "after_hours_logons", "usb_connects", "usb_after_hours",
            "files_copied", "emails_sent", "total_external_contacts", "http_visits",
            "job_search_visits", "activity_volume", "behavior_risk_score", "after_hours_risk",
        ] if key in row.index}
        by_case[case["id"]] = case

    sources = {
        "logon": event_rows("flagged_logon.csv"),
        "device": event_rows("flagged_device.csv"),
        "file": event_rows("flagged_file.csv"),
        "email": event_rows("flagged_email.csv"),
    }
    evidence = defaultdict(lambda: defaultdict(list))
    for source_name, rows in sources.items():
        for row in rows:
            evidence[(row.get("case_user"), row.get("case_date"))][source_name].append(row)

    for case in by_case.values():
        group = evidence[(case["user"], case["date"])]
        case["evidence_counts"] = {name: len(group[name]) for name in sources}
    return {"cases": by_case, "evidence": evidence, "source_names": list(sources), "reports": reports}


def clean_number(value):
    if pd.isna(value):
        return 0
    if isinstance(value, (int, float)):
        return round(float(value), 2)
    return str(value)


load_dotenv()
STORE = build_store()


def case_list() -> list[dict]:
    results = []
    for case in STORE["cases"].values():
        results.append({key: case[key] for key in [
            "id",
            "user",
            "date",
            "probability",
            "indicators",
            "evidence_counts",
            "shap",
            "deviations",
            "risk_features",
            "profile",
        ] if key in case})
    return sorted(results, key=lambda item: item["probability"], reverse=True)


def context_for(case: dict) -> str:
    return "\n".join([
        f"Case {case['id']} | subject {case['user']} | alert date {case['date']} | threat probability {case['probability']:.2%}",
        "Observed indicators: " + "; ".join(case["indicators"]),
        "Behavioral deviations: " + "; ".join(case["deviations"]),
        "Top SHAP factors: " + "; ".join(f"{x['feature']} ({x['contribution']:+.3f})" for x in case["shap"]),
        "Available evidence records: " + ", ".join(f"{name}={count}" for name, count in case["evidence_counts"].items()),
    ])


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, fmt, *args):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {fmt % args}")

    def send_json(self, value, status=200):
        body = json.dumps(value, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/cases":
            return self.send_json({"cases": case_list(), "total": len(STORE["cases"])})
        match = re.fullmatch(r"/api/cases/(\d+)", path)
        if match:
            case = STORE["cases"].get(int(match.group(1)))
            if not case:
                return self.send_json({"error": "Case not found"}, 404)
            group = STORE["evidence"][(case["user"], case["date"])]
            evidence = {name: group[name] for name in STORE["source_names"]}
            return self.send_json({"case": case, "evidence": evidence})
        if path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self):
        return self.send_json({"error": "Unsupported endpoint"}, 404)


class DashboardHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = False

    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


if __name__ == "__main__":
    server = None
    for port in range(PORT, PORT + 50):
        try:
            server = DashboardHTTPServer(("127.0.0.1", port), Handler)
            break
        except OSError as error:
            if error.errno != errno.EADDRINUSE:
                raise

    if server is None:
        raise RuntimeError(f"No available port found between {PORT} and {PORT + 49}")

    actual_port = server.server_address[1]
    url = f"http://127.0.0.1:{actual_port}"
    print(f"Loaded {len(STORE['cases'])} model-flagged cases from {ROOT}.")
    print(f"Opening dashboard at {url}")
    webbrowser.open(url)
    server.serve_forever()
