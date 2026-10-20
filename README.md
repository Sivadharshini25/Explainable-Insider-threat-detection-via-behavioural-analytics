# Sentinel — Insider Threat Investigation Platform

Local, evidence-first interface for the supplied CERT 4.2 CatBoost model outputs.

## Start

From PowerShell in this folder:

```powershell
.\start.ps1
```

The app opens at `http://127.0.0.1:8001`. If port 8001 is already occupied, it automatically uses the next available port and prints that URL.

If PyArrow is not installed, run:

```powershell
python -m pip install -r requirements.txt
```

## What is connected

- 262 CatBoost model-flagged threats from `rag_case_reports.csv`
- Case subjects and dates reconstructed from `daily_features_v5.parquet` using the original notebook's chronological test split and positional case IDs
- Supplied case-scoped authentication, device, file, and email records
- Local SHAP contribution and behavioral-deviation presentation
- SOC dashboard workflow for triage, queue review, and case evidence analysis without any external API dependency

## Important project note

This is a course-project investigation aid. A high model probability is an alert, not evidence of malicious intent. Validate business context and follow your organization’s review process before acting on a case.
