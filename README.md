# Insider Threat Detection Using Explainable AI

An explainable AI-powered insider threat detection project that analyses user activity, identifies potentially suspicious behavioural patterns, and explains model predictions using SHAP. The project also includes a SOC-style investigation dashboard for reviewing flagged cases and their associated evidence.

## Overview

Insider threats can involve unusual access patterns, suspicious file transfers, abnormal USB usage, or unexpected communication activity. Detecting such behaviour requires analysing user activity over time rather than relying on isolated events.

This project uses the CERT Insider Threat Dataset (r4.2) to develop a machine learning pipeline for identifying potentially risky user behaviour. It combines behavioural feature engineering, CatBoost classification, SHAP-based explainability, and an investigation interface to support evidence-driven security analysis.

**Important:** A model prediction indicates potential risk and is not proof of malicious intent. All flagged cases require human review and validation.

## Objectives

- Analyse user activity to identify potentially suspicious behaviour.
- Engineer behavioural features and deviations from historical activity patterns.
- Train a CatBoost classifier to identify potential insider-threat cases.
- Explain model predictions using SHAP.
- Generate case-level investigation information from behavioural indicators and risk features.
- Provide a SOC-style dashboard for reviewing flagged cases and associated evidence.

## Tech Stack

| Component | Technology |
|---|---|
| Programming language | Python |
| Dataset | CERT Insider Threat Dataset r4.2 |
| Machine learning | CatBoost |
| Explainable AI | SHAP |
| Data processing | Pandas, NumPy |
| Development environment | Kaggle Notebooks / Jupyter Notebook |
| Investigation interface | HTML, CSS, JavaScript |
| Backend | Python |
| Semantic retrieval | Sentence Transformers and FAISS, where configured |

## Project Workflow

1. **Data processing:** Process user activity data from the CERT dataset.
2. **Feature engineering:** Construct daily behavioural features from activity records, including logons, USB connections, file operations, email activity, and web activity.
3. **Behavioural baselines:** Calculate historical behavioural statistics and deviations to identify changes in user activity.
4. **Risk feature engineering:** Create composite features representing activity volume, after-hours activity, external email ratios, and relationships between different behaviours.
5. **Model training:** Train a CatBoost classifier to distinguish between normal and potentially malicious activity.
6. **Model evaluation:** Evaluate the classifier using appropriate classification metrics and a chronological train-test split.
7. **Explainability:** Use SHAP to identify features contributing to individual predictions and to understand model behaviour.
8. **Investigation support:** Organise flagged cases with their probabilities, behavioural indicators, deviations, and feature explanations.
9. **SOC dashboard:** Present flagged cases and associated evidence in an interface designed to support analyst triage and investigation.

## Machine Learning Model

The project uses CatBoost, a gradient-boosted decision tree algorithm suitable for structured/tabular data.

The model learns patterns across behavioural, historical deviation, engineered risk, and contextual features to estimate the probability associated with a potential insider-threat case.

The notebook configuration includes:

- Iterations: 500
- Tree depth: 8
- Learning rate: 0.05
- Loss function: Logloss
- Evaluation metric: F1
- Random seed: 42

The model uses a chronological train-test split to evaluate performance on later observations.

## Explainable AI with SHAP

SHAP (SHapley Additive exPlanations) is used to interpret the model's predictions.

It supports two levels of explainability:

- **Global explainability:** Identifies features that are influential across the evaluated dataset.
- **Local explainability:** Explains which features contributed to an individual flagged case's prediction.

Behavioural features, historical deviations, and engineered risk indicators help analysts understand why a case was flagged rather than relying only on a probability score.

SHAP contributions explain model behaviour; they do not independently establish malicious intent.

## SOC Investigation Dashboard

The companion web application is designed to help analysts review model-flagged cases in a structured interface.

Its intended capabilities include:

- A dashboard summarising flagged cases and threat probabilities.
- A case queue for prioritising potentially high-risk cases.
- Individual case details and behavioural indicators.
- Case-associated logon, device, file, and email evidence, where available.
- SHAP-style explanations and engineered behavioural risk features.
- Evidence-oriented investigation support.

The dashboard is an investigation aid, not an automated system for making disciplinary or other high-impact decisions.

## Repository Structure

```text
insider-threat-detection/
├── insider-threat-detection.ipynb
├── README.md
├── requirements.txt
├── feature_columns.json
├── app.py
├── app.js
├── index.html
├── styles.css
├── brief.css
└── .gitignore
```

The notebook is the primary machine learning artifact. The application files are included if the companion SOC dashboard is published in the same repository.

Actual files may differ depending on the version uploaded.

## Getting Started

### 1. Clone the repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd insider-threat-detection
```

### 2. Open the notebook

Open `insider-threat-detection.ipynb` on GitHub to review the code and saved outputs, or open it in Kaggle or Jupyter Notebook to execute it.

### 3. Obtain the dataset

Obtain the CERT Insider Threat Dataset r4.2 from its authorised source and follow the dataset's applicable access and usage conditions.

Update the notebook's data paths to match your environment. The complete dataset is not included in this repository.

### 4. Install dependencies

If running locally, install the dependencies listed in `requirements.txt`:

```bash
pip install -r requirements.txt
```

Some environments may require additional setup for notebook-specific or optional components.

### 5. Run the notebook

Execute the notebook cells in order, ensuring that the dataset paths and required dependencies are configured correctly.

The web dashboard, if included, may require additional local data and model artifacts. Refer to the application code and configuration for its specific setup requirements.

## Evaluation

The notebook evaluates the model using classification metrics, including precision, recall, F1-score, ROC-AUC, and a confusion matrix, where available.

Evaluation results should be interpreted in the context of class imbalance, temporal data splitting, and the distinction between model predictions and confirmed insider incidents.

Refer to the saved notebook outputs for the reported experimental results.

## Limitations

- Model performance depends on the dataset, feature engineering, and evaluation methodology.
- Historical patterns may not capture every legitimate change in employee responsibilities or work schedules.
- High model confidence does not guarantee that a case represents malicious behaviour.
- The investigation dashboard is a local demonstration and is not a production-ready enterprise security platform.
- Access to the complete dataset and reproduction of results may require additional setup.
- The system should support, not replace, qualified human investigation.

## Future Improvements

- Improve native categorical feature handling and model validation.
- Evaluate performance across different time periods and user groups.
- Add more robust evidence provenance and investigation audit trails.
- Improve dashboard filtering, case prioritisation, and visual analytics.
- Add tests, reproducible configuration, and deployment documentation.
- Evaluate the system on additional datasets and realistic operational scenarios.

## Responsible Use

This project is intended for educational, research, and defensive cybersecurity purposes. It should be used to support authorised security analysis, with appropriate access controls and human oversight.

Flagged behaviour should be investigated in context. The system must not be used to treat a prediction as conclusive evidence of wrongdoing.

## Acknowledgements

This project uses the CERT Insider Threat Dataset r4.2 for insider-threat research and experimentation.

Refer to the dataset's official documentation and applicable terms for attribution and usage requirements.

## Author

**[Your Name]**

GitHub: [Your GitHub Profile URL](https://github.com/)

---

*Built as a machine learning and explainable AI project for behavioural risk analysis and insider-threat investigation.*
