# ScaMail AI — Scam & Phishing Detection System

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**ScaMail AI** is an intelligent decision-support web application engineered to detect whether suspicious SMS, WhatsApp messages, or website URLs are phishing or fraud attempts.

Designed specifically for contemporary cyber fraud (such as bank KYC scams, electricity bill extortion, fake lottery alerts, and APK hijacking), the system employs a **3-tier hybrid detection architecture**:

1. **Heuristic Rule Engine:** Instant deterministic checks for urgent threats, credential requests (OTP/CVV/PIN), APK downloads, remote access tools (AnyDesk/TeamViewer), and deceptive domain patterns.
2. **Machine Learning Classifiers:** Classical statistical classifiers analyzing message linguistics (TF-IDF + Logistic Regression) and URL structural features (Random Forest with zero-leakage domain grouping).
3. **AI Explanations & Privacy:** PII redaction (phones, Aadhaar, cards, OTPs) and LLM-powered bilingual (English & Hindi) guidance explaining *why* an input is dangerous and what specific actions to take.

---

## 🏗️ System Architecture

```
[ User pastes SMS / WhatsApp / URL ]
                  │
                  ▼
         [ Frontend: React UI ] ────────── POST /api/scan ──────────┐
                                                                    ▼
                                                        [ Backend: FastAPI ]
                                                                    │
                                                                    ▼
                                                     [ Step 1: PII Redaction ]
                                                       (Masks phones, OTPs, cards)
                                                                    │
                                          ┌─────────────────────────┴─────────────────────────┐
                                          ▼                                                   ▼
                             [ Step 2: Heuristic Rules ]                         [ Step 3: ML Classifiers ]
                               - Urgency & suspension threats                      - Text Scam Model (TF-IDF)
                               - Sensitive credential theft                        - URL Phishing Model (Random Forest)
                               - Bank & authority impersonation
                               - Malicious APK & AnyDesk traps
                                          │                                                   │
                                          └─────────────────────────┬─────────────────────────┘
                                                                    ▼
                                                     [ Step 4: Detection Fusion ]
                                                       - Weighted composite risk score (0-100)
                                                       - Critical safety floor overrides
                                                       - Verdict: Safe / Suspicious / Likely Scam
                                                                    │
                                                                    ▼
                                                     [ Step 5: AI Explanation ]
                                                       - Bilingual (English & Hindi) advice
                                                       - Actionable safety recommendations
                                                                    │
                                                                    ▼
                                                     [ Step 6: SQLite Storage ]
                                                       - Redacted history & live analytics
                                                                    │
                                                                    ▼
[ Frontend: React UI ] ◄────────── Structured JSON Response ────────┘
(Color-coded verdict, Risk meter, Highlighted terms, Bilingual cards)
```

---

## 👥 Team Roles & Responsibilities

| Member | Role | Directory | Key Deliverables |
|---|---|---|---|
| **Sabyasachi** | Machine Learning Engineer | [`model/`](model/) | Text scam pipeline, URL phishing pipeline, dataset curation, offline feature extraction. |
| **Aayush** | Backend & Integration Engineer | [`backend/`](backend/) | FastAPI server, Rule Engine, Detection Fusion, SQLite DB, end-to-end integration pipeline. |
| **Devansh** | Frontend & UI Engineer | `frontend/` | Responsive React UI, verdict badges, risk gauge, highlighted keywords, history & analytics. |
| **Aman** | AI & Application Security Engineer | `ai_security/` | PII redaction, prompt injection defense, bilingual LLM explanation generator with fallbacks. |

---

## 📁 Repository Layout

```text
ScaMail-AI/
├── README.md                           # Project landing page & documentation
├── SPEC.md                             # Formal API specification & component contract
├── future-task.txt                     # Detailed implementation roadmap for each team member
├── project_overview_and_team_roles.txt # Project vision, grading criteria & viva prep
│
├── backend/                            # Aayush's Backend & Integration module
│   ├── app/
│   │   ├── main.py                     # FastAPI application & CORS setup
│   │   ├── schemas.py                  # Pydantic request & response contracts
│   │   ├── rules/                      # Heuristic rules & Indian fraud patterns
│   │   ├── fusion/                     # Detection Fusion formula & safety overrides
│   │   ├── db/                         # SQLite database connection & CRUD analytics
│   │   ├── services/                   # Integration pipeline & subsystem wrappers
│   │   └── routers/                    # API endpoints (/scan, /history, /stats, /health)
│   ├── tests/                          # 22 automated unit & integration tests
│   ├── requirements.txt
│   └── README.md
│
├── model/                              # Sabyasachi's Machine Learning module
│   ├── data/                           # Datasets (UCI SMS, Mendeley Phishing, PhiUSIIL)
│   ├── notebook/                       # Jupyter training & evaluation notebooks
│   ├── saved_model/                    # Joblib fitted pipelines & evaluation metrics
│   ├── src/                            # Inference functions (predict_text, predict_url)
│   ├── requirements.txt
│   └── README.md
│
├── frontend/                           # Devansh's React dashboard (in progress)
└── ai_security/                        # Aman's PII redaction & LLM explainer (in progress)
```

---

## 🚀 Quick Start

### 1. Prerequisites
Ensure you have Python 3.10+ installed.

### 2. Backend Setup
```bash
# Install backend dependencies
pip install -r backend/requirements.txt

# Start the FastAPI development server
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive API documentation will be available at:
- Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)
- ReDoc: [http://localhost:8000/redoc](http://localhost:8000/redoc)

### 3. Run Automated Tests
```bash
python3 -m unittest discover backend/tests -v
```

---

## 📊 Detection Logic & Thresholds

| Risk Score | Risk Level | Verdict | Description |
|---|---|---|---|
| `0.0 - 34.9` | Low | **Safe** | No prominent heuristics or statistical scam patterns detected. |
| `35.0 - 69.9` | Medium | **Suspicious** | Ambiguous signals detected (e.g. link shorteners, generic urgency). Caution advised. |
| `70.0 - 100.0` | High | **Likely Scam** | Strong indicators of fraudulent activity, credential theft, or malware. |

> **Fail-Safe Overrides:** If a critical rule triggers (e.g., OTP/CVV request, AnyDesk installation prompt, or direct APK download), the score is clamped to a minimum of **75.0**, ensuring malicious inputs are never marked as "Safe".

---

## 📖 Specifications & Guides
- Detailed API schemas and parameters: See [`SPEC.md`](SPEC.md)
- Team member next steps: See [`future-task.txt`](future-task.txt)
- ML model training & evaluation: See [`model/README.md`](model/README.md)
- Backend architecture & viva preparation: See [`backend/README.md`](backend/README.md)
