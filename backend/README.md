# ScaMail AI — Backend & Integration Module

> **Owned by:** Aayush (Backend & Integration Engineer)  
> **Directory:** `backend/`  
> **Framework:** FastAPI, SQLite, Pydantic, Python 3

---

## 1. Overview & Architecture

The **Backend & Integration Engine** is the central orchestrator of ScaMail AI. It exposes a high-performance REST API that receives suspicious inputs from Devansh's React frontend, executes a multi-stage security and detection pipeline, and stores anonymized scan logs in an SQLite database.

### The Request Lifecycle Pipeline

```
           [ User Input: Text / URL ]
                       │
                       ▼
            [ Step 1: PII Redaction ] 
            (Aman: ai_security / local fallback)
            - Masks phone numbers, OTPs, Aadhaar, card numbers
                       │
         ┌─────────────┴─────────────┐
         ▼                           ▼
[ Step 2: Rule Engine ]     [ Step 3: ML Classifiers ]
(backend/app/rules)         (Sabyasachi: model/src)
- Urgency / threats         - Text scam probability
- Credential requests       - Phishing URL probability
- Bank impersonation
- APK / AnyDesk traps
         │                           │
         └─────────────┬─────────────┘
                       ▼
          [ Step 4: Detection Fusion ]
          (backend/app/fusion)
          - Weighted composite formula
          - Critical safety floor overrides
          - Final Verdict: Safe / Suspicious / Likely Scam
                       │
                       ▼
          [ Step 5: AI Explanation ]
          (Aman: ai_security / bilingual fallback)
          - English & Hindi contextual advice
          - Actionable user next steps
                       │
                       ▼
          [ Step 6: SQLite Storage ]
          (backend/app/db)
          - Stores redacted record & analytics
                       │
                       ▼
       [ Structured JSON Response to Frontend ]
```

---

## 2. Directory Structure

```text
backend/
├── app/
│   ├── __init__.py
│   ├── main.py                     # FastAPI app instance, CORS middleware, lifespan
│   ├── config.py                   # Central settings, paths, DB path, thresholds
│   ├── schemas.py                  # Pydantic request/response schemas (with fallback)
│   ├── rules/
│   │   ├── __init__.py
│   │   ├── patterns.py             # Indian & global smishing heuristics & regexes
│   │   └── rule_engine.py          # Pattern matching, scoring, keyword highlights
│   ├── fusion/
│   │   ├── __init__.py
│   │   └── score_calculator.py     # Weighted fusion formula & safety overrides
│   ├── db/
│   │   ├── __init__.py
│   │   ├── database.py             # Thread-safe SQLite connection & schema creation
│   │   └── crud.py                 # Insert scan, fetch history, aggregate stats
│   ├── services/
│   │   ├── __init__.py
│   │   ├── ml_client.py            # Wrapper for Sabyasachi's model/src predictors
│   │   ├── security_client.py      # PII redaction & bilingual explanation engine
│   │   └── pipeline.py             # End-to-end integration orchestrator
│   └── routers/
│       ├── __init__.py
│       ├── scan.py                 # POST /api/scan endpoint
│       ├── history.py              # GET /api/history & GET /api/stats endpoints
│       └── health.py               # GET /api/health endpoint
├── tests/
│   ├── __init__.py
│   ├── test_rules.py               # Heuristic rule engine unit tests
│   ├── test_fusion.py              # Fusion calculation & threshold tests
│   ├── test_db.py                  # Database CRUD and analytics tests
│   ├── test_pipeline.py            # End-to-end pipeline integration tests
│   └── test_api.py                 # Schema and edge case tests
├── scamail.db                      # Local SQLite database (created on first run)
├── requirements.txt                # Python backend dependencies
└── README.md                       # Documentation & viva preparation
```

---

## 3. API Endpoints

### 3.1 `POST /api/scan`
Evaluates text, URL, or both for scam/phishing indicators.

**Request Body:**
```json
{
  "text": "URGENT: Your SBI account is blocked. Verify OTP at http://sbi-fake.com",
  "url": "http://sbi-fake.com",
  "language_preference": "both"
}
```

**Response (`200 OK`):**
```json
{
  "scan_id": "99f8d976-bf10-4ca0-90c2-5fb3d2f93ce0",
  "timestamp": "2026-11-13T09:50:00Z",
  "verdict": "Likely Scam",
  "risk_score": 92.5,
  "risk_level": "high",
  "summary": "Critical credential/OTP phishing attempt detected.",
  "redacted_text": "URGENT: Your SBI account is blocked. Verify OTP at [URL_REDACTED]",
  "url": "http://sbi-fake.com",
  "detections": {
    "rules": {
      "triggered": true,
      "score_contribution": 45.0,
      "flags": [
        {
          "category": "credential_theft",
          "rule": "CREDENTIAL_OTP_REQUEST",
          "severity": "critical",
          "matched_text": "Verify OTP"
        }
      ],
      "highlighted_terms": ["URGENT", "SBI", "blocked", "OTP"]
    },
    "text_ml": {
      "analyzed": true,
      "probability": 0.98,
      "prediction": "scam"
    },
    "url_ml": {
      "analyzed": true,
      "probability": 0.99,
      "prediction": "phishing"
    }
  },
  "explanation": {
    "en": {
      "title": "High Risk: Fraud / Phishing Attempt Detected",
      "description": "This input demands confidential OTP credentials and impersonates SBI.",
      "actions": [
        "Do not click on any link or open attached files.",
        "Never share OTP, PIN, NetBanking passwords, or CVV under any circumstances."
      ]
    },
    "hi": {
      "title": "उच्च जोखिम: धोखाधड़ी (स्कैम) का प्रयास पाया गया",
      "description": "यह इनपुट गोपनीय ओटीपी मांग रहा है और भारतीय स्टेट बैंक (SBI) के नाम का दुरुपयोग कर रहा है।",
      "actions": [
        "संदेश में दिए गए किसी भी लिंक पर क्लिक न करें।",
        "किसी भी परिस्थिति में अपना ओटीपी या पासवर्ड किसी से साझा न करें।"
      ]
    }
  }
}
```

### 3.2 `GET /api/history`
Retrieves paginated scan history.
- Query Parameters: `limit` (default: 20), `offset` (default: 0), `verdict` (optional filter).

### 3.3 `GET /api/stats`
Returns aggregated dashboard metrics:
- Total scans count
- Verdict distribution (Safe, Suspicious, Likely Scam)
- Top detected threat categories
- Average overall risk score

### 3.4 `GET /api/health`
Returns system status and component availability:
```json
{
  "status": "healthy",
  "components": {
    "rule_engine": "online",
    "text_model": "loaded",
    "url_model": "loaded",
    "database": "connected",
    "llm_service": "fallback_ready"
  },
  "version": "1.0.0"
}
```

---

## 4. Detection Fusion: Math & Logic

The Risk Score ($Score \in [0.0, 100.0]$) is calculated through a hybrid fusion mechanism:

### 4.1 Weight Distribution Formula
Depending on what input the user provided:

1. **Both Text and URL provided:**
   $$\text{Score} = (0.35 \cdot P_{\text{text}} + 0.35 \cdot P_{\text{url}} + 0.30 \cdot S_{\text{rule}}) \times 100$$
2. **Text Only provided:**
   $$\text{Score} = (0.60 \cdot P_{\text{text}} + 0.40 \cdot S_{\text{rule}}) \times 100$$
3. **URL Only provided:**
   $$\text{Score} = (0.70 \cdot P_{\text{url}} + 0.30 \cdot S_{\text{rule}}) \times 100$$

Where:
- $P_{\text{text}} \in [0.0, 1.0]$: Probability of scam from Sabyasachi's Text ML model.
- $P_{\text{url}} \in [0.0, 1.0]$: Probability of phishing from Sabyasachi's URL ML model.
- $S_{\text{rule}} \in [0.0, 1.0]$: Heuristic penalty score with diminishing returns ($1 - \prod (1 - w_i)$).

### 4.2 Safety Floor Overrides (Fail-Safe Principles)
Statistical ML models can occasionally be misled by adversarial wording. To prevent dangerous false negatives:
- **Critical Rule Floor:** If a `critical` rule fires (e.g. asking for OTP/CVV, requesting AnyDesk installation, or prompting an `.apk` download), the final score is clamped to a **minimum of 75.0**, guaranteeing a **Likely Scam** verdict.
- **High ML Confidence Floor:** If either ML model reports scam/phishing probability $\ge 0.85$, the score cannot drop below **70.0**.

### 4.3 Verdict Bands
- $0.0 \le \text{Score} < 35.0$: **Safe**
- $35.0 \le \text{Score} < 70.0$: **Suspicious**
- $70.0 \le \text{Score} \le 100.0$: **Likely Scam**

---

## 5. Running the Backend

### Installation
```bash
pip install -r backend/requirements.txt
```

### Running Server
```bash
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive API docs are available at: `http://localhost:8000/docs`

### Running Automated Tests
```bash
python3 -m unittest discover backend/tests
```

---

## 6. Viva Defense Questions & Answers (for Aayush)

**Q1: Why did you choose FastAPI over Flask or Django?**  
> *FastAPI provides native asynchronous I/O (`async/await`), automatic request validation using Pydantic, built-in interactive OpenAPI/Swagger documentation (`/docs`), and significantly higher throughput under concurrent requests compared to synchronous frameworks.*

**Q2: How does the Rule Engine complement the Machine Learning models?**  
> *Machine Learning models detect subtle lexical and statistical patterns from training datasets, but they can be bypassed by creative phrasing. The Rule Engine enforces deterministic security baselines: explicit red flags like asking for an OTP, prompting remote desktop software (AnyDesk), or downloading an APK immediately flag the message, regardless of whether the ML model has seen that specific phrasing before.*

**Q3: How does your Detection Fusion logic work?**  
> *The Detection Fusion engine dynamically weights inputs depending on whether the user submitted text, a URL, or both. It calculates a weighted linear combination of ML probabilities and heuristic rule scores, then applies a 'Safety Floor Override' where critical rules enforce a floor of 75/100, preventing adversarial text from receiving a 'Safe' verdict.*

**Q4: How do you handle user privacy and PII (Personally Identifiable Information)?**  
> *Privacy is enforced at Step 1 of the pipeline before data is processed by external APIs or stored in the database. Phone numbers, Aadhaar numbers, card numbers, and OTPs are redacted into tokens like `[PHONE_REDACTED]` and `[OTP_REDACTED]`. The SQLite database only stores the redacted versions.*

**Q5: What happens if an external service or ML model is unreachable or fails?**  
> *The backend is designed for resilience: each subsystem (ML inference, external LLM, and SQLite logging) has graceful error handling and offline fallbacks. If the LLM API is down, a contextual bilingual template engine generates rich safety advice in English and Hindi without interrupting the user experience.*
