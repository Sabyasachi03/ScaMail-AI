# ScaMail AI — System Specification & Contract (SPEC.md)

This document serves as the formal specification and API contract between all ScaMail AI subsystems:
- **ML Layer** (Sabyasachi — `model/`)
- **Backend & Rule/Fusion Engine** (Aayush — `backend/`)
- **Frontend Dashboard** (Devansh — `frontend/`)
- **Security & LLM Explainer** (Aman — `ai_security/`)

---

## 1. System Architecture & Request Lifecycle

```
[ User Input (Text / URL) ]
            │
            ▼
[ Frontend: React UI ] ────────── POST /api/scan ──────────┐
                                                           ▼
                                               [ Backend: FastAPI ]
                                                           │
                                                           ▼
                                            [ Step 1: PII Redaction ]
                                              (Aman: ai_security)
                                                           │
                                 ┌─────────────────────────┴─────────────────────────┐
                                 ▼                                                   ▼
                    [ Step 2: Rule Engine ]                             [ Step 3: ML Inference ]
                      (Aayush: backend/rules)                             (Sabyasachi: model/src)
                      - Urgency & threat detection                        - predict_text(text)
                      - Sensitive OTP/PIN requests                        - predict_url(url)
                      - Bank & authority impersonation
                      - Suspicious URL patterns
                                 │                                                   │
                                 └─────────────────────────┬─────────────────────────┘
                                                           ▼
                                            [ Step 4: Detection Fusion ]
                                              (Aayush: backend/fusion)
                                              - Weighted composite risk calculation
                                              - Safety floor overrides
                                              - Verdict: Safe / Suspicious / Likely Scam
                                                           │
                                                           ▼
                                            [ Step 5: AI Explanation ]
                                              (Aman: ai_security)
                                              - Bilingual (English & Hindi) guidance
                                              - Actionable user advice
                                              - Fallback template engine
                                                           │
                                                           ▼
                                            [ Step 6: Database Logging ]
                                              (Aayush: SQLite storage)
                                              - Store redacted scan record
                                                           │
                                                           ▼
[ Frontend: React UI ] ◄────────── JSON Response ──────────┘
(Verdict cards, Risk gauge, Highlighted words, Bilingual explanation)
```

---

## 2. API Contract

### 2.1 `POST /api/scan` — Primary Scam Detection Endpoint

#### Request Payload
```json
{
  "text": "URGENT: Your SBI account has been suspended due to pending KYC. Click http://sbi-kyc-verify.com to update immediately or account will be blocked.",
  "url": "http://sbi-kyc-verify.com",
  "language_preference": "both"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `text` | `string \| null` | Optional* | SMS, WhatsApp, or email message body. |
| `url` | `string \| null` | Optional* | Suspicious website URL. |
| `language_preference` | `string` | Optional | `"both"` (default), `"en"`, or `"hi"`. |

*\*Note: At least one of `text` or `url` must be provided and non-empty.*

#### Success Response (`200 OK`)
```json
{
  "scan_id": "c7f991ec-b04e-4f27-9971-55ec4dfb074a",
  "timestamp": "2026-11-13T15:30:00.000Z",
  "verdict": "Likely Scam",
  "risk_score": 93.4,
  "risk_level": "high",
  "summary": "Urgent bank KYC threat with suspicious external link",
  "redacted_text": "URGENT: Your SBI account has been suspended due to pending KYC. Click [URL_REDACTED] to update immediately or account will be blocked.",
  "detections": {
    "rules": {
      "triggered": true,
      "score_contribution": 45.0,
      "flags": [
        {
          "category": "urgency",
          "rule": "URGENT_DEADLINE",
          "severity": "high",
          "matched_text": "immediately"
        },
        {
          "category": "impersonation",
          "rule": "BANK_IMPERSONATION",
          "severity": "high",
          "matched_text": "SBI"
        },
        {
          "category": "threat",
          "rule": "ACCOUNT_SUSPENSION_THREAT",
          "severity": "high",
          "matched_text": "account will be blocked"
        }
      ],
      "highlighted_terms": ["URGENT", "SBI", "suspended", "KYC", "immediately", "blocked"]
    },
    "text_ml": {
      "analyzed": true,
      "probability": 0.9812,
      "prediction": "scam",
      "model": "text_classifier"
    },
    "url_ml": {
      "analyzed": true,
      "probability": 0.9924,
      "prediction": "phishing",
      "flags": ["suspicious_keywords", "not_https"],
      "domain": "sbi-kyc-verify.com"
    }
  },
  "explanation": {
    "en": {
      "title": "High Risk: Probable Bank Phishing Scam",
      "description": "This message impersonates SBI and creates false urgency regarding account suspension to induce you into clicking an unauthorized link.",
      "actions": [
        "Do not click on the link or provide any personal or banking credentials.",
        "SBI never sends links via SMS to update KYC.",
        "Report the message to the cyber crime portal (cybercrime.gov.in) or call 1930."
      ]
    },
    "hi": {
      "title": "उच्च जोखिम: बैंक फ़िशिंग धोखाधड़ी की चेतावनी",
      "description": "यह संदेश भारतीय स्टेट बैंक (SBI) के नाम पर फर्जी डर पैदा कर रहा है ताकि आप संदिग्ध लिंक पर क्लिक करें।",
      "actions": [
        "दिए गए लिंक पर बिल्कुल क्लिक न करें और कोई व्यक्तिगत जानकारी न दें।",
        "बैंक कभी भी एसएमएस के माध्यम से केवाईसी अपडेट करने के लिए लिंक नहीं भेजते।",
        "साइबर हेल्पलाइन 1930 पर या cybercrime.gov.in पर शिकायत दर्ज करें।"
      ]
    }
  }
}
```

#### Error Responses
- `400 Bad Request`: Empty input or invalid JSON structure.
- `422 Unprocessable Entity`: Neither `text` nor `url` provided.
- `500 Internal Server Error`: Server failure with structured error message.

---

### 2.2 `GET /api/history` — Scan History Endpoint

#### Query Parameters
- `limit` (integer, default: 20, max: 100)
- `offset` (integer, default: 0)
- `verdict` (optional string filter: `"Safe"`, `"Suspicious"`, `"Likely Scam"`)

#### Response (`200 OK`)
```json
{
  "total": 42,
  "limit": 20,
  "offset": 0,
  "items": [
    {
      "scan_id": "c7f991ec-b04e-4f27-9971-55ec4dfb074a",
      "timestamp": "2026-11-13T15:30:00.000Z",
      "redacted_text_snippet": "URGENT: Your SBI account has been suspended...",
      "url": "http://sbi-kyc-verify.com",
      "verdict": "Likely Scam",
      "risk_score": 93.4,
      "risk_level": "high",
      "top_category": "impersonation"
    }
  ]
}
```

---

### 2.3 `GET /api/stats` — Aggregate Dashboard Statistics

#### Response (`200 OK`)
```json
{
  "total_scans": 154,
  "verdict_breakdown": {
    "safe": 89,
    "suspicious": 27,
    "likely_scam": 38
  },
  "top_threat_categories": [
    { "category": "urgency", "count": 45 },
    { "category": "bank_impersonation", "count": 38 },
    { "category": "credential_request", "count": 29 },
    { "category": "lottery_prize", "count": 14 }
  ],
  "average_risk_score": 41.2
}
```

---

### 2.4 `GET /api/health` — System Health & Component Status

#### Response (`200 OK`)
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

## 3. Risk Score & Verdict Mapping Contract

- **Risk Score Range**: `0.0` to `100.0`
- **Verdict Bands**:
  - `0.0 <= score < 35.0`: **`Safe`** (Green) — Low risk, no red flags.
  - `35.0 <= score < 70.0`: **`Suspicious`** (Amber / Yellow) — Caution advised, partial triggers.
  - `70.0 <= score <= 100.0`: **`Likely Scam`** (Red) — Strong indicators of fraudulent activity.

### Safety Floor Overrides:
- If a **CRITICAL** rule fires (e.g. asking for OTP/CVV or remote access tool installation), the minimum score is clamped to **`75.0`** (ensuring verdict is always `Likely Scam`).
- If an ML model predicts probability $> 0.90$, the score cannot be below **`70.0`**.
