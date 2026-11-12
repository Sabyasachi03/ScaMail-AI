# ScaMail AI machine-learning module

ScaMail AI contains two independent, classical machine-learning classifiers for a B.Tech scam and phishing-detection project:

- **Text scam classifier:** receives an SMS/text and returns `legitimate` (`0`) or `scam` (`1`).
- **Phishing URL classifier:** receives only a raw URL and returns `legitimate` (`0`) or `phishing` (`1`). It does not request, open, or inspect a website.

## Data and preparation

Original files remain untouched below `data/`. See [DATASET_INSPECTION_REPORT.md](DATASET_INSPECTION_REPORT.md) for the verified filenames, encodings, headers, samples, missing values, duplicate counts, and source-label distributions.

`src.data_preparation` uses separate loaders because the source formats differ:

| Dataset | Source format | Input field | Original labels | ScaMail mapping |
|---|---|---|---|---|
| UCI SMS Spam Collection | headerless UTF-8 TSV | message column 2 | `ham`, `spam` | ham `0`, spam `1` |
| Mendeley SMS Phishing | UTF-8 CSV within supplied ZIP | `TEXT` | `ham`, `spam`/`smishing` (case-insensitive) | ham `0`, malicious `1` |
| PhiUSIIL URL | UTF-8-BOM CSV | `URL` | `1` legitimate, `0` phishing | **inverted:** legitimate `0`, phishing `1` |

The processed outputs are:

- `data/processed/combined_sms.csv`: 6,056 non-empty, exact-deduplicated SMS records (4,994 legitimate; 1,062 scam), with `text`, `label`, and `source`.
- `data/processed/cleaned_urls.csv`: 235,370 unique non-empty URLs (134,850 legitimate; 100,520 phishing), with only `url` and `label`.

## Layout

```text
model/
├── data/                       # original data plus generated processed/ data
├── notebook/                   # executable training notebooks
├── saved_model/                # fitted Joblib pipelines and measured JSON metrics
├── src/                        # loaders, feature extraction, training, inference
├── DATASET_INSPECTION_REPORT.md
├── requirements.txt
└── README.md
```

## Install and run

From the `model` directory:

```powershell
python -m pip install -r requirements.txt
python -m src.dataset_inspection
jupyter notebook notebook/01_text_scam_classifier.ipynb
jupyter notebook notebook/02_phishing_url_classifier.ipynb
```

Run each notebook from top to bottom. They regenerate their processed data, train, evaluate, and write the complete fitted artifacts:

- `saved_model/text_scam_pipeline.joblib`
- `saved_model/url_phishing_pipeline.joblib`

`text_metrics.json` and `url_metrics.json` retain the exact splits, validation choices, held-out metrics, confusion matrices, and feature importance from the latest run. No training dataset is accessed at inference time.

## Integration

Import through the `src` package while `model/` is on Python's import path:

```python
from src import predict_text, predict_url

predict_text("URGENT: Your account is blocked. Verify now at http://example.test")
# {'prob': 0.97..., 'prediction': 'scam', 'model': 'text_classifier'}

predict_url("http://secure-login.verify-account.example/confirm?user=123")
# {'prob': 1.0, 'prediction': 'phishing', 'flags': ['suspicious_keywords', 'not_https']}
```

Both functions resolve model paths relative to their own files, so they do not depend on the FastAPI process's current directory. Invalid or empty inputs return `prediction: "invalid"` and an explanatory `error`. Probabilities are always column `1`: scam for text and phishing for URLs.

## How the models work

The text pipeline combines word TF-IDF 1–2 grams with character TF-IDF 3–5 grams. It compares Complement Naive Bayes, balanced Logistic Regression, and calibrated Linear SVM using only the validation set; the selected model is then refitted on train+validation before the single test evaluation.

The URL pipeline parses the URL locally using `urllib.parse`, then extracts length, host/subdomain structure, punctuation/digits, HTTPS, path/query, suspicious-word, punycode, and entropy features. `tldextract` obtains a public-suffix-aware registered-domain grouping key using its bundled suffix list (no network fetch). Random Forest is trained with class balancing. XGBoost was not installed in this environment, so it was not compared or listed as a dependency.

URLs from a registered domain are assigned to exactly one of train, validation, or test. The latest run has zero registered-domain overlap across every pair of splits.

## Measured evaluation results

These are the actual saved held-out test results, not estimates:

| Model | Test rows | Accuracy | Malicious precision | Malicious recall | Malicious F1 | PR-AUC | Confusion matrix `[TN, FP; FN, TP]` |
|---|---:|---:|---:|---:|---:|---:|---|
| Text — selected Logistic Regression | 1,212 | 0.990924 | 0.976415 | 0.971831 | 0.974118 | 0.993561 | `[[994, 5], [6, 207]]` |
| URL — Random Forest | 41,889 | 0.995751 | 0.997842 | 0.990230 | 0.994021 | 0.997221 | `[[26914, 32], [146, 14797]]` |

The URL grouped split contained 148,453 train, 45,028 validation, and 41,889 test rows; because entire domains stay together, its class proportions are not identical between splits. The notebooks show classification reports, plots, feature importance, and examples of false positives/negatives.

For interpretation: a **text false positive** can be a genuine bank alert or OTP/transaction notice whose urgent wording resembles a scam; a **text false negative** is a scam written with ordinary conversational language. A **URL false positive** often has a benign but unusual surface pattern (for example, a long HTTP URL or account-related word), while a **URL false negative** can be a phishing URL with a short, HTTPS-looking, otherwise ordinary structure. The notebooks print actual held-out examples rather than assuming a single cause for every error.

## Limitations and safe use

- These models learn from historical datasets and may be biased by their language, era, and collection methods. Treat output as a risk signal, not proof of fraud.
- Exact duplicate removal prevents message leakage; domain grouping prevents the same registered domain from leaking into URL evaluation. Similar templates or related domains can still be correlated.
- The URL model intentionally cannot inspect redirects, DNS, certificates, reputation, HTML, or page titles. That protects privacy and makes it usable with a raw URL alone, but limits detection.
- Domain-held-out performance is more realistic than a random URL split, yet a model can still behave poorly on unfamiliar top-level domains or very new attack styles. Monitor production performance and review false positives, especially security-related legitimate URLs.
- The default `0.5` threshold is a product choice. Adjust it only after validating the recall/false-positive trade-off on representative deployment data.

## Viva preparation

**What is supervised learning?** It learns a relationship from examples that already have the correct answer. Here the answer is a binary label: legitimate (`0`) or malicious (`1`).

**Why TF-IDF?** It turns messages into numbers. A term gets more weight when it is important in one message but not common in every message. Word n-grams capture phrases; character n-grams capture spelling tricks, phone-like patterns, and URLs.

**Why use validation and test sets?** The validation set selects the model. The test set is locked away until the end, so it gives an honest estimate rather than a score tuned repeatedly to the same data.

**Why stratify SMS splits?** Scam messages are fewer than legitimate messages. Stratification preserves approximately the same balance in every text split.

**Why group URL splits by registered domain?** A random URL split could put `bank.example/a` in training and `bank.example/b` in testing, making the score unrealistically easy. Grouping keeps a domain in one split only.

**What is precision versus recall?** Precision asks: “of URLs/messages predicted malicious, how many really were?” Recall asks: “of the truly malicious inputs, how many did we catch?” F1 balances those two; PR-AUC summarizes precision–recall behavior across thresholds and is useful with class imbalance.

**Why calibrated probabilities?** A score is not automatically a probability. The text SVM candidate is calibrated before comparison, and the selected Logistic Regression and Random Forest expose probability estimates. The API returns only the malicious-class probability.
