"""Generate the two concise, executable training notebooks from maintained source code."""

from __future__ import annotations

from pathlib import Path

import nbformat as nbf

from .data_preparation import MODEL_DIR


BOOTSTRAP = '''from pathlib import Path
import sys

MODEL_DIR = Path.cwd().resolve()
while not (MODEL_DIR / "src").is_dir():
    if MODEL_DIR.parent == MODEL_DIR:
        raise RuntimeError("Run this notebook from inside the model directory tree.")
    MODEL_DIR = MODEL_DIR.parent
if str(MODEL_DIR) not in sys.path:
    sys.path.insert(0, str(MODEL_DIR))
'''


def _notebook(cells):
    book = nbf.v4.new_notebook()
    book.cells = cells
    book.metadata = {
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python", "version": "3"},
    }
    return book


def build_notebooks() -> tuple[Path, Path]:
    destination = MODEL_DIR / "notebook"
    destination.mkdir(exist_ok=True)
    text = _notebook([
        nbf.v4.new_markdown_cell("# Text scam classifier\n\nThis notebook combines the two verified SMS datasets, uses word and character TF-IDF features, selects a classical classifier on validation data, and evaluates once on a held-out test set. Label `1` always means scam."),
        nbf.v4.new_code_cell(BOOTSTRAP + "\nimport pandas as pd\nimport matplotlib.pyplot as plt\nimport seaborn as sns\nfrom src.data_preparation import prepare_sms_dataset\nfrom src.train_models import train_text_model\n\nsns.set_theme(style='whitegrid')"),
        nbf.v4.new_markdown_cell("## Prepare and inspect the standardized data\n\nExact duplicate messages and empty messages are removed before splitting. We preserve a `source` column so UCI and Mendeley provenance remains visible."),
        nbf.v4.new_code_cell("sms, cleaning_report = prepare_sms_dataset(save=True)\nprint(cleaning_report)\nprint('Shape:', sms.shape)\ndisplay(sms.head())\nprint('Missing values:\\n', sms.isna().sum())\nprint('Duplicate messages:', sms.duplicated('text').sum())\nprint('Class distribution:\\n', sms.label.value_counts().rename(index={0: 'legitimate', 1: 'scam'}))\n\nsms['message_length'] = sms.text.str.len()\nfig, axes = plt.subplots(1, 2, figsize=(12, 4))\nsns.countplot(data=sms, x='label', ax=axes[0])\naxes[0].set_xticklabels(['legitimate', 'scam'])\nsns.histplot(data=sms, x='message_length', hue='label', bins=40, element='step', ax=axes[1])\nplt.tight_layout()\ndisplay(sms.groupby('label').head(3)[['label', 'text']])"),
        nbf.v4.new_markdown_cell("## Features, validation, and test evaluation\n\nEach candidate pipeline learns two TF-IDF representations: word 1–2 grams capture phrases such as “verify account”, while character 3–5 grams help with URL fragments, spelling variants, and obfuscation. Complement Naive Bayes is a fast sparse-text baseline; balanced Logistic Regression models linear evidence; calibrated Linear SVM adds a margin-based comparison with valid probabilities. The test set is never used to select the model."),
        nbf.v4.new_code_cell("result = train_text_model()\nprint('Selected on validation F1:', result['selected_model'])\nprint('Split sizes:', result['split_sizes'])\nprint('Duplicate overlap checks:', result['duplicate_messages_across_train_validation_test'])\nvalidation = pd.DataFrame(result['validation_metrics']).T\ndisplay(validation[['accuracy', 'precision_scam_or_phishing', 'recall_scam_or_phishing', 'f1_scam_or_phishing', 'pr_auc']])\nprint('Held-out test metrics:')\ndisplay(pd.Series(result['test_metrics']).drop(['classification_report', 'confusion_matrix']))\nsns.heatmap(result['test_metrics']['confusion_matrix'], annot=True, fmt='d', cmap='Blues', xticklabels=['legitimate', 'scam'], yticklabels=['legitimate', 'scam'])\nplt.xlabel('Predicted'); plt.ylabel('Actual'); plt.show()\nprint(pd.DataFrame(result['test_metrics']['classification_report']).T)"),
        nbf.v4.new_markdown_cell("## Error analysis\n\nFalse positives involving genuine bank, OTP, account, or transaction language are especially important because these ordinary alerts can resemble scams. False negatives are scams that the model has labelled legitimate; review them to identify gaps in the training data."),
        nbf.v4.new_code_cell("display(result['error_analysis']['bank_or_otp_false_positives'])\ndisplay(result['error_analysis']['all_false_negatives'])"),
        nbf.v4.new_markdown_cell("## Saved pipeline and inference\n\nThe saved Joblib object includes the fitted TF-IDF vectorizers and selected classifier. Its `predict_proba(...)[..., 1]` is the scam probability, not an uncalibrated score."),
        nbf.v4.new_code_cell("from src.text_predictor import predict_text\nartifact = MODEL_DIR / 'saved_model' / 'text_scam_pipeline.joblib'\nprint('Saved:', artifact, artifact.exists())\npredict_text('URGENT: Your bank account is blocked. Verify your KYC immediately at http://example.test')"),
    ])
    url = _notebook([
        nbf.v4.new_markdown_cell("# Phishing URL classifier\n\nThis notebook trains only on features extracted from the URL string. It never visits a URL, reads HTML, or uses PhiUSIIL’s webpage-derived columns. Label `1` always means phishing."),
        nbf.v4.new_code_cell(BOOTSTRAP + "\nimport pandas as pd\nimport matplotlib.pyplot as plt\nimport seaborn as sns\nfrom src.data_preparation import prepare_url_dataset\nfrom src.train_models import train_url_model\n\nsns.set_theme(style='whitegrid')"),
        nbf.v4.new_markdown_cell("## Prepare and inspect safe URL data\n\nPhiUSIIL’s original `1 = legitimate` and `0 = phishing` convention is inverted once during preprocessing to ScaMail’s `0 = legitimate`, `1 = phishing` convention. The processed file retains only `url` and `label`."),
        nbf.v4.new_code_cell("urls, cleaning_report = prepare_url_dataset(save=True)\nprint(cleaning_report)\nprint('Shape:', urls.shape)\ndisplay(urls.head())\nprint('Missing values:\\n', urls.isna().sum())\nprint('Duplicate URLs:', urls.duplicated('url').sum())\nprint('Class distribution:\\n', urls.label.value_counts().rename(index={0: 'legitimate', 1: 'phishing'}))\nurls['url_length'] = urls.url.str.len()\nfig, axes = plt.subplots(1, 2, figsize=(12, 4))\nsns.countplot(data=urls, x='label', ax=axes[0]); axes[0].set_xticklabels(['legitimate', 'phishing'])\nsns.histplot(data=urls.sample(min(30000, len(urls)), random_state=42), x='url_length', hue='label', bins=50, element='step', ax=axes[1])\nplt.tight_layout()\ndisplay(urls.groupby('label').head(3)[['label', 'url']])"),
        nbf.v4.new_markdown_cell("## Offline feature engineering and domain-grouped evaluation\n\n`urllib.parse` and `tldextract` derive URL length, host structure, digits, HTTPS, path/query properties, suspicious words, punycode, and entropy without a network request. Public-suffix-aware registered domains are used as groups: the same registered domain cannot occur in more than one split. This is stricter than a random URL split, although it can shift the class balance because domains—not individual URLs—are assigned together."),
        nbf.v4.new_code_cell("result = train_url_model()\nprint('Candidates:', result['model_candidates'])\nprint(result['xgboost_reason'])\nprint('Split sizes:', result['split_sizes'])\nprint('Class distributions:', result['split_class_distributions'])\nprint('Shared registered domains:', result['shared_registered_domains'])\nprint('Validation metrics:')\ndisplay(pd.Series(result['validation_metrics']).drop(['classification_report', 'confusion_matrix']))\nprint('Held-out test metrics:')\ndisplay(pd.Series(result['test_metrics']).drop(['classification_report', 'confusion_matrix']))\nsns.heatmap(result['test_metrics']['confusion_matrix'], annot=True, fmt='d', cmap='Blues', xticklabels=['legitimate', 'phishing'], yticklabels=['legitimate', 'phishing'])\nplt.xlabel('Predicted'); plt.ylabel('Actual'); plt.show()\nprint(pd.DataFrame(result['test_metrics']['classification_report']).T)"),
        nbf.v4.new_markdown_cell("## Feature importance and error analysis\n\nRandom Forest importance indicates which engineered URL-string features the fitted model used most. Importance is association, not causation. Examine false positives (legitimate URLs flagged as phishing) and false negatives (phishing URLs missed) before changing a decision threshold."),
        nbf.v4.new_code_cell("importance = pd.Series(result['feature_importance']).sort_values()\nimportance.plot.barh(figsize=(8, 6), title='Random Forest feature importance')\nplt.show()\ndisplay(result['error_analysis']['false_positives'])\ndisplay(result['error_analysis']['false_negatives'])"),
        nbf.v4.new_markdown_cell("## Saved pipeline and inference\n\nThe persisted pipeline contains the URL feature transformer and fitted Random Forest. `predict_proba(...)[..., 1]` is the phishing probability; flags are derived directly from actual URL features."),
        nbf.v4.new_code_cell("from src.url_predictor import predict_url\nartifact = MODEL_DIR / 'saved_model' / 'url_phishing_pipeline.joblib'\nprint('Saved:', artifact, artifact.exists())\npredict_url('http://secure-login.verify-account.example/confirm?user=123')"),
    ])
    text_path, url_path = destination / "01_text_scam_classifier.ipynb", destination / "02_phishing_url_classifier.ipynb"
    nbf.write(text, text_path)
    nbf.write(url, url_path)
    return text_path, url_path


if __name__ == "__main__":
    print(*build_notebooks(), sep="\n")
