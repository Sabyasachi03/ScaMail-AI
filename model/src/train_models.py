"""Reproducible classical-ML training routines used by the teaching notebooks."""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, classification_report,
                             confusion_matrix, precision_recall_fscore_support)
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.naive_bayes import ComplementNB
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.svm import LinearSVC

from .data_preparation import MODEL_DIR
from .url_features import FEATURE_COLUMNS, URLFeatureTransformer, registered_domain

RANDOM_SEED = 42
PROCESSED_DIR = MODEL_DIR / "data" / "processed"
SAVED_DIR = MODEL_DIR / "saved_model"


def _metrics(y_true, probabilities, threshold: float = 0.5) -> dict:
    prediction = (np.asarray(probabilities) >= threshold).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, prediction, pos_label=1, average="binary", zero_division=0)
    return {
        "accuracy": round(float(accuracy_score(y_true, prediction)), 6),
        "precision_scam_or_phishing": round(float(precision), 6),
        "recall_scam_or_phishing": round(float(recall), 6),
        "f1_scam_or_phishing": round(float(f1), 6),
        "pr_auc": round(float(average_precision_score(y_true, probabilities)), 6),
        "confusion_matrix": confusion_matrix(y_true, prediction, labels=[0, 1]).tolist(),
        "classification_report": classification_report(y_true, prediction, labels=[0, 1], target_names=["legitimate", "malicious"], zero_division=0, output_dict=True),
    }


def _text_features() -> FeatureUnion:
    """Required word and character TF-IDF features, both fitted inside the pipeline."""
    return FeatureUnion([
        ("word_tfidf", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
        ("char_tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=2, sublinear_tf=True)),
    ])


def _text_pipeline(classifier) -> Pipeline:
    return Pipeline([("features", _text_features()), ("classifier", classifier)])


def _overlap_count(*series: pd.Series) -> int:
    sets = [set(values.astype(str)) for values in series]
    return len(set.intersection(*sets)) if sets else 0


def train_text_model() -> dict:
    """Select on validation F1, retrain without test data, evaluate once, and save."""
    frame = pd.read_csv(PROCESSED_DIR / "combined_sms.csv")
    X, y = frame["text"].astype(str), frame["label"].astype(int)
    X_trainval, X_test, y_trainval, y_test = train_test_split(X, y, test_size=0.20, random_state=RANDOM_SEED, stratify=y)
    X_train, X_val, y_train, y_val = train_test_split(X_trainval, y_trainval, test_size=0.25, random_state=RANDOM_SEED, stratify=y_trainval)
    candidates = {
        "ComplementNB": _text_pipeline(ComplementNB(alpha=0.25)),
        "LogisticRegression": _text_pipeline(LogisticRegression(C=3.0, class_weight="balanced", max_iter=2000, random_state=RANDOM_SEED)),
        "CalibratedLinearSVC": _text_pipeline(CalibratedClassifierCV(LinearSVC(class_weight="balanced", random_state=RANDOM_SEED), method="sigmoid", cv=3)),
    }
    validation = {}
    for name, pipeline in candidates.items():
        pipeline.fit(X_train, y_train)
        validation[name] = _metrics(y_val, pipeline.predict_proba(X_val)[:, 1])
    # F1 prioritizes the malicious class. PR-AUC breaks an exact tie.
    selected_name = max(validation, key=lambda name: (validation[name]["f1_scam_or_phishing"], validation[name]["pr_auc"]))
    selected = clone(candidates[selected_name]).fit(X_trainval, y_trainval)
    test_probabilities = selected.predict_proba(X_test)[:, 1]
    test_metrics = _metrics(y_test, test_probabilities)
    test_predictions = (test_probabilities >= 0.5).astype(int)
    result_frame = pd.DataFrame({"text": X_test.to_numpy(), "actual": y_test.to_numpy(), "prediction": test_predictions, "probability": test_probabilities})
    fp = result_frame[(result_frame.actual == 0) & (result_frame.prediction == 1)]
    fn = result_frame[(result_frame.actual == 1) & (result_frame.prediction == 0)]
    bank_or_otp = fp[fp.text.str.contains(r"bank|otp|transaction|account", case=False, regex=True, na=False)].head(5)
    details = {
        "seed": RANDOM_SEED,
        "split_sizes": {"train": len(X_train), "validation": len(X_val), "test": len(X_test)},
        "duplicate_messages_across_train_validation_test": {
            "train_validation": _overlap_count(X_train, X_val), "train_test": _overlap_count(X_train, X_test), "validation_test": _overlap_count(X_val, X_test),
        },
        "validation_metrics": validation,
        "selected_model": selected_name,
        "test_metrics": test_metrics,
    }
    SAVED_DIR.mkdir(exist_ok=True)
    joblib.dump(selected, SAVED_DIR / "text_scam_pipeline.joblib")
    (SAVED_DIR / "text_metrics.json").write_text(json.dumps(details, indent=2), encoding="utf-8")
    return {**details, "pipeline": selected, "error_analysis": {"bank_or_otp_false_positives": bank_or_otp, "all_false_negatives": fn.head(10)}}


def _group_split(X, y, groups, test_size):
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=RANDOM_SEED)
    train_index, test_index = next(splitter.split(X, y, groups=groups))
    return train_index, test_index


def train_url_model() -> dict:
    """Train a domain-grouped, offline-feature Random Forest and save its pipeline."""
    frame = pd.read_csv(PROCESSED_DIR / "cleaned_urls.csv")
    X, y = frame["url"].astype(str).reset_index(drop=True), frame["label"].astype(int).reset_index(drop=True)
    groups = X.map(registered_domain)
    trainval_index, test_index = _group_split(X, y, groups, test_size=0.20)
    trainval_groups = groups.iloc[trainval_index]
    train_index_relative, val_index_relative = _group_split(X.iloc[trainval_index], y.iloc[trainval_index], trainval_groups, test_size=0.25)
    train_index, val_index = trainval_index[train_index_relative], trainval_index[val_index_relative]
    classifier = RandomForestClassifier(
        n_estimators=250, min_samples_leaf=2, max_features="sqrt", class_weight="balanced_subsample",
        n_jobs=-1, random_state=RANDOM_SEED,
    )
    pipeline = Pipeline([("url_features", URLFeatureTransformer()), ("classifier", classifier)])
    pipeline.fit(X.iloc[train_index], y.iloc[train_index])
    validation_metrics = _metrics(y.iloc[val_index], pipeline.predict_proba(X.iloc[val_index])[:, 1])
    # Hyperparameters are fixed before test evaluation; validation is recorded for transparent selection.
    final_pipeline = clone(pipeline).fit(X.iloc[trainval_index], y.iloc[trainval_index])
    test_probabilities = final_pipeline.predict_proba(X.iloc[test_index])[:, 1]
    test_metrics = _metrics(y.iloc[test_index], test_probabilities)
    test_predictions = (test_probabilities >= 0.5).astype(int)
    result_frame = pd.DataFrame({"url": X.iloc[test_index].to_numpy(), "actual": y.iloc[test_index].to_numpy(), "prediction": test_predictions, "probability": test_probabilities})
    false_positive = result_frame[(result_frame.actual == 0) & (result_frame.prediction == 1)].head(10)
    false_negative = result_frame[(result_frame.actual == 1) & (result_frame.prediction == 0)].head(10)
    importances = dict(sorted(zip(FEATURE_COLUMNS, final_pipeline.named_steps["classifier"].feature_importances_), key=lambda item: item[1], reverse=True))
    group_sets = {"train": set(groups.iloc[train_index]), "validation": set(groups.iloc[val_index]), "test": set(groups.iloc[test_index])}
    details = {
        "seed": RANDOM_SEED,
        "model_candidates": ["RandomForestClassifier"],
        "xgboost_used": False,
        "xgboost_reason": "xgboost was not installed; RandomForestClassifier is the selected documented baseline.",
        "split_sizes": {"train": len(train_index), "validation": len(val_index), "test": len(test_index)},
        "split_class_distributions": {name: {str(k): int(v) for k, v in y.iloc[idx].value_counts().items()} for name, idx in {"train": train_index, "validation": val_index, "test": test_index}.items()},
        "shared_registered_domains": {
            "train_validation": len(group_sets["train"] & group_sets["validation"]),
            "train_test": len(group_sets["train"] & group_sets["test"]),
            "validation_test": len(group_sets["validation"] & group_sets["test"]),
        },
        "validation_metrics": validation_metrics,
        "test_metrics": test_metrics,
        "feature_importance": {key: round(float(value), 6) for key, value in importances.items()},
    }
    SAVED_DIR.mkdir(exist_ok=True)
    joblib.dump(final_pipeline, SAVED_DIR / "url_phishing_pipeline.joblib")
    (SAVED_DIR / "url_metrics.json").write_text(json.dumps(details, indent=2), encoding="utf-8")
    return {**details, "pipeline": final_pipeline, "error_analysis": {"false_positives": false_positive, "false_negatives": false_negative}}
