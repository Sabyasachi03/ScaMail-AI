"""Verified loaders and preprocessing for the original ScaMail AI datasets."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

MODEL_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = MODEL_DIR / "data"
PROCESSED_DIR = DATA_DIR / "processed"
UCI_FILE = DATA_DIR / "sms+spam+collection" / "SMSSpamCollection"
URL_FILE = DATA_DIR / "phiusiil+phishing+url+dataset" / "PhiUSIIL_Phishing_URL_Dataset.csv"


def _distribution(frame: pd.DataFrame, column: str) -> dict[str, int]:
    return {str(key): int(value) for key, value in frame[column].value_counts(dropna=False).items()}


def load_uci_sms() -> pd.DataFrame:
    """Load UCI's headerless tab-delimited ham/spam corpus."""
    frame = pd.read_csv(UCI_FILE, sep="\t", header=None, names=["raw_label", "text"], dtype=str, encoding="utf-8")
    values = frame["raw_label"].str.strip().str.lower()
    unknown = set(values.dropna()) - {"ham", "spam"}
    if unknown:
        raise ValueError(f"Unexpected UCI labels: {sorted(unknown)}")
    return pd.DataFrame({"text": frame["text"], "label": values.map({"ham": 0, "spam": 1}), "source": "UCI"})


def _mendeley_zip() -> Path:
    matches = list(DATA_DIR.rglob("Dataset_5971.zip"))
    if len(matches) != 1:
        raise FileNotFoundError(f"Expected exactly one Dataset_5971.zip, found {len(matches)}")
    return matches[0]


def load_mendeley_sms() -> pd.DataFrame:
    """Load Mendeley's CSV directly from its supplied ZIP without altering it."""
    frame = pd.read_csv(_mendeley_zip(), compression="zip", dtype=str, encoding="utf-8")
    columns = {column.strip().lower(): column for column in frame.columns}
    if not {"label", "text"}.issubset(columns):
        raise ValueError(f"Mendeley CSV needs LABEL and TEXT; found {list(frame.columns)}")
    raw = frame[columns["label"]].str.strip().str.lower()
    mapping = {"ham": 0, "spam": 1, "smishing": 1, "phishing": 1}
    unknown = set(raw.dropna()) - set(mapping)
    if unknown:
        raise ValueError(f"Unexpected Mendeley labels: {sorted(unknown)}")
    return pd.DataFrame({"text": frame[columns["text"]], "label": raw.map(mapping), "source": "Mendeley"})


def prepare_sms_dataset(save: bool = True) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Combine SMS sources, remove empty messages and exact duplicate messages."""
    uci, mendeley = load_uci_sms(), load_mendeley_sms()
    combined = pd.concat([uci, mendeley], ignore_index=True)
    before = {"records": len(combined), "class_distribution": _distribution(combined, "label"),
              "by_source": _distribution(combined, "source")}
    cleaned = combined.copy()
    cleaned["text"] = cleaned["text"].fillna("").astype(str).str.strip()
    cleaned = cleaned.loc[cleaned["text"].ne("")].copy()
    cleaned = cleaned.drop_duplicates(subset=["text"], keep="first").reset_index(drop=True)
    cleaned["label"] = cleaned["label"].astype(int)
    after = {"records": len(cleaned), "class_distribution": _distribution(cleaned, "label"),
             "by_source": _distribution(cleaned, "source")}
    report = {"before_cleaning": before, "after_cleaning": after,
              "removed_empty": int(len(combined) - len(combined.dropna(subset=["text"]))),
              "removed_exact_duplicates_or_empty": int(len(combined) - len(cleaned))}
    if save:
        PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
        cleaned.to_csv(PROCESSED_DIR / "combined_sms.csv", index=False, encoding="utf-8")
    return cleaned, report


def load_phiusiil_urls() -> pd.DataFrame:
    """Read only PhiUSIIL raw URLs and map its 1=legitimate, 0=phishing labels."""
    frame = pd.read_csv(URL_FILE, encoding="utf-8-sig", usecols=["URL", "label"], dtype={"URL": str, "label": int})
    labels = set(frame["label"].dropna().unique())
    if labels != {0, 1}:
        raise ValueError(f"Expected PhiUSIIL labels {{0, 1}}, found {sorted(labels)}")
    # Dataset documentation convention: 1 legitimate, 0 phishing. Invert for ScaMail.
    return frame.rename(columns={"URL": "url"}).assign(label=lambda d: d["label"].map({1: 0, 0: 1}))


def prepare_url_dataset(save: bool = True) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Keep raw URL + ScaMail label, excluding all webpage-derived source columns."""
    raw = load_phiusiil_urls()
    before = {"records": len(raw), "class_distribution": _distribution(raw, "label")}
    cleaned = raw.copy()
    cleaned["url"] = cleaned["url"].fillna("").astype(str).str.strip()
    cleaned = cleaned.loc[cleaned["url"].ne("")].drop_duplicates("url", keep="first").reset_index(drop=True)
    cleaned["label"] = cleaned["label"].astype(int)
    report = {"before_cleaning": before,
              "after_cleaning": {"records": len(cleaned), "class_distribution": _distribution(cleaned, "label")},
              "removed_exact_duplicates_or_empty": int(len(raw) - len(cleaned)),
              "source_label_mapping": {"1": "legitimate -> 0", "0": "phishing -> 1"}}
    if save:
        PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
        cleaned.to_csv(PROCESSED_DIR / "cleaned_urls.csv", index=False, encoding="utf-8")
    return cleaned, report
