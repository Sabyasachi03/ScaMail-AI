"""Offline, URL-string-only feature extraction for phishing detection."""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from typing import Iterable
from urllib.parse import parse_qsl, urlparse

import numpy as np
import pandas as pd
import tldextract
from sklearn.base import BaseEstimator, TransformerMixin

# Bundled suffix data is used; this disables any network fetch of the PSL.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
SUSPICIOUS_KEYWORDS = ("login", "verify", "update", "account", "refund", "kyc", "secure")
FEATURE_COLUMNS = [
    "url_length", "domain_length", "dot_count", "hyphen_count", "underscore_count",
    "digit_count", "digit_ratio", "subdomain_count", "has_at", "has_ip_host",
    "is_https", "path_length", "query_param_count", "suspicious_keyword_count",
    "has_punycode", "url_entropy",
]


def _parse(value: object):
    """Parse a URL safely, accepting a scheme-less user entry as a host."""
    raw = "" if value is None else str(value).strip()
    candidate = raw if "://" in raw else f"//{raw}"
    try:
        parsed = urlparse(candidate, scheme="", allow_fragments=True)
        host = parsed.hostname or ""
    except (TypeError, ValueError):
        parsed, host = urlparse(""), ""
    return raw, parsed, host.lower()


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    size = len(value)
    return float(-sum((count / size) * math.log2(count / size) for count in Counter(value).values()))


def _is_ip(host: str) -> int:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return 1
    except ValueError:
        return 0


def extract_url_feature_dict(value: object) -> dict[str, float]:
    """Return deterministic features derived solely from one URL string."""
    raw, parsed, host = _parse(value)
    domain = _EXTRACT(host)
    registered = ".".join(part for part in (domain.domain, domain.suffix) if part)
    # tldextract's subdomain is public-suffix aware and excludes the registered domain.
    subdomains = len([part for part in domain.subdomain.split(".") if part])
    lower = raw.lower()
    digit_count = sum(char.isdigit() for char in raw)
    return {
        "url_length": len(raw),
        "domain_length": len(host),
        "dot_count": raw.count("."),
        "hyphen_count": raw.count("-"),
        "underscore_count": raw.count("_"),
        "digit_count": digit_count,
        "digit_ratio": digit_count / len(raw) if raw else 0.0,
        "subdomain_count": subdomains,
        "has_at": int("@" in raw),
        "has_ip_host": _is_ip(host),
        "is_https": int(parsed.scheme.lower() == "https"),
        "path_length": len(parsed.path or ""),
        "query_param_count": len(parse_qsl(parsed.query, keep_blank_values=True)),
        "suspicious_keyword_count": sum(keyword in lower for keyword in SUSPICIOUS_KEYWORDS),
        "has_punycode": int("xn--" in host),
        "url_entropy": _entropy(raw),
    }


def extract_url_features(values: Iterable[object]) -> pd.DataFrame:
    """Extract the fixed, model-ready feature table with no network access."""
    rows = [extract_url_feature_dict(value) for value in values]
    return pd.DataFrame(rows, columns=FEATURE_COLUMNS).astype(float)


def registered_domain(value: object) -> str:
    """Return a public-suffix-aware grouping key for leakage-resistant splits."""
    _, _, host = _parse(value)
    extracted = _EXTRACT(host)
    result = ".".join(part for part in (extracted.domain, extracted.suffix) if part)
    return result or host or "__invalid_or_empty__"


def url_flags(value: object) -> list[str]:
    """Human-readable flags grounded in the same offline features as the model."""
    f = extract_url_feature_dict(value)
    flags: list[str] = []
    if f["url_length"] >= 75:
        flags.append("long_url")
    if f["suspicious_keyword_count"]:
        flags.append("suspicious_keywords")
    if f["has_ip_host"]:
        flags.append("ip_address_host")
    if f["has_at"]:
        flags.append("at_symbol")
    if f["has_punycode"]:
        flags.append("punycode")
    if f["subdomain_count"] >= 3:
        flags.append("many_subdomains")
    if not f["is_https"]:
        flags.append("not_https")
    return flags


class URLFeatureTransformer(BaseEstimator, TransformerMixin):
    """scikit-learn transformer that converts raw URL strings into numeric features."""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        if isinstance(X, pd.DataFrame):
            X = X.iloc[:, 0]
        if isinstance(X, str):
            X = [X]
        return extract_url_features(X).to_numpy(dtype=np.float64)
