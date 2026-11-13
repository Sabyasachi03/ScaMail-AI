"""Rule engine that evaluates text messages and URLs against heuristic rules."""

from __future__ import annotations

import re
from typing import Optional, Dict, Any, List, Set

from .patterns import RULES, HIGHLIGHT_WORDS


class RuleEngine:
    """Evaluates text messages and URLs for explicit scam heuristics."""

    def __init__(self, custom_rules: Optional[List[Dict[str, Any]]] = None):
        self.rules = custom_rules if custom_rules is not None else RULES
        # Precompile regular expressions
        self._compiled_rules = []
        for r in self.rules:
            compiled_patterns = [
                re.compile(p, re.IGNORECASE) for p in r.get("patterns", [])
            ]
            self._compiled_rules.append({
                "id": r["id"],
                "category": r["category"],
                "severity": r["severity"],
                "weight": float(r.get("weight", 0.2)),
                "description": r.get("description", ""),
                "patterns": compiled_patterns,
            })

        self._highlight_regex = re.compile(
            r"\b(" + "|".join(re.escape(w) for w in HIGHLIGHT_WORDS) + r")\b",
            re.IGNORECASE,
        )

    def evaluate(self, text: Optional[str] = None, url: Optional[str] = None) -> Dict[str, Any]:
        """Run all heuristic rules against input text and/or URL.

        Returns a dictionary matching the RuleDetections schema.
        """
        combined_content = []
        if text and isinstance(text, str):
            combined_content.append(text)
        if url and isinstance(url, str):
            combined_content.append(url)

        content_to_scan = " ".join(combined_content).strip()
        if not content_to_scan:
            return {
                "triggered": False,
                "score_contribution": 0.0,
                "flags": [],
                "highlighted_terms": [],
                "has_critical": False,
            }

        matched_flags: List[Dict[str, Any]] = []
        highlighted_terms: Set[str] = set()
        total_weight = 0.0
        has_critical = False

        # 1. Evaluate heuristic rules
        for rule in self._compiled_rules:
            for pattern in rule["patterns"]:
                match = pattern.search(content_to_scan)
                if match:
                    matched_span = match.group(0).strip()
                    # Truncate overly long matched text for clean presentation
                    if len(matched_span) > 80:
                        matched_span = matched_span[:77] + "..."

                    matched_flags.append({
                        "category": rule["category"],
                        "rule": rule["id"],
                        "severity": rule["severity"],
                        "matched_text": matched_span,
                        "description": rule["description"],
                    })

                    total_weight += rule["weight"]
                    if rule["severity"] == "critical":
                        has_critical = True

                    # Add matched keywords to highlights
                    for token in re.findall(r"\b[A-Za-z]{3,}\b", matched_span):
                        if token.lower() in [w.lower() for w in HIGHLIGHT_WORDS]:
                            highlighted_terms.add(token)

                    # Once a rule fires on a pattern, proceed to next rule
                    break

        # 2. Extract standard keyword highlights from text
        for token_match in self._highlight_regex.finditer(content_to_scan):
            highlighted_terms.add(token_match.group(0))

        # Calculate rule penalty score normalized to 0.0 - 1.0 (capped at 1.0)
        # Using diminishing returns formula: 1 - product(1 - w)
        multiplied_prob = 1.0
        for flag in matched_flags:
            # find original weight
            w = next((r["weight"] for r in self._compiled_rules if r["id"] == flag["rule"]), 0.2)
            multiplied_prob *= (1.0 - w)

        rule_score = round(1.0 - multiplied_prob, 4) if matched_flags else 0.0

        return {
            "triggered": len(matched_flags) > 0,
            "score_contribution": round(rule_score * 100.0, 1),
            "raw_rule_score": rule_score,
            "flags": matched_flags,
            "highlighted_terms": sorted(list(highlighted_terms)),
            "has_critical": has_critical,
        }
