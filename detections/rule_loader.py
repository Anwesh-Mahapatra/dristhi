# detections/rule_loader.py
from dataclasses import dataclass, field
from typing import Optional
import yaml
from sigma.collection import SigmaCollection   # [GIVEN] pySigma parse entrypoint

from . import config

@dataclass
class CorrelationSpec:
    type: str
    group_by: str
    window_seconds: int
    threshold: int
    alert_title: str
    alert_level: str

@dataclass
class MatchSpec:
    """Engine-internal, evaluation-ready form of a rule. YOU define exactly what matcher.py needs."""
    name: str
    level: str
    # TODO: design these to match how matcher.py wants to consume them, e.g.:
    selections: dict = field(default_factory=dict)   # name -> list[ (field, modifiers, values) ]
    condition: str = "selection"
    correlation: Optional[CorrelationSpec] = None

def load_rules() -> list[MatchSpec]:
    # [GIVEN] pySigma parses the whole directory into SigmaRule objects.
    collection = SigmaCollection.load_ruleset([config.RULES_DIR])   # recursion_pattern defaults to **/*.yml
    specs: list[MatchSpec] = []
    for rule in collection.rules:
        specs.append(_to_match_spec(rule))
    return specs

def _to_match_spec(rule) -> MatchSpec:
    """[YOURS] Translate a parsed pySigma SigmaRule into your MatchSpec.

    Introspect the parsed structure FIRST so you map the right attributes for your version:
        print(type(rule), rule.title, rule.level)
        print(rule.detection.detections)   # dict: name -> SigmaDetection
        print(rule.detection.condition)    # list of condition strings
        for det in rule.detection.detections.values():
            for item in det.detection_items:
                print(item.field, item.modifiers, item.value)
        print(getattr(rule, "custom_attributes", None))   # your drishti: block lives here (verify)

    TODO:
      1. name  = str(rule.title)
      2. level = str(rule.level)  (SigmaLevel enum -> str; map to your severity vocabulary)
      3. selections: walk rule.detection.detections; for each detection item capture
         (field, modifiers, values). Normalize values to a list.
      4. condition: take rule.detection.condition[0] for the Phase-1 subset.
      5. correlation: if the drishti block is present, build CorrelationSpec.
         Parse window "5m"/"30s"/"1h" -> seconds with a tiny helper.
         If custom_attributes is empty on your version, re-read the raw YAML with
         yaml.safe_load(open(path)) keyed by rule id/title to recover the block.
    """
    raise NotImplementedError