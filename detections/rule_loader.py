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
    collection = SigmaCollection.load_ruleset([config.RULES_DIR])
    specs: list[MatchSpec] = []
    for rule in collection.rules:
        spec = _to_match_spec(rule)
        print(f"\n--- {spec.name} ---")
        print(f"  level: {spec.level}")
        print(f"  condition: {spec.condition}")
        for dname, items in spec.selections.items():
            for field, mods, values in items:
                print(f"  [{dname}] field={field} mods={mods} values={values}")
        if spec.correlation:
            print(f"  correlation: {spec.correlation}")
        specs.append(spec)
    return specs

def _to_match_spec(rule) -> MatchSpec:
    name = str(rule.title)
    level = rule.level.name.lower()

    selections: dict = {}
    for dname, det in rule.detection.detections.items():
        items = []
        for item in det.detection_items:
            values = []
            for v in item.value:
                if hasattr(v, 'to_plain'):      # SigmaString
                    values.append(v.to_plain())
                elif hasattr(v, 'number'):      # SigmaNumber
                    values.append(v.number)
                else:
                    values.append(str(v))
            items.append((item.field, list(item.modifiers), values))
        selections[dname] = items

    condition = rule.detection.condition[0] if rule.detection.condition else "selection"

    correlation: Optional[CorrelationSpec] = None
    drishti = (rule.custom_attributes or {}).get('drishti')
    if drishti:
        correlation = CorrelationSpec(
            type=drishti.get('type', ''),
            group_by=drishti.get('group_by', ''),
            window_seconds=int(drishti.get('window_seconds', 0)),
            threshold=int(drishti.get('threshold', 1)),
            alert_title=drishti.get('alert_title', name),
            alert_level=drishti.get('alert_level', level),
        )

    return MatchSpec(
        name=name,
        level=level,
        selections=selections,
        condition=condition,
        correlation=correlation,
    )