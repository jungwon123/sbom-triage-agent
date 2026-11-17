import json

import pytest
from pydantic import ValidationError

from triage import models


def test_agent_verdict_has_no_score_fields():
    fields = set(models.AgentVerdict.model_fields)
    assert not fields & {"risk", "risk_breakdown", "final_bucket", "rule_bucket", "effort"}


def test_extra_fields_rejected():
    with pytest.raises(ValidationError):
        models.AgentVerdict.model_validate({
            "reachability": "unknown", "proposed_bucket": "NOW", "override_reason": None, "rationale": ["a"],
            "risk": 99,
            "remediation": {"kind": "mitigation_only", "to_version": None, "mitigation": "x",
                            "breaking_risk": "low", "notes": None}})


def test_schema_exports():
    assert {"Finding", "Triage", "AgentVerdict"} <= set(json.loads(models.schema_json()))
