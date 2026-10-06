from __future__ import annotations

from src.models.schemas import RiskLevel


class RiskEngine:
    def __init__(self, policy: dict) -> None:
        self.policy = policy

    def score(
        self,
        risk: RiskLevel,
        *,
        suspicious: bool,
        mismatch: bool,
        escalation: bool,
        sequence: bool,
        untrusted_high_risk: bool,
    ) -> float:
        weights = self.policy["risk_weights"]
        signals = self.policy["signals"]
        value = float(weights[risk.value])
        value += signals["suspicious_instruction"] if suspicious else 0
        value += signals["intent_mismatch"] if mismatch else 0
        value += signals["privilege_escalation"] if escalation else 0
        value += signals["sequence_risk"] if sequence else 0
        value += signals["untrusted_high_risk"] if untrusted_high_risk else 0
        return min(1.0, round(value, 3))

