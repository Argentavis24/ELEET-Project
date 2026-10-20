from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Dict, Any

@dataclass
class AlertCandidate:
    rule_name: str
    severity: str  # Low, Medium, High, Critical
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    evidence: str
    explanation: str
    recommended_action: str
    classification: str
    risk_score: float

class BaseRule(ABC):
    def __init__(self, name: str, default_severity: str = "Medium"):
        self.name = name
        self.default_severity = default_severity

    @abstractmethod
    def evaluate(self, flow: Any, window: Any, current_timestamp: float) -> Optional[AlertCandidate]:
        """
        Evaluate flow against rule using current sliding window.
        Returns AlertCandidate if violation is detected, None otherwise.
        """
        pass
