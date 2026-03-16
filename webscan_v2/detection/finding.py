"""detection/finding.py"""
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Finding:
    vuln_type:           str
    severity:            str
    url:                 str
    param:               str
    method:              str
    request_example:     str = ""
    response_indicator:  str = ""
    evidence_snippet:    str = ""
    description:         str = ""
    mitigation:          str = ""
    cwe:                 Optional[str]   = None
    cvss_score:          Optional[float] = None
    confidence:          str = "MEDIUM"

    def to_dict(self) -> dict:
        return asdict(self)
