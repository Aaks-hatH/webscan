"""
reporting/differ.py — Compare two scan results and surface regressions/fixes.
"""
from config import SEVERITY_ORDER


class ReportDiffer:
    def __init__(self, findings_before: list[dict], findings_after: list[dict]):
        self.before = {_finding_key(f): f for f in findings_before}
        self.after  = {_finding_key(f): f for f in findings_after}

    def diff(self) -> dict:
        keys_before = set(self.before)
        keys_after  = set(self.after)

        new_keys      = keys_after - keys_before
        resolved_keys = keys_before - keys_after
        shared_keys   = keys_before & keys_after

        regression_count  = 0
        improvement_count = 0

        for key in shared_keys:
            sev_before = SEVERITY_ORDER.get(self.before[key]["severity"], 99)
            sev_after  = SEVERITY_ORDER.get(self.after[key]["severity"],  99)
            if sev_after < sev_before:    # lower SEVERITY_ORDER value = worse
                regression_count += 1
            elif sev_after > sev_before:
                improvement_count += 1

        return {
            "new_findings":       [self.after[k]  for k in sorted(new_keys)],
            "resolved_findings":  [self.before[k] for k in sorted(resolved_keys)],
            "unchanged_count":    len(shared_keys) - regression_count - improvement_count,
            "regression_count":   regression_count,
            "improvement_count":  improvement_count,
        }


def _finding_key(f: dict) -> str:
    return f"{f.get('vuln_type')}|{f.get('url')}|{f.get('param')}|{f.get('method')}"
