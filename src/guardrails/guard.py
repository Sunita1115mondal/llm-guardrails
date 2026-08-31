"""The guard pipeline: scan input (block/redact) and scan output (redact/block).

One `Guard` runs all detectors against a Policy and returns an explainable verdict —
what fired, what action was taken, and the redacted text.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from . import injection, pii, secrets, toxicity
from .config import Policy


@dataclass
class Verdict:
    action: str                       # "allow" | "redact" | "block"
    text: str                         # original or redacted text
    reasons: list[str] = field(default_factory=list)
    detections: dict = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.action != "block"

    def to_dict(self) -> dict:
        return {**asdict(self), "allowed": self.allowed}


class Guard:
    def __init__(self, policy: Policy | None = None):
        self.policy = policy or Policy.default()
    def _toxicity(self, text: str) -> dict:
        return toxicity.llm_judge(text) if self.policy.use_llm_toxicity else toxicity.score(text)

    def scan_input(self, text: str) -> Verdict:
        """User prompt → block on injection/toxicity/banned-topic/secret; redact PII."""
        p = self.policy
        reasons: list[str] = []
        det: dict = {}
        out = text

        inj = injection.score(text)
        det["injection"] = inj
        if "injection" in p.categories and inj["score"] >= p.injection_threshold:
            reasons.append(f"prompt_injection({','.join(inj['signals'])})")
            return Verdict("block", text, reasons, det)

        tox = self._toxicity(text)
        det["toxicity"] = tox
        if "toxicity" in p.categories and (tox["flagged"] or tox["score"] >= p.toxicity_threshold):
            reasons.append("toxicity" + (f":{tox.get('banned_topics')}" if tox.get("banned_topics") else ""))
            return Verdict("block", text, reasons, det)

        sec = secrets.detect(text)
        det["secrets"] = sec
        if "secrets" in p.categories and sec:
            if p.block_on_input_secret:
                reasons.append(
    f"secret({','.join(item.type for item in sec)})"
)
                return Verdict("block", text, reasons, det)
            out = secrets.redact(out)
            reasons.append("secret_redacted")

        spans = pii.detect(out)
        det["pii"] = [s.type for s in spans]
        if "pii" in p.categories and spans and p.redact_pii:
            out = pii.redact(out, spans)
            reasons.append(f"pii_redacted({','.join(sorted({s.type for s in spans}))})")

        return Verdict("redact" if out != text else "allow", out, reasons, det)

    def scan_output(self, text: str) -> Verdict:
        """Model completion → redact PII + secrets; block toxic output."""
        p = self.policy
        reasons: list[str] = []
        det: dict = {}
        out = text

        tox = self._toxicity(text)
        det["toxicity"] = tox
        if "toxicity" in p.categories and (tox["flagged"] or tox["score"] >= p.toxicity_threshold):
            return Verdict("block", text, ["toxic_output"], det)

        if "secrets" in p.categories and secrets.detect(out):
            det["secrets"] = secrets.detect(out)
            out = secrets.redact(out)
            reasons.append("secret_redacted")

        spans = pii.detect(out)
        det["pii"] = [s.type for s in spans]
        if "pii" in p.categories and spans and p.redact_pii:
            out = pii.redact(out, spans)
            reasons.append(f"pii_redacted({','.join(sorted({s.type for s in spans}))})")

        return Verdict("redact" if out != text else "allow", out, reasons, det)
