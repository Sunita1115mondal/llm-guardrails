
from pathlib import Path
import yaml

from guardrails import injection, pii, secrets, toxicity
from guardrails.config import Policy


ROOT = Path(__file__).resolve().parent
CASES_PATH = ROOT / "data" / "cases.yaml"

policy = Policy.default()

with CASES_PATH.open("r", encoding="utf-8") as f:
    cases = yaml.safe_load(f)["cases"]


for category in ("injection", "pii", "toxicity", "secrets"):
    print("\n" + "=" * 70)
    print(f"{category.upper()} MISSED CASES")
    print("=" * 70)

    label_key = "secret" if category == "secrets" else category

    for i, case in enumerate(cases, start=1):
        text = case["text"]
        expected = bool(case[label_key])

        if category == "injection":
            result = injection.score(text)
            predicted = result["score"] >= policy.injection_threshold

        elif category == "pii":
            result = pii.detect(text)
            predicted = bool(result)

        elif category == "toxicity":
            result = toxicity.score(text)
            predicted = result["flagged"] or (
                result["score"] >= policy.toxicity_threshold
            )

        else:
            result = secrets.detect(text)
            predicted = bool(result)

        if expected != predicted:
            print(f"\nCase #{i}")
            print(f"Expected : {expected}")
            print(f"Predicted: {predicted}")
            print(f"Text     : {text}")
            print(f"Detector : {result}")

