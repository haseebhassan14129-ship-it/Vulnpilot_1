r"""
risk.py - Give the whole log a risk level (low, medium, high, critical) and explain WHY.

WHO OWNS THIS: TODO
DIFFICULTY: medium
TIME ESTIMATE: 2 hours

WHAT GOES IN
    findings: list of Finding. Use finding.finding_type and finding.severity.

WHAT MUST COME OUT
    A RiskResult(level, score, reasons). score is a number from 0 to 100, level is one of
    "low", "medium", "high", "critical", and reasons is a list of plain sentences (one per rule that fired).
    Example for auth_attack.log:
    RiskResult(level="critical", score=95, reasons=["Brute force ended in a successful login (+50)",
               "Password spray from one IP (+25)", "Attempts with non-existent usernames (+10)", ...])
    For no findings: RiskResult("low", 0, ["No suspicious findings"]).
    The checker accepts your own point values as long as an attack scores high/critical,
    no findings score 0, and more findings never lower the score.

RULES
    - Do not rename the function(s).
    - Do not change the arguments.
    - Do not edit any other file.
    - Do not import anything except: nothing new (the imports already at the top are enough).
    - Write only between the two ### lines. Plain, simple Python. Comments that explain WHY are welcome.

HINTS
    1. Start with score = 0 and reasons = [].
    2. Suggested points: brute_force +50, password_spray +25, invalid_users +10 per finding.
    3. For each finding add its points and append a sentence to reasons, e.g. "Brute force ended in a successful login (+50)".
    4. Stop the score at 100:  if score > 100: score = 100
    5. Level: 70 or more critical, 40 or more high, 20 or more medium, otherwise low.
    6. If there are no findings, reasons = ["No suspicious findings"].

Your own check:  python checks/check_risk.py
"""

from vulnpilot.dummies import dummy_risk
from vulnpilot.models import RiskResult


def score_risk(findings):
    """Return a RiskResult with the level, the score and the reasons."""
    result = dummy_risk()  # placeholder, so the whole app works from the first minute

    ### WRITE YOUR CODE BELOW THIS LINE ###
    # Replace the placeholder by building your own `result` here, step by step.
    ### WRITE YOUR CODE ABOVE THIS LINE ###

    # Start with zero risk and an empty list of explanations.
    score = 0
    reasons = []

    # Give points for every suspicious finding.
    for finding in findings:
        if finding.finding_type == "brute_force":
            points = 50
            reason = "Brute force attack detected"
        elif finding.finding_type == "password_spray":
            points = 25
            reason = "Password spray attack detected"
        elif finding.finding_type == "invalid_users":
            points = 10
            reason = "Attempts with non-existent usernames detected"
        else:
            points = 5
            reason = "Other suspicious activity detected"

        # More serious findings receive additional points.
        if finding.severity == "critical":
            points += 20
        elif finding.severity == "high":
            points += 10
        elif finding.severity == "medium":
            points += 5

        score += points
        reasons.append(f"{reason} (+{points})")

    # If nothing suspicious was found, the risk is low.
    if not findings:
        result = RiskResult("low", 0, ["No suspicious findings"])
    else:
        # Keep the score within the allowed range of 0 to 100.
        if score > 100:
            score = 100

        # Convert the numeric score into a risk level.
        if score >= 70:
            level = "critical"
        elif score >= 40:
            level = "high"
        elif score >= 20:
            level = "medium"
        else:
            level = "low"

        result = RiskResult(level, score, reasons)

    return result


# ---------------------------------------------------------------------------
# WORKED EXAMPLE (a different, smaller job in the same style. Copy the pattern, not the task.)
# prices = {"pen": 2, "book": 10}
# total = 0
# notes = []
# for item in ["pen", "book", "pen"]:
#     cost = prices.get(item, 1)          # 1 if the item is unknown
#     total = total + cost
#     notes.append(f"{item} costs {cost}")
# if total >= 10:
#     size = "big"
# else:
#     size = "small"
# Same pattern: add up points per finding, remember why, then turn the total into a level.
#
# DONE WHEN
#   python checks/check_risk.py   prints PASS.
#   (Right now it prints STILL DUMMY. That is normal: you have not written your code yet.)
#   Then run  python checks/check_all.py  to see every module, and open a pull request.
