import os
from vulnpilot.dummies import dummy_report_text

def build_report(findings, indicators, timeline, mitre, risk, investigation):
    """Return the incident report as one markdown string."""
    
    ### WRITE YOUR CODE BELOW THIS LINE ###

    lines = ["# VulnPilot Incident Report", ""]

    # 1. AI Summary
    lines.append("## AI Summary")
    lines.append(str(investigation.summary))
    lines.append("")

    # 2. Confirmed Observations
    lines.append("## Confirmed Observations")
    for observation in investigation.confirmed:
        lines.append(f"- {observation}")
    lines.append("")

    # 3. Hypotheses
    lines.append("## Hypotheses")
    for hypothesis in investigation.hypotheses:
        lines.append(f"- {hypothesis}")
    lines.append("")

    # 4. Recommended Actions
    lines.append("## Recommended Actions")
    for action in investigation.actions:
        lines.append(f"- {action}")
    lines.append("")

    # 5. Findings Section
    lines.append("## Findings")
    for finding in findings:
        lines.append(f"### {finding.title}")
        lines.append("Evidence:")
        lines.append("```")
        for line in finding.evidence_lines:
            lines.append(line)
        lines.append("```")
        lines.append("")

    # 6. Indicators Section
    lines.append("## Indicators")
    for indicator in indicators:
        lines.append(f"- {indicator}")
    lines.append("")

    # 7. Timeline Section
    lines.append("## Timeline")
    for item in timeline:
        lines.append(f"- {item}")
    lines.append("")

    # 8. MITRE ATT&CK Section
    lines.append("## MITRE ATT&CK")
    for m in mitre:
        lines.append(f"- {m}")
    lines.append("")

    # 9. Risk Assessment
    lines.append("## Risk Assessment")
    lines.append(f"Level: {risk.level}")
    lines.append(f"Score: {risk.score}")
    lines.append("Reasons:")
    for reason in risk.reasons:
        lines.append(f"- {reason}")
    lines.append("")

    result = "\n".join(lines) + "\n"

    ### WRITE YOUR CODE ABOVE THIS LINE ###

    return result
