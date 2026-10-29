   def map_to_mitre(findings):
    """Return a list of dicts with the MITRE technique for every finding."""
    result = dummy_mitre()  # placeholder, so the whole app works from the first minute

    ### WRITE YOUR CODE BELOW THIS LINE ###
    # Start with an empty list so "no findings" returns [].
    result = []

    # Load the lookup table once, not once per finding.
    with open(MAP_PATH) as f:
        table = json.load(f)

    for finding in findings:
        # .get() returns None for unknown types instead of crashing.
        entry = table.get(finding.finding_type)
        if entry is None:
            continue  # skip unknown types

        result.append({
            "finding_title": finding.title,
            "id": entry["id"],
            "name": entry["name"],
            "tactic": entry["tactic"],
        })
    ### WRITE YOUR CODE ABOVE THIS LINE ###

    return result
