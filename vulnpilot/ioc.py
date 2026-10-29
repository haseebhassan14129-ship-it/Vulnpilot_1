    ### WRITE YOUR CODE BELOW THIS LINE ###
    # Start from an empty list so no dummy data leaks into the real answer.
    result = []

    # Step 1: collect every evidence line from every finding, without duplicates.
    # The same line can show up in several findings, but we only want to count
    # it once ("how many DIFFERENT evidence lines mention it").
    lines = []
    for finding in findings:
        for line in finding.evidence_lines:
            if line not in lines:
                lines.append(line)

    # Step 2: count IPs, once per line.
    ip_pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
    ip_counts = {}
    for line in lines:
        # set() so an IP that appears twice in one line is still counted once
        for ip in set(re.findall(ip_pattern, line)):
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    # Step 3: count usernames. finding.users tells us who was involved, so we
    # check which evidence lines mention each name instead of guessing with regex.
    all_users = []
    for finding in findings:
        for user in finding.users:
            if user not in all_users:
                all_users.append(user)

    user_counts = {}
    for user in all_users:
        count = 0
        for line in lines:
            # \b so "admin" does not match inside "administrator"
            if re.search(r"\b" + re.escape(user) + r"\b", line):
                count += 1
        user_counts[user] = count

    # Step 4: turn the counts into Indicator objects (IPs first, then users).
    for ip, count in ip_counts.items():
        result.append(Indicator("ip", ip, count))
    for user, count in user_counts.items():
        result.append(Indicator("user", user, count))
    ### WRITE YOUR CODE ABOVE THIS LINE ###
