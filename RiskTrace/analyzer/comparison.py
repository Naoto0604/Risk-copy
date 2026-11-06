def get_finding_key(finding):
    """
    Findingを比較するためのキーを作成する
    """

    return (
     finding.get("type"),
     finding.get("subtype", ""),
     finding.get("url"),
     finding.get("title")   
    )


def compare_findings(before_findings, after_findings):
    """
    Before / AfterのFindingを比較する
    """

    before_map = {
        get_finding_key(finding): finding
        for finding in before_findings
    }

    after_map = {
        get_finding_key(finding): finding
        for finding in after_findings
    }
    before_keys = set(before_map.keys())
    after_keys = set(after_map.keys())
    removed = [
        before_map[key]
        for key in before_keys - after_keys
    ]

    added = [
        after_map[key]
        for key in after_keys - before_keys
    ]

    common_keys = before_keys & after_keys

    severity_changed = []

    for key in common_keys:

        before = before_map[key]
        after = after_map[key]

        if before.get("severity") != after.get("severity"):
            severity_changed.append({
                "title": after.get("title"),
                "url": after.get("url"),
                "type": after.get("type"),
                "before_severity": before.get("severity"),
                "after_severity": after.get("severity")
            })
        
    return {
        "removed": removed,
            "added": added,
            "severity_changed": severity_changed,
            "before_count": len(before_findings),
            "after_count": len(after_findings)
        }