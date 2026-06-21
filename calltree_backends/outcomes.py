"""Shared success/failure string heuristics.

These are semantic anchors, not authorization logic: they help both native and
managed frontends identify likely success/failure sides before falling back to
structural dominance/reachability.
"""
WIN_WORDS=["correct","granted","welcome","success","unlocked","accepted",
           "licensed","thank you","notes","access granted"]
LOSE_WORDS=["wrong","denied","invalid","incorrect","not correct","not valid",
            "fail","failed","nope","unregistered","unlicensed",
            "not registered","try again","bad "]

def classify_strings(strings):
    wins=[]; loses=[]; other=[]
    for st in strings:
        low=(st or "").lower()
        # Negative phrases win precedence: "not correct" must not become win-ish.
        if any(w in low for w in LOSE_WORDS): loses.append(st)
        elif any(w in low for w in WIN_WORDS): wins.append(st)
        else: other.append(st)
    return wins,loses,other
