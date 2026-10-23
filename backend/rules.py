"""Business rules, kept free of Flask/DB code so they are easy to read and test."""

CATEGORIES = ["Laptop", "Mobile Phone", "Television", "Computer", "Other"]
CONDITIONS = ["working", "partially_working", "non_working"]

# The rule-based recommendation from the prototype (AI intentionally excluded).
RECOMMENDATIONS = {
    "working": "Reuse / Donate",
    "partially_working": "Repair / Refurbish",
    "non_working": "Recycle",
}
MANUAL_REVIEW = "Manual Review"
SPECIALIZED = "Specialized Handling"  # from the E-Waste Guide: damaged/swollen battery


def recommend(condition: str, battery_damaged: bool = False) -> str:
    """Safety first: a damaged battery overrides every condition-based rule."""
    if battery_damaged:
        return SPECIALIZED
    return RECOMMENDATIONS.get(condition, MANUAL_REVIEW)


# Strictly linear lifecycle. Order matters: a status may only move to the next one.
STATUS_FLOW = ["SUBMITTED", "VERIFIED", "COLLECTION_SCHEDULED", "COLLECTED", "PROCESSED"]

STAGES = {
    "SUBMITTED": ("Submitted", "Request received by E-Cycle."),
    "VERIFIED": ("Verified", "Device details reviewed."),
    "COLLECTION_SCHEDULED": ("Collection Scheduled", "Collection has been scheduled."),
    "COLLECTED": ("Collected", "Device has been collected."),
    "PROCESSED": ("Processed", "Final processing has been recorded."),
}


def next_status(current: str):
    i = STATUS_FLOW.index(current)
    return STATUS_FLOW[i + 1] if i + 1 < len(STATUS_FLOW) else None
