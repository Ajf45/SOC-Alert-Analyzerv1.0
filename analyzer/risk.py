"""
Risk Score Engine
Calculates the overall security risk score.
"""


SEVERITY_WEIGHTS = {
    "Critical": 10,
    "High": 7,
    "Medium": 5,
    "Low": 2
}


def calculate_risk(df):
    """
    Calculate the overall SOC risk score.
    """

    df = df.copy()

    # Assign numerical weight to each severity
    weights = df["Severity"].map(SEVERITY_WEIGHTS).fillna(0)

    total_score = weights.sum()

    max_score = len(df) * 10

    if max_score == 0:
        risk_percentage = 0
    else:
        risk_percentage = round(
            (total_score / max_score) * 100,
            2
        )

    if risk_percentage >= 80:
        risk_level = "Critical"

    elif risk_percentage >= 60:
        risk_level = "High"

    elif risk_percentage >= 40:
        risk_level = "Medium"

    else:
        risk_level = "Low"

    return {

        "score": risk_percentage,

        "level": risk_level,

        "critical": len(df[df["Severity"] == "Critical"]),

        "high": len(df[df["Severity"] == "High"]),

        "medium": len(df[df["Severity"] == "Medium"]),

        "low": len(df[df["Severity"] == "Low"])
    }