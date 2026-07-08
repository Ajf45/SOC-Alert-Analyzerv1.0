"""
Severity Engine
Assigns severity to each detected alert.
"""

SEVERITY_MAP = {
    "None": "Low",

    "Failed Login": "Low",

    "Brute Force": "High",

    "PowerShell Execution": "High",

    "Remote Desktop Login": "Medium",

    "USB Device Connected": "Medium",

    "Antivirus Disabled": "Critical",

    "Admin Login": "Low",

    "Suspicious IP": "High",

    "Port Scan": "Medium"
}


def assign_severity(df):
    """
    Assign severity to every alert.
    """

    df = df.copy()

    df["Severity"] = df["Alert"].map(SEVERITY_MAP)

    df["Severity"] = df["Severity"].fillna("Low")

    return df