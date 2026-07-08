import pandas as pd


# Example suspicious public IPs
SUSPICIOUS_IPS = {
    "203.0.113.10",
    "198.51.100.20",
    "45.33.32.156",
    "185.220.101.1"
}


def detect_alerts(df):
    """
    Apply rule-based detections to log data.
    """

    df = df.copy()

    df["Alert"] = "None"
    df["Severity"] = "Pending"
    df["Status"] = "Normal"
    df["Description"] = ""

    # ----------------------------------------
    # Rule 1 : Failed Login
    # ----------------------------------------

    failed_login_count = {}

    for index, row in df.iterrows():

        event = str(row["Event"]).lower()
        user = str(row["User"])

        if "failed login" in event:

            failed_login_count[user] = failed_login_count.get(user, 0) + 1

            df.at[index, "Alert"] = "Failed Login"
            df.at[index, "Status"] = "Detected"
            df.at[index, "Description"] = "User authentication failed."

    # ----------------------------------------
    # Rule 2 : Brute Force
    # ----------------------------------------

    for user, count in failed_login_count.items():

        if count >= 5:

            mask = (
                (df["User"] == user) &
                (df["Alert"] == "Failed Login")
            )

            df.loc[mask, "Alert"] = "Brute Force"

            df.loc[mask, "Description"] = (
                f"{count} failed login attempts detected."
            )

    # ----------------------------------------
    # Rule 3 : PowerShell
    # ----------------------------------------

    mask = df["Event"].str.contains(
        "powershell",
        case=False,
        na=False
    )

    df.loc[mask, "Alert"] = "PowerShell Execution"
    df.loc[mask, "Status"] = "Detected"
    df.loc[mask, "Description"] = (
        "PowerShell executed on host."
    )

    # ----------------------------------------
    # Rule 4 : RDP Login
    # ----------------------------------------

    mask = df["Event"].str.contains(
        "rdp",
        case=False,
        na=False
    )

    df.loc[mask, "Alert"] = "Remote Desktop Login"
    df.loc[mask, "Status"] = "Detected"
    df.loc[mask, "Description"] = (
        "Remote Desktop connection detected."
    )

    # ----------------------------------------
    # Rule 5 : USB
    # ----------------------------------------

    mask = df["Event"].str.contains(
        "usb",
        case=False,
        na=False
    )

    df.loc[mask, "Alert"] = "USB Device Connected"
    df.loc[mask, "Status"] = "Detected"
    df.loc[mask, "Description"] = (
        "USB device inserted."
    )

    # ----------------------------------------
    # Rule 6 : Antivirus Disabled
    # ----------------------------------------

    mask = df["Event"].str.contains(
        "antivirus disabled",
        case=False,
        na=False
    )

    df.loc[mask, "Alert"] = "Antivirus Disabled"
    df.loc[mask, "Status"] = "Detected"
    df.loc[mask, "Description"] = (
        "Endpoint protection disabled."
    )

    # ----------------------------------------
    # Rule 7 : Admin Login
    # ----------------------------------------

    mask = df["Event"].str.contains(
        "admin login",
        case=False,
        na=False
    )

    df.loc[mask, "Alert"] = "Admin Login"
    df.loc[mask, "Status"] = "Detected"
    df.loc[mask, "Description"] = (
        "Administrator account login."
    )

    # ----------------------------------------
    # Rule 8 : Suspicious IP
    # ----------------------------------------

    mask = df["SourceIP"].astype(str).isin(SUSPICIOUS_IPS)

    df.loc[mask, "Alert"] = "Suspicious IP"
    df.loc[mask, "Status"] = "Detected"
    df.loc[mask, "Description"] = (
        "Known suspicious source IP."
    )

    # ----------------------------------------
    # Rule 9 : Port Scan
    # ----------------------------------------

    mask = df["Event"].str.contains(
        "port scan",
        case=False,
        na=False
    )

    df.loc[mask, "Alert"] = "Port Scan"
    df.loc[mask, "Status"] = "Detected"
    df.loc[mask, "Description"] = (
        "Possible port scanning activity."
    )

    return df