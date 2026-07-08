from collections import Counter


def prepare_report_data(df, risk):

    severity = (
        df["Severity"]
        .value_counts()
        .to_dict()
    )

    alerts = (
        df["Alert"]
        .value_counts()
        .to_dict()
    )

    top_ips = (
        df["SourceIP"]
        .value_counts()
        .head(10)
        .to_dict()
    )

    top_users = (
        df["User"]
        .value_counts()
        .head(10)
        .to_dict()
    )

    mitre = (
        df[df["MITRE ID"] != ""]
        [["MITRE ID", "Technique", "Tactic"]]
        .drop_duplicates()
        .sort_values(by="MITRE ID")
        .to_dict("records")
    )

    iocs = {

        "ips": sorted(
            df["SourceIP"]
            .dropna()
            .astype(str)
            .unique()
            .tolist()
        ),

        "users": sorted(
            df["User"]
            .dropna()
            .astype(str)
            .unique()
            .tolist()
        ),

        "alerts": sorted(
            df[df["Alert"] != "None"]["Alert"]
            .dropna()
            .unique()
            .tolist()
        ),

        "techniques": sorted(
            df[df["Technique"] != ""]["Technique"]
            .dropna()
            .unique()
            .tolist()
        )

    }

    recommendations = []

    alerts_present = set(
        df[df["Alert"] != "None"]["Alert"]
    )

# -----------------------------
# Alert-specific recommendations
# -----------------------------

    if "Brute Force" in alerts_present:
        recommendations.append(
            "Enable Multi-Factor Authentication (MFA) and configure account lockout policies to reduce brute-force attack success."
        )

    if "Failed Login" in alerts_present:
        recommendations.append(
            "Review authentication logs for repeated failed login attempts and investigate affected user accounts."
        )
 
    if "PowerShell Execution" in alerts_present:
        recommendations.append(
            "Enable PowerShell Script Block Logging and review suspicious PowerShell execution for malicious activity."
        )

    if "RDP Login" in alerts_present:
        recommendations.append(
            "Restrict Remote Desktop Protocol (RDP) access using firewalls, VPNs, and Network Level Authentication (NLA)."
        )

    if "USB Device Connected" in alerts_present:
        recommendations.append(
            "Review removable media usage and enforce USB device control policies where appropriate."
     )

    if "Antivirus Disabled" in alerts_present:
        recommendations.append(
            "Immediately verify endpoint protection status and re-enable antivirus or endpoint detection software."
        )

    if "Admin Login" in alerts_present:
        recommendations.append(
            "Review privileged account activity and verify that administrator logins are authorized."
       )

    if "Suspicious IP" in alerts_present:
        recommendations.append(
            "Investigate suspicious IP addresses and block confirmed malicious sources at the firewall."
        )

    if "Port Scan" in alerts_present:
        recommendations.append(
            "Investigate possible reconnaissance activity and restrict unnecessary exposed services."
        )

# -----------------------------
# Risk-level recommendations
# -----------------------------

    if risk["level"] == "Critical":

        recommendations.append(
            "Initiate the incident response process immediately and isolate affected systems."
       )

    elif risk["level"] == "High":

        recommendations.append(
            "Prioritize investigation of high-severity alerts within the SOC queue."
        )

    elif risk["level"] == "Medium":

        recommendations.append(
            "Continue enhanced monitoring and validate suspicious activities."
       )

    else:

        recommendations.append(
            "Maintain continuous monitoring and perform routine security reviews."
       )

    return {

        "total_logs": len(df),

        "risk": risk,

        "severity": severity,

        "alerts": alerts,

        "top_ips": top_ips,

        "top_users": top_users,

        "mitre": mitre,

        "iocs": iocs,

        "recommendations": recommendations

    }