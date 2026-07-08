"""
MITRE ATT&CK Mapping Module
Maps detected alerts to MITRE ATT&CK techniques.
"""

MITRE_MAPPING = {

    "Failed Login": {
        "TechniqueID": "T1110",
        "Technique": "Brute Force",
        "Tactic": "Credential Access"
    },

    "Brute Force": {
        "TechniqueID": "T1110",
        "Technique": "Brute Force",
        "Tactic": "Credential Access"
    },

    "PowerShell Execution": {
        "TechniqueID": "T1059.001",
        "Technique": "PowerShell",
        "Tactic": "Execution"
    },

    "Remote Desktop Login": {
        "TechniqueID": "T1021.001",
        "Technique": "Remote Services",
        "Tactic": "Lateral Movement"
    },

    "USB Device Connected": {
        "TechniqueID": "T1091",
        "Technique": "Replication Through Removable Media",
        "Tactic": "Lateral Movement"
    },

    "Antivirus Disabled": {
        "TechniqueID": "T1562.001",
        "Technique": "Impair Defenses",
        "Tactic": "Defense Evasion"
    },

    "Admin Login": {
        "TechniqueID": "T1078",
        "Technique": "Valid Accounts",
        "Tactic": "Persistence"
    },

    "Suspicious IP": {
        "TechniqueID": "T1595",
        "Technique": "Active Scanning",
        "Tactic": "Reconnaissance"
    },

    "Port Scan": {
        "TechniqueID": "T1046",
        "Technique": "Network Service Discovery",
        "Tactic": "Discovery"
    }
}


def map_mitre(df):
    """
    Add MITRE ATT&CK information to alerts.
    """

    df = df.copy()

    df["MITRE ID"] = ""
    df["Technique"] = ""
    df["Tactic"] = ""

    for index, row in df.iterrows():

        alert = row["Alert"]

        if alert in MITRE_MAPPING:

            mapping = MITRE_MAPPING[alert]

            df.at[index, "MITRE ID"] = mapping["TechniqueID"]
            df.at[index, "Technique"] = mapping["Technique"]
            df.at[index, "Tactic"] = mapping["Tactic"]

    return df