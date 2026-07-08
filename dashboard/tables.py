import streamlit as st

from dashboard.helpers import highlight_severity


def show_parsed_logs(df):
    """
    Display parsed logs with severity highlighting.
    """

    st.subheader("📋 Parsed Logs")

    styled_df = df.style.map(
        highlight_severity,
        subset=["Severity"]
    )

    st.dataframe(
        styled_df,
        use_container_width=True
    )


def show_log_information(df):
    """
    Display basic log statistics.
    """

    st.subheader("📊 Log Information")

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Total Logs",
        len(df)
    )

    col2.metric(
        "Unique Users",
        df["User"].nunique()
    )

    col3.metric(
        "Unique Source IPs",
        df["SourceIP"].nunique()
    )


def show_detection_summary(df):
    """
    Display detection summary.
    """

    alerts = df[df["Status"] == "Detected"]

    st.subheader("🚨 Detection Summary")

    col1, col2 = st.columns(2)

    col1.metric(
        "Detected Alerts",
        len(alerts)
    )

    col2.metric(
        "Unique Alert Types",
        alerts["Alert"].nunique()
    )


def show_detected_alerts(df):
    """
    Display detected alerts only.
    """

    st.subheader("⚠️ Detected Alerts")

    alerts = df[df["Status"] == "Detected"]

    styled_alerts = alerts.style.map(
        highlight_severity,
        subset=["Severity"]
    )

    st.dataframe(
        styled_alerts,
        use_container_width=True
    )


def show_severity_distribution(df):
    """
    Severity distribution table.
    """

    st.subheader("📈 Severity Distribution")

    severity_counts = (
        df["Severity"]
        .value_counts()
        .reset_index()
    )

    severity_counts.columns = [
        "Severity",
        "Count"
    ]

    st.dataframe(
        severity_counts,
        use_container_width=True
    )


def show_severity_summary(df):
    """
    Severity metrics.
    """

    st.subheader("🔥 Severity Summary")

    critical = len(df[df["Severity"] == "Critical"])
    high = len(df[df["Severity"] == "High"])
    medium = len(df[df["Severity"] == "Medium"])
    low = len(df[df["Severity"] == "Low"])

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Critical", critical)
    c2.metric("High", high)
    c3.metric("Medium", medium)
    c4.metric("Low", low)


def show_mitre_summary(df):
    """
    Display MITRE ATT&CK mappings.
    """

    st.subheader("🛡️ MITRE ATT&CK Summary")

    mitre_summary = (
        df[df["MITRE ID"] != ""]
        [["MITRE ID", "Technique", "Tactic"]]
        .drop_duplicates()
    )

    st.dataframe(
        mitre_summary,
        use_container_width=True
    )


def show_mitre_statistics(df):
    """
    Display MITRE statistics.
    """

    st.subheader("📚 MITRE Statistics")

    c1, c2, c3 = st.columns(3)

    c1.metric(
        "MITRE Techniques",
        df["Technique"]
        .replace("", None)
        .dropna()
        .nunique()
    )

    c2.metric(
        "MITRE Tactics",
        df["Tactic"]
        .replace("", None)
        .dropna()
        .nunique()
    )

    c3.metric(
        "Mapped Alerts",
        len(df[df["MITRE ID"] != ""])
    )


def show_all_tables(df):
    """
    Display every dashboard table.
    """

    show_parsed_logs(df)

    show_log_information(df)

    show_detection_summary(df)

    show_detected_alerts(df)

    show_severity_distribution(df)

    show_severity_summary(df)

    show_mitre_summary(df)

    show_mitre_statistics(df)