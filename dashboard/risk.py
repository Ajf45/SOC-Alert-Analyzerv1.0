import streamlit as st


def show_risk_summary(risk):
    """
    Display overall risk assessment.
    """

    st.header("🛡️ Overall Risk Assessment")

    col1, col2 = st.columns(2)

    col1.metric(
        "Risk Score",
        f"{risk['score']}%"
    )

    col2.metric(
        "Risk Level",
        risk["level"]
    )

    st.subheader("Risk Breakdown")

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Critical",
        risk["critical"]
    )

    c2.metric(
        "High",
        risk["high"]
    )

    c3.metric(
        "Medium",
        risk["medium"]
    )

    c4.metric(
        "Low",
        risk["low"]
    )

    st.subheader("Overall Risk Score")

    st.progress(risk["score"] / 100)

    st.write(
        f"Current Security Risk: **{risk['level']}**"
    )


def show_recommendations(risk):
    """
    Display recommendations based on the current risk level.
    """

    st.subheader("Recommendations")

    if risk["level"] == "Critical":

        st.error("""
Immediate action required.

• Investigate critical alerts immediately.

• Isolate affected systems.

• Block malicious IPs.

• Review administrator accounts.

• Perform incident response.
""")

    elif risk["level"] == "High":

        st.warning("""
High security risk detected.

• Investigate high severity alerts.

• Monitor PowerShell activity.

• Review authentication failures.

• Verify endpoint protection.

• Review privileged account activity.
""")

    elif risk["level"] == "Medium":

        st.info("""
Medium security risk.

• Continue monitoring.

• Review suspicious activity.

• Audit privileged accounts.

• Verify endpoint security configuration.
""")

    else:

        st.success("""
Low security risk.

• Continue routine monitoring.

• No major threats detected.

• Maintain regular log reviews.
""")


def show_risk_dashboard(risk):
    """
    Display the complete risk section.
    """

    show_risk_summary(risk)

    show_recommendations(risk)