import streamlit as st

from analyzer.parser import parse_logs
from rules.detection_rules import detect_alerts
from analyzer.severity import assign_severity
from analyzer.mitre import map_mitre
from analyzer.risk import calculate_risk
from reports.report_data import prepare_report_data
from reports.html_report import generate_html_report

from dashboard.metrics import show_metrics
from dashboard.charts import (
    create_severity_chart,
    create_alert_chart,
    create_top_ip_chart,
    create_top_user_chart,
    create_timeline_chart,
    create_risk_gauge,
)
from dashboard.tables import show_all_tables
from dashboard.risk import show_risk_dashboard


st.set_page_config(
    page_title="SOC Alert Analyzer",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SOC Alert Analyzer")
st.write("Upload CSV or JSON security logs for analysis.")

uploaded_file = st.file_uploader(
    "Choose a log file",
    type=["csv", "json"]
)

if uploaded_file:

    try:

        # ----------------------------
        # Processing Pipeline
        # ----------------------------

        df = parse_logs(uploaded_file)

        df = detect_alerts(df)

        df = assign_severity(df)

        df = map_mitre(df)

        risk = calculate_risk(df)

        # ----------------------------
        # Dashboard
        # ----------------------------

        st.success("Logs parsed successfully!")

        st.divider()

        st.header("📊 SOC Dashboard")

        show_metrics(df)

        severity_chart = create_severity_chart(df)
        alert_chart = create_alert_chart(df)
        top_ip_chart = create_top_ip_chart(df)
        top_user_chart = create_top_user_chart(df)
        timeline_chart = create_timeline_chart(df)
        risk_gauge = create_risk_gauge(risk)

        left, right = st.columns(2)

        with left:
            st.plotly_chart(
                severity_chart,
                use_container_width=True
            )

        with right:
            st.plotly_chart(
                alert_chart,
                use_container_width=True
            )

        left, right = st.columns(2)

        with left:
            st.plotly_chart(
                top_ip_chart,
                use_container_width=True
            )

        with right:
            st.plotly_chart(
                top_user_chart,
                use_container_width=True
            )

        st.plotly_chart(
            timeline_chart,
            use_container_width=True
        )

        st.plotly_chart(
            risk_gauge,
            use_container_width=True
        )

        # ----------------------------
        # Tables
        # ----------------------------

        show_all_tables(df)

        # ----------------------------
        # Risk Summary
        # ----------------------------

        show_risk_dashboard(risk)

        report_data = prepare_report_data(
            df,
            risk
        )

        html_file = generate_html_report(
            report_data
        )

        with open(html_file, "rb") as file:

            st.download_button(

            label="📄 Download HTML Report",

            data=file,

            file_name="SOC_Incident_Report.html",

            mime="text/html"

        )

    except Exception as e:

        st.error(f"Error: {e}")

else:

    st.info("Upload a CSV or JSON log file to begin analysis.")