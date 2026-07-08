import streamlit as st

def show_metrics(df):

    total_logs = len(df)

    detected_alerts = len(
        df[df["Status"] == "Detected"]
    )

    unique_users = df["User"].nunique()

    unique_ips = df["SourceIP"].nunique()

    k1, k2, k3, k4 = st.columns(4)

    k1.metric("Logs", total_logs)

    k2.metric("Alerts", detected_alerts)

    k3.metric("Users", unique_users)

    k4.metric("Source IPs", unique_ips)
