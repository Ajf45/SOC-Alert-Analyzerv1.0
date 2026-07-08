import plotly.express as px
import plotly.graph_objects as go


def create_severity_chart(df):
    """
    Severity Distribution Bar Chart
    """

    severity_counts = (
        df["Severity"]
        .value_counts()
        .reset_index()
    )

    severity_counts.columns = [
        "Severity",
        "Count"
    ]

    fig = px.bar(
        severity_counts,
        x="Severity",
        y="Count",
        color="Severity",
        text="Count",
        title="Severity Distribution"
    )

    fig.update_layout(
        xaxis_title="Severity",
        yaxis_title="Count"
    )

    return fig


def create_alert_chart(df):
    """
    Alert Distribution Pie Chart
    """

    alert_counts = (
        df["Alert"]
        .value_counts()
        .reset_index()
    )

    alert_counts.columns = [
        "Alert",
        "Count"
    ]

    fig = px.pie(
        alert_counts,
        names="Alert",
        values="Count",
        title="Alert Distribution"
    )

    return fig


def create_top_ip_chart(df):
    """
    Top Source IPs
    """

    ip_counts = (
        df["SourceIP"]
        .value_counts()
        .head(10)
        .reset_index()
    )

    ip_counts.columns = [
        "Source IP",
        "Count"
    ]

    fig = px.bar(
        ip_counts,
        x="Source IP",
        y="Count",
        text="Count",
        title="Top Source IPs"
    )

    fig.update_layout(
        xaxis_title="Source IP",
        yaxis_title="Events"
    )

    return fig


def create_top_user_chart(df):
    """
    Most Targeted Users
    """

    user_counts = (
        df["User"]
        .value_counts()
        .head(10)
        .reset_index()
    )

    user_counts.columns = [
        "User",
        "Count"
    ]

    fig = px.bar(
        user_counts,
        x="User",
        y="Count",
        text="Count",
        title="Most Targeted Users"
    )

    fig.update_layout(
        xaxis_title="User",
        yaxis_title="Events"
    )

    return fig


def create_timeline_chart(df):
    """
    Incident Timeline
    """

    timeline = df.sort_values("Timestamp")

    fig = px.scatter(
        timeline,
        x="Timestamp",
        y="Alert",
        color="Severity",
        hover_data=[
            "User",
            "SourceIP"
        ],
        title="Incident Timeline"
    )

    return fig


def create_risk_gauge(risk):
    """
    Overall Risk Gauge
    """

    fig = go.Figure(
        go.Indicator(

            mode="gauge+number",

            value=risk["score"],

            title={
                "text": "Overall Risk Score"
            },

            gauge={

                "axis": {
                    "range": [0, 100]
                },

                "bar": {
                    "color": "red"
                },

                "steps": [

                    {
                        "range": [0, 40],
                        "color": "lightgreen"
                    },

                    {
                        "range": [40, 70],
                        "color": "gold"
                    },

                    {
                        "range": [70, 100],
                        "color": "tomato"
                    }

                ]
            }
        )
    )

    return fig