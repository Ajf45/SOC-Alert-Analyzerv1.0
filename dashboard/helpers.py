def highlight_severity(value):

    colors = {
        "Critical": "background-color:#ff4b4b;color:white;",
        "High": "background-color:#ff9800;color:white;",
        "Medium": "background-color:#ffd54f;",
        "Low": "background-color:#81c784;"
    }

    return colors.get(value, "")