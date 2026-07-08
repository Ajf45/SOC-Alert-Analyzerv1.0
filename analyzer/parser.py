import pandas as pd


# Standard column names used throughout the project
STANDARD_COLUMNS = [
    "Timestamp",
    "User",
    "SourceIP",
    "Event"
]


def detect_file_type(uploaded_file):
    """
    Detect uploaded file type based on extension.
    """

    filename = uploaded_file.name.lower()

    if filename.endswith(".csv"):
        return "csv"

    elif filename.endswith(".json"):
        return "json"

    else:
        raise ValueError("Unsupported file format.")


def load_file(uploaded_file):
    """
    Load CSV or JSON into a DataFrame.
    """

    file_type = detect_file_type(uploaded_file)

    if file_type == "csv":
        df = pd.read_csv(uploaded_file)

    elif file_type == "json":
        df = pd.read_json(uploaded_file)

    else:
        raise ValueError("Invalid file.")

    return df


def standardize_columns(df):
    """
    Rename common log column variations
    into one standard format.
    """

    column_mapping = {

        "timestamp": "Timestamp",
        "time": "Timestamp",
        "date": "Timestamp",

        "user": "User",
        "username": "User",
        "account": "User",

        "ip": "SourceIP",
        "sourceip": "SourceIP",
        "source_ip": "SourceIP",
        "clientip": "SourceIP",

        "event": "Event",
        "action": "Event",
        "activity": "Event"

    }

    renamed_columns = {}

    for col in df.columns:
        key = col.strip().lower()

        if key in column_mapping:
            renamed_columns[col] = column_mapping[key]

    df = df.rename(columns=renamed_columns)

    return df


def clean_data(df):
    """
    Basic data cleaning.
    """

    df = df.drop_duplicates()

    df = df.fillna("Unknown")

    if "Timestamp" in df.columns:
        df["Timestamp"] = pd.to_datetime(
            df["Timestamp"],
            errors="coerce"
        )

    return df


def validate_columns(df):
    """
    Ensure required columns exist.
    """

    missing = []

    for col in STANDARD_COLUMNS:

        if col not in df.columns:
            missing.append(col)

    if missing:
        raise ValueError(
            f"Missing required columns: {', '.join(missing)}"
        )

    return True


def parse_logs(uploaded_file):
    """
    Complete parser pipeline.
    """

    df = load_file(uploaded_file)

    df = standardize_columns(df)

    df = clean_data(df)

    validate_columns(df)

    return df