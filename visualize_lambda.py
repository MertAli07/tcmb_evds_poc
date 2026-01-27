import json
import os
from datetime import datetime
from io import BytesIO

import boto3
import matplotlib
import matplotlib.pyplot as plt
import numpy as np

matplotlib.use("Agg")

DEFAULT_BUCKET = "tcmb-poc-evds"
DEFAULT_PREFIX = "visuals/"
PUBLIC_BASE_URL = "https://tcmb-poc-evds.s3.us-east-1.amazonaws.com/visuals/"


def _parse_unixtime(raw_unixtime):
    if isinstance(raw_unixtime, dict):
        raw_unixtime = raw_unixtime.get("$numberLong")
    return int(raw_unixtime)


def load_series(payload):
    raw_data = payload["raw_data"]

    dates = []
    values = []
    for row in raw_data:
        dates.append(datetime.utcfromtimestamp(_parse_unixtime(row["UNIXTIME"])))
        values.append(float(row["TP_DK_USD_A"]))

    order = np.argsort(dates)
    dates = [dates[i] for i in order]
    values = np.array([values[i] for i in order], dtype=float)
    return dates, values


def build_dashboard(dates, values):
    mean_val = float(np.mean(values))
    std_val = float(np.std(values, ddof=0))

    fig = plt.figure(figsize=(13, 6))
    grid = fig.add_gridspec(
        nrows=2,
        ncols=2,
        width_ratios=[2.4, 1],
        height_ratios=[1, 1],
        wspace=0.25,
        hspace=0.35,
    )

    ax_time = fig.add_subplot(grid[:, 0])
    ax_box = fig.add_subplot(grid[0, 1])
    ax_hist = fig.add_subplot(grid[1, 1])

    ax_time.plot(dates, values, color="#1f77b4", linewidth=2)
    ax_time.set_title("USD Buy Rate (TP_DK_USD_A) - Weekly Trend")
    ax_time.set_xlabel("Date")
    ax_time.set_ylabel("Rate")
    ax_time.grid(True, alpha=0.3)

    ax_box.boxplot(values, vert=True, patch_artist=True, widths=0.6)
    ax_box.set_title("Distribution (Box Plot)")
    ax_box.set_xticks([])
    ax_box.set_ylabel("Rate")
    ax_box.grid(True, axis="y", alpha=0.3)

    ax_hist.hist(values, bins=12, color="#7f7f7f", edgecolor="white", alpha=0.85)
    ax_hist.axvline(mean_val, color="#d62728", linestyle="--", linewidth=2, label="Mean")
    ax_hist.axvline(mean_val + std_val, color="#ff7f0e", linestyle=":", linewidth=1.5, label="+1 Std")
    ax_hist.axvline(mean_val - std_val, color="#ff7f0e", linestyle=":", linewidth=1.5, label="-1 Std")
    ax_hist.set_title("Distribution (Histogram)")
    ax_hist.set_xlabel("Rate")
    ax_hist.set_ylabel("Count")
    ax_hist.grid(True, axis="y", alpha=0.3)
    ax_hist.legend(
        loc="upper right",
        frameon=True,
        framealpha=0.9,
        facecolor="white",
        edgecolor="#bbbbbb",
        fontsize=8,
    )

    fig.suptitle("TCMB EVDS Dashboard", fontsize=14, fontweight="bold")
    return fig


def save_figure_to_s3(fig, bucket, prefix):
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    filename = f"tcmb-evds-dashboard-{timestamp}.png"
    buffer = BytesIO()
    fig.savefig(buffer, dpi=150, bbox_inches="tight", format="png")
    buffer.seek(0)

    s3_key = f"{prefix}{filename}"
    boto3.client("s3").put_object(
        Bucket=bucket,
        Key=s3_key,
        Body=buffer.getvalue(),
        ContentType="image/png",
    )
    return f"{PUBLIC_BASE_URL}{filename}"


def _load_payload_from_event(event):
    if not isinstance(event, dict):
        raise ValueError("Event payload must be a dict.")

    if "raw_data" in event:
        return event

    node = event.get("node", {})
    inputs = node.get("inputs", [])
    for item in inputs:
        if isinstance(item, dict) and item.get("name") == "codeHookInput":
            value = item.get("value")
            if isinstance(value, dict) and "raw_data" in value:
                return value

    body = event.get("body")
    if body:
        if isinstance(body, str):
            return json.loads(body)
        if isinstance(body, dict):
            return body

    raise ValueError("Event must include 'raw_data' or JSON body.")


def lambda_handler(event, context):
    payload = _load_payload_from_event(event or {})
    dates_series, value_series = load_series(payload)
    fig = build_dashboard(dates_series, value_series)

    bucket = os.getenv("S3_BUCKET", DEFAULT_BUCKET)
    prefix = os.getenv("S3_PREFIX", DEFAULT_PREFIX)
    url = save_figure_to_s3(fig, bucket, prefix)
    plt.close(fig)

    return {
        "statusCode": 200,
        "body": json.dumps({"url": url}),
    }
