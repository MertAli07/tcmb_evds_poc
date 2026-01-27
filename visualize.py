import json
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import boto3


S3_BUCKET = "tcmb-poc-evds"
S3_PREFIX = "visuals/"
PUBLIC_BASE_URL = "https://tcmb-poc-evds.s3.us-east-1.amazonaws.com/visuals/"


def _parse_unixtime(raw_unixtime):
    if isinstance(raw_unixtime, dict):
        raw_unixtime = raw_unixtime.get("$numberLong")
    return int(raw_unixtime)


def load_series(json_path):
    payload = json.loads(Path(json_path).read_text())
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
    local_path = Path(__file__).with_name(filename)

    fig.savefig(local_path, dpi=150, bbox_inches="tight")

    s3 = boto3.client("s3")
    s3_key = f"{prefix}{filename}"
    s3.upload_file(
        str(local_path),
        bucket,
        s3_key,
        ExtraArgs={"ContentType": "image/png"},
    )
    return f"{PUBLIC_BASE_URL}{filename}", local_path


if __name__ == "__main__":
    data_path = Path(__file__).with_name("thrash.json")
    dates_series, value_series = load_series(data_path)
    fig = build_dashboard(dates_series, value_series)
    url, saved_path = save_figure_to_s3(fig, S3_BUCKET, S3_PREFIX)
    print(f"Saved locally: {saved_path}")
    print(f"S3 URL: {url}")
