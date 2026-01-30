import json
import os

import pandas as pd
from evds import evdsAPI


def _parse_event_body(event):
    body = event.get("body", {}) if isinstance(event, dict) else {}
    if isinstance(body, str):
        body = json.loads(body) if body else {}
    if body is None:
        body = {}
    if not isinstance(body, dict):
        raise ValueError("Request body must be a JSON object.")
    return body


def _get_required_param(body, key):
    value = body.get(key)
    if value is None or value == "":
        raise ValueError(f"Missing required parameter: {key}")
    return value


def _extract_from_node_inputs(event):
    if not isinstance(event, dict):
        return None, None
    node = event.get("node")
    if not isinstance(node, dict):
        return None, None
    inputs = node.get("inputs")
    if not isinstance(inputs, list):
        return None, None

    series = None
    options = None
    for item in inputs:
        if not isinstance(item, dict):
            continue
        value = item.get("value")
        value_type = item.get("type")
        if value_type == "STRING" and isinstance(value, str) and series is None:
            series = value
        elif value_type == "OBJECT" and isinstance(value, dict) and options is None:
            options = value

    return series, options


def lambda_handler(event, context):
    try:
        body = _parse_event_body(event)
        series = body.get("series")
        options = body.get("options") or body.get("params")

        node_series, node_options = _extract_from_node_inputs(event)
        if node_series is not None:
            series = node_series
        if node_options is not None:
            options = node_options

        if series is None or series == "":
            raise ValueError("Missing required parameter: series")
        if not isinstance(series, str):
            raise ValueError("Parameter series must be a string.")
        if options is None:
            raise ValueError("Missing required parameter: options")
        if not isinstance(options, dict):
            raise ValueError("Parameter options must be an object.")

        startdate = _get_required_param(options, "startDate")
        enddate = _get_required_param(options, "endDate")

        api_key = os.getenv("EVDS_API_KEY", "eQo4WDdFeB")
        evds = evdsAPI(api_key)
        print("series", series)
        print("startdate", startdate)
        print("enddate", enddate)
        print("options", options)
        data = evds.get_data(
            [series],
            startdate=startdate,
            enddate=enddate,
            aggregation_types=options.get("aggregationType", ""),
            formulas=options.get("formulas", ""),
            frequency=options.get("frequency", ""),
            raw=True,
        )
        print("data", data)
        df = pd.DataFrame(data)
        series_column = series.replace(".", "_")
        if series_column not in df.columns:
            raise ValueError(f"Series column not found: {series_column}")
        df[series_column] = pd.to_numeric(df[series_column], errors="coerce")

        statistics = df[[series_column]].describe().to_dict()
        data = df.to_dict(orient="records")

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(
                {"raw_data": data, "series": series, "statistics": statistics}
            ),
        }
    except Exception as exc:
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": str(exc)}),
        }
