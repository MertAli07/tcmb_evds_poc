import json
import os

import boto3
from boto3.dynamodb.conditions import Attr, Key


def _resolve_table_name():
    for key in ("DDB_TABLE_NAME", "SESSION_TABLE_NAME", "SESSION_LOG_TABLE"):
        value = os.environ.get(key)
        if value:
            return value
    return None


def _parse_event_body(event):
    body = event.get("body", {}) if isinstance(event, dict) else {}
    if isinstance(body, str):
        body = json.loads(body) if body else {}
    if body is None:
        body = {}
    if not isinstance(body, dict):
        raise ValueError("Request body must be a JSON object.")
    return body


def _extract_session_id(event):
    body = _parse_event_body(event)
    session_id = body.get("sessionID") or body.get("sessionId")
    if not session_id and isinstance(event, dict):
        params = event.get("queryStringParameters") or {}
        if isinstance(params, dict):
            session_id = params.get("sessionID") or params.get("sessionId")
    if not session_id and isinstance(event, dict):
        node = event.get("node")
        if isinstance(node, dict):
            inputs = node.get("inputs") or []
            if isinstance(inputs, list):
                for item in inputs:
                    if not isinstance(item, dict):
                        continue
                    if item.get("type") != "STRING":
                        continue
                    value = item.get("value")
                    if isinstance(value, str) and value:
                        session_id = value
                        break
    if not session_id:
        raise ValueError("Missing required parameter: sessionID")
    return session_id


def _scan_by_session_id(table, session_id):
    items = []
    start_key = None
    while True:
        kwargs = {
            "FilterExpression": Attr("sessionId").eq(session_id)
            | Attr("sessionID").eq(session_id)
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        response = table.scan(**kwargs)
        items.extend(response.get("Items", []))
        start_key = response.get("LastEvaluatedKey")
        if not start_key:
            break
    return items


def _query_by_session_id(table, session_id, index_name):
    items = []
    start_key = None
    while True:
        kwargs = {
            "IndexName": index_name,
            "KeyConditionExpression": Key("sessionId").eq(session_id),
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        response = table.query(**kwargs)
        items.extend(response.get("Items", []))
        start_key = response.get("LastEvaluatedKey")
        if not start_key:
            break
    return items


def lambda_handler(event, context):
    try:
        session_id = _extract_session_id(event)
        table_name = _resolve_table_name()
        if not table_name:
            raise ValueError("Missing DynamoDB table name.")

        region = os.environ.get("AWS_REGION", "us-east-1")
        dynamodb = boto3.resource("dynamodb", region_name=region)
        table = dynamodb.Table(table_name)

        index_name = os.environ.get("SESSION_ID_INDEX")
        if index_name:
            items = _query_by_session_id(table, session_id, index_name)
        else:
            items = _scan_by_session_id(table, session_id)

        items.sort(key=lambda x: x.get("timestamp", 0))

        full_conversation = ""
        for item in items:
            full_conversation += item.get("user_query", "") + "\n"

        return full_conversation
    except Exception as exc:
        print("Error getting full conversation: ", exc)
