import streamlit as st
import requests
import json
import boto3
import os
import uuid
from botocore.config import Config
from botocore.exceptions import ClientError, EventStreamError
import time
from io import BytesIO
from PIL import Image

st.set_page_config(page_title="EVDS", layout="wide")

config = Config(
    connect_timeout=60,
    read_timeout=300  # extend timeout to 5 minutes
)
client_runtime = boto3.client("bedrock-agent-runtime", region_name="us-east-1", config=config)

SESSION_STATE_KEY = "execution_id"
SESSION_LOG_KEY = "session_log"
SESSION_USER_KEY = "session_user_id"
SESSION_CUSTOM_ID_KEY = "session_id"
ALIAS_ID = "WDSO2II0RX"


def resolve_ddb_table_name():
    for key in ("DDB_TABLE_NAME", "SESSION_TABLE_NAME", "SESSION_LOG_TABLE"):
        try:
            value = "tcmb_evds_sessions"
        except Exception:
            value = None
        if not value:
            value = os.environ.get(key)
        if value:
            return value
    return None


def get_ddb_table():
    table_name = resolve_ddb_table_name()
    if not table_name:
        return None
    region = os.environ.get("AWS_REGION", "us-east-1")
    dynamodb = boto3.resource("dynamodb", region_name=region)
    return dynamodb.Table(table_name)


def read_execution_id():
    execution_id = st.session_state.get(SESSION_STATE_KEY)
    return execution_id if execution_id else None


def write_execution_id(execution_id):
    st.session_state[SESSION_STATE_KEY] = execution_id or ""


def read_custom_session_id():
    session_id = st.session_state.get(SESSION_CUSTOM_ID_KEY)
    return session_id if session_id else None


def write_custom_session_id(session_id):
    st.session_state[SESSION_CUSTOM_ID_KEY] = session_id or ""


def get_or_create_session_id():
    session_id = read_custom_session_id()
    if not session_id:
        session_id = str(uuid.uuid4())
        write_custom_session_id(session_id)
    return session_id


def build_flow_input_content(user_input, session_id):
    return {
        "document":
            {
                "user_question": user_input,
                "sessionID": session_id or "",
            }
    }


def get_user_id():
    user_id = st.session_state.get(SESSION_USER_KEY)
    if not user_id:
        user_id = str(uuid.uuid4())
        st.session_state[SESSION_USER_KEY] = user_id
    return user_id


def start_session_log(
    user_query,
    status="IN_PROGRESS",
    last_node="analyzer",
    session_id=None,
    execution_id=None,
):
    table = get_ddb_table()
    if not table:
        st.warning("DynamoDB table name not configured; skipping log write.")
        return None
    
    timestamp_epoch = int(time.time())
    timestamp = str(timestamp_epoch)
    ttl = timestamp_epoch + 30 * 24 * 60 * 60
    effective_execution_id = execution_id or session_id or str(uuid.uuid4())
    
    # Check if sessionID already exists
    existing_item = None
    if session_id:
        try:
            # Query by partition key (sessionId) to get the most recent item
            response = table.query(
                KeyConditionExpression='sessionId = :sid',
                ExpressionAttributeValues={':sid': session_id},
                ScanIndexForward=False,  # Sort descending by sort key
                Limit=1
            )
            if response.get('Items'):
                existing_item = response['Items'][0]
        except ClientError as exc:
            st.warning(f"Query failed: {exc}")
            pass
    
    if existing_item:
    # Update existing entry - append new query to user_query
        try:
            # Primary key is sessionId + executionId
            key = {
                'sessionId': existing_item['sessionId'],
                'executionId': existing_item['executionId']
            }
            
            # Get existing user_query and append new one
            existing_query = existing_item.get('user_query', '')
            updated_query = f"{existing_query}\n{user_query}" if existing_query else user_query
            
            table.update_item(
                Key=key,
                UpdateExpression="SET #status = :status, last_node = :last_node, user_query = :query, timestampEpoch = :ts_epoch, #ts = :ts, #ttl = :ttl",
                ExpressionAttributeNames={
                    "#status": "status",
                    "#ts": "timestamp",
                    "#ttl": "ttl"
                },
                ExpressionAttributeValues={
                    ":status": status,
                    ":last_node": last_node,
                    ":query": updated_query,
                    ":ts_epoch": timestamp_epoch,
                    ":ts": timestamp,
                    ":ttl": ttl
                }
            )
            st.session_state[SESSION_LOG_KEY] = {
                "userId": existing_item["userId"],
                "timestamp": timestamp,
                "ttl": ttl,
                "executionId": existing_item["executionId"],
            }
            return existing_item
        except ClientError as exc:
            st.error(f"DynamoDB update failed: {exc}")
            raise
    else:
        # Insert new entry
        item = {
            "userId": get_user_id(),
            "executionId": effective_execution_id,
            "timestamp": timestamp,
            "timestampEpoch": timestamp_epoch,
            "status": status,
            "last_node": last_node,
            "user_query": user_query,
            "ttl": ttl,
        }
        if session_id:
            item["sessionId"] = session_id
            item["sessionID"] = session_id
        if execution_id and execution_id != effective_execution_id:
            item["flowExecutionId"] = execution_id
        try:
            table.put_item(Item=item)
            st.session_state[SESSION_LOG_KEY] = {
                "userId": item["userId"],
                "timestamp": timestamp,
                "ttl": ttl,
                "executionId": item["executionId"],
            }
            return item
        except ClientError as exc:
            st.error(f"DynamoDB write failed: {exc}")
            raise


def update_session_log(status, last_node):
    table = get_ddb_table()
    log_state = st.session_state.get(SESSION_LOG_KEY)
    if not table or not log_state:
        return
    try:
        key_candidates = []
        if log_state.get("userId") and log_state.get("executionId"):
            key_candidates.append(
                {"userId": log_state["userId"], "executionId": log_state["executionId"]}
            )
        if log_state.get("executionId") and log_state.get("timestamp") is not None:
            key_candidates.append(
                {"executionId": log_state["executionId"], "timestamp": log_state["timestamp"]}
            )
        if log_state.get("executionId"):
            key_candidates.append({"executionId": log_state["executionId"]})
        if log_state.get("userId") and log_state.get("timestamp") is not None:
            key_candidates.append(
                {"userId": log_state["userId"], "timestamp": log_state["timestamp"]}
            )

        for key in key_candidates:
            try:
                table.update_item(
                    Key=key,
                    UpdateExpression="SET #status = :status, last_node = :last_node, ttl = :ttl",
                    ExpressionAttributeNames={"#status": "status"},
                    ExpressionAttributeValues={
                        ":status": status,
                        ":last_node": last_node,
                        ":ttl": log_state["ttl"],
                    },
                )
                return
            except ClientError:
                continue
    except ClientError:
        return

def display_s3_image(s3_uri: str, region: str = "us-east-1"):
    """
    Download an image from S3 and display it in Streamlit.

    Args:
        s3_uri (str): Full S3 URI, e.g. "s3://bucket-name/path/to/file.png"
        region (str): AWS region of the bucket
    """
    # Parse S3 URI
    if not s3_uri.startswith("s3://"):
        return
    
    parts = s3_uri.replace("s3://", "").split("/", 1)
    bucket, key = parts[0], parts[1]

    # Get object from S3
    s3 = boto3.client("s3", region_name=region)
    response = s3.get_object(Bucket=bucket, Key=key)

    # Read image bytes
    img_bytes = response["Body"].read()
    img = Image.open(BytesIO(img_bytes))

    return img


def display_url_image(image_url: str):
    if not image_url:
        return None
    try:
        response = requests.get(image_url, timeout=30)
        response.raise_for_status()
        return Image.open(BytesIO(response.content))
    except requests.RequestException:
        return None
    except OSError:
        return None


def extract_image_payload(item):
    if isinstance(item, dict):
        if "s3_uri" in item:
            return {"s3_uri": item["s3_uri"]}
        if "url" in item:
            return {"url": item["url"]}
        if "body" in item:
            body = item.get("body")
            if isinstance(body, dict):
                if "url" in body:
                    return {"url": body["url"]}
                if "s3_uri" in body:
                    return {"s3_uri": body["s3_uri"]}
            if isinstance(body, str):
                try:
                    parsed = json.loads(body)
                    if isinstance(parsed, dict):
                        if "url" in parsed:
                            return {"url": parsed["url"]}
                        if "s3_uri" in parsed:
                            return {"s3_uri": parsed["s3_uri"]}
                except json.JSONDecodeError:
                    return None
    if isinstance(item, str):
        try:
            parsed = json.loads(item)
            if isinstance(parsed, dict):
                if "url" in parsed:
                    return {"url": parsed["url"]}
                if "s3_uri" in parsed:
                    return {"s3_uri": parsed["s3_uri"]}
        except json.JSONDecodeError:
            return None
    return None
    

with st.sidebar:
    st.title("Configuration")
    st.write(
        "Execution ID: " + read_execution_id()
        if read_execution_id()
        else "No active execution"
    )
    session_id_input = st.text_input(
        "Custom Session ID",
        value=read_custom_session_id() or "",
        help="Optional. If set, it will be sent to the flow and stored in DynamoDB.",
    )
    if session_id_input != (read_custom_session_id() or ""):
        write_custom_session_id(session_id_input.strip())

    st.title("Example Questions")
    st.write("26-01-2023'ten itibaren 1 yıllık ortalama aylık USD/TRY paritesini getir. Ham veri.")
    st.write("Son bir yilda USD ile EUR arasindaki artisi goster")
    st.write("daily istiyorum. percentage change olsun")

st.title("EVDS Assistant")

# Initialize chat history
if "messages" not in st.session_state:
    st.session_state.messages = []

# Display chat messages from history on app rerun
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

user_input = st.chat_input("Mesajınızı buraya yazın...")

if user_input:
    with st.chat_message("user"):
        st.write(user_input)
        st.session_state.messages.append({"role": "user", "content": user_input})

    with st.spinner("Generating response..."):
        payload = user_input
        execution_id = read_execution_id()
        session_id = get_or_create_session_id()
        start_session_log(
            user_input,
            status="IN_PROGRESS",
            last_node="analyzer",
            session_id=session_id,
            execution_id=execution_id,
        )

        flow_inputs_existing = [
            {
                "content": {"document": user_input},
                "nodeName": "AgentsNode_1",
                "nodeInputName": "agentInputText",
            }
        ]
        flow_inputs_new = [
            {
                "content": build_flow_input_content(user_input, session_id),
                "nodeName": "FlowInputNode",
                "nodeOutputName": "document",
            }
        ]

        if execution_id:
            print()
            print("CONTINUE EXISTING FLOW")
            print()
            # Continue existing flow
            try:
                response = client_runtime.invoke_flow(
                    flowIdentifier="arn:aws:bedrock:us-east-1:980088652213:flow/HMWETVTTZ2",
                    flowAliasIdentifier=ALIAS_ID,
                    executionId=execution_id,
                    inputs=flow_inputs_existing,
                )
            except ClientError as exc:
                error_code = exc.response.get("Error", {}).get("Code", "")
                error_message = exc.response.get("Error", {}).get("Message", "")
                if error_code == "validationException" and "session context" in error_message.lower():
                    write_execution_id("")
                    execution_id = None
                else:
                    update_session_log("FAILED", "analyzer")
                    raise

        if not execution_id:
            print()
            print("NEW FLOW")
            print()
            # Start new flow
            try:
                response = client_runtime.invoke_flow(
                    flowIdentifier="arn:aws:bedrock:us-east-1:980088652213:flow/HMWETVTTZ2",
                    flowAliasIdentifier=ALIAS_ID,
                    inputs=flow_inputs_new,
                )
                execution_id = response["executionId"]
                write_execution_id(execution_id)
            except ClientError:
                update_session_log("FAILED", "analyzer")
                raise

        output_lines = []

        print("response", response)
        exec_id = response["executionId"]
        write_execution_id(exec_id)

        output_lines = []

        completion_status = None
        for event in response.get("responseStream", []):
            if "flowOutputEvent" in event:
                output_lines.append(event["flowOutputEvent"]["content"]["document"])
            elif "flowMultiTurnInputRequestEvent" in event:
                output_lines.append(
                    event["flowMultiTurnInputRequestEvent"]["content"]["document"]
                )
            elif "flowCompletionEvent" in event:
                if event["flowCompletionEvent"]["completionReason"] == "SUCCESS":
                    write_execution_id("")  # clear file on completion
                    completion_status = "COMPLETED"

        if completion_status:
            update_session_log(completion_status, "visualizer" if completion_status == "COMPLETED" else "analyzer")

        print()
        print("output_lines")
        print(output_lines)
        print()

        result = None
        image_obj = None
        for item in output_lines:
            if isinstance(item, str) and result is None:
                result = item
                continue
            if image_obj is None:
                image_obj = extract_image_payload(item)

        if result is None:
            result = "Yanıt alınamadı."

        with st.chat_message("assistant"):
            img = None
            image_url = None
            if image_obj:
                if "s3_uri" in image_obj:
                    img = display_s3_image(image_obj["s3_uri"])
                elif "url" in image_obj:
                    image_url = image_obj["url"]
                    img = display_url_image(image_url)
                if img:
                    st.image(img, caption="Generated Diagram", use_container_width=True)
                elif image_url:
                    st.image(image_url, caption="Generated Diagram", use_container_width=True)
            st.write(result)
            st.session_state.messages.append(
                {
                    "role": "assistant",
                    "content": result,
                    "graph": image_url if image_url else (img if img else None),
                }
            )
else:
    with st.chat_message("assistant"):
        st.write("Size nasıl yardımcı olabilirim?")
