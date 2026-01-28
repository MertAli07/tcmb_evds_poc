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


def resolve_ddb_table_name():
    for key in ("DDB_TABLE_NAME", "SESSION_TABLE_NAME", "SESSION_LOG_TABLE"):
        try:
            value = st.secrets.get(key)
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


def get_user_id():
    user_id = st.session_state.get(SESSION_USER_KEY)
    if not user_id:
        user_id = str(uuid.uuid4())
        st.session_state[SESSION_USER_KEY] = user_id
    return user_id


def start_session_log(user_query, status="IN_PROGRESS", last_node="analyzer"):
    table = get_ddb_table()
    if not table:
        return None
    timestamp = int(time.time())
    ttl = timestamp + 30 * 24 * 60 * 60
    item = {
        "userId": get_user_id(),
        "timestamp": timestamp,
        "status": status,
        "last_node": last_node,
        "user_query": user_query,
        "ttl": ttl,
    }
    try:
        table.put_item(Item=item)
        st.session_state[SESSION_LOG_KEY] = {
            "userId": item["userId"],
            "timestamp": timestamp,
            "ttl": ttl,
        }
        return item
    except ClientError:
        return None


def update_session_log(status, last_node):
    table = get_ddb_table()
    log_state = st.session_state.get(SESSION_LOG_KEY)
    if not table or not log_state:
        return
    try:
        table.update_item(
            Key={
                "userId": log_state["userId"],
                "timestamp": log_state["timestamp"],
            },
            UpdateExpression="SET #status = :status, last_node = :last_node, ttl = :ttl",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":status": status,
                ":last_node": last_node,
                ":ttl": log_state["ttl"],
            },
        )
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
    st.write("Session ID: " + read_execution_id() if read_execution_id() else "No active session")

    st.title("Example Questions")
    st.write("26-01-2023'ten itibaren 1 yıllık ortalama aylık USD/TRY paritesini getir. Ham veri.")

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
        start_session_log(user_input, status="IN_PROGRESS", last_node="analyzer")

        execution_id = read_execution_id()

        flow_inputs_existing = [
            {
                "content": {"document": user_input},
                "nodeName": "AgentsNode_1",
                "nodeInputName": "agentInputText",
            }
        ]
        flow_inputs_new = [
            {
                "content": {"document": user_input},
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
                    flowAliasIdentifier="EB7Q8SNTQR",
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
                    flowAliasIdentifier="EB7Q8SNTQR",
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
        try:
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
        except EventStreamError as exc:
            error_code = ""
            error_message = ""
            if hasattr(exc, "response"):
                error_code = exc.response.get("Error", {}).get("Code", "")
                error_message = exc.response.get("Error", {}).get("Message", "")
            if error_code or error_message:
                output_lines.append(
                    f"Bedrock akış hatası: {error_code} {error_message}".strip()
                )
            else:
                output_lines.append("Bedrock akış hatası: Yanıt alınamadı.")
            write_execution_id("")
            completion_status = "FAILED"

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
