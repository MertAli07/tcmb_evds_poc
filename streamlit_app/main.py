import streamlit as st
import requests
import json
import boto3
from botocore.config import Config
import time
from io import BytesIO
from PIL import Image

st.set_page_config(page_title="EVDS", layout="wide")

config = Config(
    connect_timeout=60,
    read_timeout=300  # extend timeout to 5 minutes
)
client_runtime = boto3.client("bedrock-agent-runtime", region_name="us-east-1", config=config)

SESSION_FILE = "session_info.txt"


def read_execution_id():
    try:
        with open(SESSION_FILE, "r") as f:
            execution_id = f.read().strip()
            return execution_id if execution_id else None
    except FileNotFoundError:
        return None


def write_execution_id(execution_id):
    with open(SESSION_FILE, "w") as f:
        f.write(execution_id or "")

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

        execution_id = read_execution_id()

        if execution_id:
            print()
            print("CONTINUE EXISTING FLOW")
            print()
            # Continue existing flow
            inputs = [
                {
                    "content": {"document": user_input},
                    "nodeName": "AgentsNode_1",
                    "nodeInputName": "agentInputText"
                }
            ]
            response = client_runtime.invoke_flow(
                flowIdentifier="arn:aws:bedrock:us-east-1:980088652213:flow/HMWETVTTZ2",
                flowAliasIdentifier="EB7Q8SNTQR",
                executionId=execution_id,
                inputs=inputs,
            )
        else:
            print()
            print("NEW FLOW")
            print()
            # Start new flow
            inputs = [
                {
                    "content": {"document": user_input},
                    "nodeName": "FlowInputNode",
                    "nodeOutputName": "document",
                }
            ]
            response = client_runtime.invoke_flow(
                flowIdentifier="arn:aws:bedrock:us-east-1:980088652213:flow/HMWETVTTZ2",
                flowAliasIdentifier="EB7Q8SNTQR",
                inputs=inputs,
            )
            execution_id = response["executionId"]
            write_execution_id(execution_id)

        output_lines = []

        print("response", response)
        exec_id = response["executionId"]
        write_execution_id(exec_id)

        output_lines = []

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
