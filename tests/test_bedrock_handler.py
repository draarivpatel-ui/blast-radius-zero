import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("bedrock_handler_test", ROOT / "bedrock_action_handler.py")
handler = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handler)


def event(manifest):
    return {"messageVersion": "1.0", "function": "authorizeAgentAction", "actionGroup": "boundary",
            "parameters": [{"name": "manifest", "type": "string", "value": json.dumps(manifest)}]}


@pytest.mark.parametrize("manifest,allowed", [
    ({"version": 1, "kind": "read", "parameters": {"path": "/workspace/src/main.py"}}, True),
    ({"version": 1, "kind": "network", "parameters": {"host": "example.invalid", "method": "GET", "data_class": "public"}}, False),
    ({}, False),
])
def test_real_bedrock_response_contract(manifest, allowed):
    response = handler.lambda_handler(event(manifest))
    assert response["messageVersion"] == "1.0"
    assert response["response"]["function"] == "authorizeAgentAction"
    body = json.loads(response["response"]["functionResponse"]["responseBody"]["TEXT"]["body"])
    assert body["allowed"] is allowed


@pytest.mark.parametrize("bad_event", [None, {}, {"parameters": []}, {"messageVersion": "2.0"}])
def test_malformed_cloud_events_fail_closed(bad_event):
    body = handler.lambda_handler(bad_event)["response"]["functionResponse"]
    assert body["responseState"] == "FAILURE"
    assert not json.loads(body["responseBody"]["TEXT"]["body"])["allowed"]
