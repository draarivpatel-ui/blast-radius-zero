"""AWS Bedrock function-action-group boundary adapter, testable without AWS.

Deploy this together with gate.py. The handler returns a policy decision only.
No infrastructure action, AWS request, command execution or input logging occurs.
"""
import json
from dataclasses import asdict

from gate import decide


def lambda_handler(event, context=None):
    valid = isinstance(event, dict) and event.get("messageVersion") == "1.0"
    valid = valid and event.get("function") == "authorizeAgentAction"
    parameters = event.get("parameters") if isinstance(event, dict) else None
    valid = valid and isinstance(parameters, list) and len(parameters) == 1
    valid = valid and isinstance(parameters[0], dict) and parameters[0].get("name") == "manifest"
    valid = valid and parameters[0].get("type") == "string" and isinstance(parameters[0].get("value"), str)
    if valid:
        try:
            text = parameters[0]["value"]
            if len(text) > 100000: raise ValueError("Manifest too large")
            manifest = json.loads(text, parse_constant=lambda _: None)
        except (ValueError, TypeError):
            manifest = None
    else:
        manifest = None
    decision = asdict(decide(manifest))
    incoming = event if isinstance(event, dict) else {}
    response = {
        "actionGroup": incoming.get("actionGroup", "developer-agent-boundary"),
        "function": incoming.get("function", "authorizeAgentAction"),
        "functionResponse": {"responseBody": {"TEXT": {"body": json.dumps(decision)}}},
    }
    if not valid:
        response["functionResponse"]["responseState"] = "FAILURE"
    return {"messageVersion": "1.0", "response": response}
