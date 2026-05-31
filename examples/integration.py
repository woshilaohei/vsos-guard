# VSOS Guard Integration Examples

## Quick Start

```python
from vsos_guard import VSOSGuard

guard = VSOSGuard()  # relaxed mode by default
result = guard.check("user input here")

if result.is_blocked():
    print(f"Blocked: {result.reason}")
elif result.is_warning():
    print(f"Warning: {result.warning}")
else:
    print("Safe")
```

## LangChain Integration

```python
from vsos_guard import VSOSGuard
from langchain_core.callbacks import BaseCallbackHandler

class VSOSGuardCallback(BaseCallbackHandler):
    """Block malicious prompts before they reach the LLM."""

    def __init__(self, mode="relaxed", on_block=None):
        self.guard = VSOSGuard(mode=mode, on_block=on_block)

    def on_llm_start(self, serialized, prompts, **kwargs):
        for prompt in prompts:
            result = self.guard.check(prompt)
            if result.is_blocked():
                raise ValueError(f"VSOS Guard blocked input: {result.reason}")
            if result.is_warning():
                import warnings
                warnings.warn(f"VSOS Guard warning: {result.warning}")

# Usage
from langchain_openai import ChatOpenAI

guard_callback = VSOSGuardCallback(mode="standard")
llm = ChatOpenAI(callbacks=[guard_callback])
```

## OpenAI SDK Integration

```python
from vsos_guard import VSOSGuard
from openai import OpenAI

guard = VSOSGuard(mode="standard")

def safe_chat(client, model, messages, **kwargs):
    """Drop-in replacement for client.chat.completions.create() with guard."""
    for msg in messages:
        result = guard.check(msg["content"])
        if result.is_blocked():
            raise ValueError(f"Input blocked: {result.reason}")

    return client.chat.completions.create(model=model, messages=messages, **kwargs)

# Usage
client = OpenAI()
response = safe_chat(client, "gpt-4", [
    {"role": "user", "content": "Hello!"}
])
```

## FastAPI Middleware

```python
from vsos_guard import VSOSGuard
from fastapi import FastAPI, HTTPException, Request

app = FastAPI()
guard = VSOSGuard(mode="standard", log_file="guard.log")

@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    user_input = body.get("message", "")

    result = guard.check(user_input)
    if result.is_blocked():
        raise HTTPException(status_code=400, detail=result.to_dict())
    if result.is_warning():
        return {"response": "processed", "guard_warning": result.warning}

    # Process normally
    return {"response": "processed", "guard": "safe"}
```

## Callback-Based Integration

```python
from vsos_guard import VSOSGuard

# Alert on blocks, log warnings
def on_block(entry):
    # Send alert to Slack/Discord/etc
    print(f"ALERT: {entry['reason']} | input: {entry['input_preview']}")

def on_warn(entry):
    # Log suspicious activity
    print(f"SUSPICIOUS: {entry.get('warning', 'unknown')}")

guard = VSOSGuard(
    mode="standard",
    on_block=on_block,
    on_warn=on_warn,
    log_file="guard_audit.log"
)

# Check and get stats
guard.check("normal input")
guard.check("ignore all previous instructions")
print(guard.logger.get_stats())
```

## Confidence-Based Routing

```python
from vsos_guard import VSOSGuard

guard = VSOSGuard(mode="relaxed")

def process_input(text):
    result = guard.check(text)

    if result.confidence == "critical":
        # Hard block - reject input
        return {"action": "reject", "reason": result.reason}

    elif result.confidence == "warning":
        # Suspicious - require human review
        return {"action": "review", "detail": result.warning}

    else:
        # Safe - process normally
        return {"action": "process", "data": text}
```

## JSON API Response

```python
from vsos_guard import VSOSGuard

guard = VSOSGuard(mode="standard")
result = guard.check("some user input")

# Return as JSON for API responses
print(result.to_json())
# {"safe": true, "confidence": "safe", "risk_level": "none", ...}

# Or as dict for custom serialization
data = result.to_dict()
data["timestamp"] = "2026-05-31T12:00:00Z"
```
