"""API keys with scopes. Keys come from VENDOR_API_KEYS as 'key:scope1,scope2;key2:scope'."""

from typing import Literal

from fastapi import HTTPException, Request

Scope = Literal["feed", "read", "respond", "ingest"]


def load_keys(spec: str) -> dict[str, set[str]]:
    keys: dict[str, set[str]] = {}
    for entry in filter(None, (e.strip() for e in spec.split(";"))):
        key, _, scopes = entry.partition(":")
        keys[key.strip()] = {s.strip() for s in scopes.split(",") if s.strip()}
    return keys


def require_scope(scope: Scope):
    """FastAPI dependency: 401 for an unknown or missing key, 403 when the key lacks the scope."""

    def check(request: Request) -> str | None:
        key = request.headers.get("X-Api-Key")
        scopes = request.app.state.api_keys.get(key) if key else None
        if scopes is None:
            raise HTTPException(status_code=401, detail="unknown API key")
        if scope not in scopes:
            raise HTTPException(status_code=403, detail=f"API key lacks scope '{scope}'")
        return key

    return check
