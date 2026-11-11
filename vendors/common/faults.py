"""Random 429/500 responses on feed and lookup reads, to exercise client retry logic."""

from random import Random

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send


class FaultMiddleware:
    def __init__(self, app: ASGIApp, rate_429: float = 0.0, rate_500: float = 0.0,
                 retry_after: int = 2, rng: Random | None = None):
        self.app = app
        self.rate_429 = rate_429
        self.rate_500 = rate_500
        self.retry_after = retry_after
        self.rng = rng or Random()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["method"] == "GET" and "/actions/" not in scope["path"]:
            roll = self.rng.random()
            if roll < self.rate_429:
                response = JSONResponse({"error": "rate limited"}, status_code=429,
                                        headers={"Retry-After": str(self.retry_after)})
                await response(scope, receive, send)
                return
            if roll < self.rate_429 + self.rate_500:
                await JSONResponse({"error": "internal error"}, status_code=500)(scope, receive, send)
                return
        await self.app(scope, receive, send)
