# One image for the vendor services and the scenario runner. The hosts have their own image (assets/host).
FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.9.17 /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy PYTHONUNBUFFERED=1 PATH="/app/.venv/bin:$PATH"
COPY pyproject.toml uv.lock .python-version ./
RUN uv sync --frozen --no-dev
COPY vendors ./vendors
COPY assets/__init__.py ./assets/__init__.py
COPY assets/scenarios ./assets/scenarios
CMD ["python", "-c", "print('set a command per service')"]
