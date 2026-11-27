FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    VIBEAUDIT_NO_CACHE=1

RUN groupadd --system vibeaudit && useradd --system --gid vibeaudit --create-home vibeaudit

WORKDIR /tmp/build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip install --no-cache-dir . && rm -rf /tmp/build

USER vibeaudit
WORKDIR /workspace

ENTRYPOINT ["vibeaudit"]
CMD ["--help"]
