FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    gdb \
    ltrace \
    strace \
    binutils \
    libc6-dbg \
    patchelf \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/supwngo

COPY pyproject.toml setup.py ./
COPY supwngo/ supwngo/

RUN pip install --no-cache-dir -e ".[dev]"

ENTRYPOINT ["supwngo"]
