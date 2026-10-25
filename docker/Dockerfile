FROM node:24-bookworm-slim

ARG CLAUDE_VERSION=latest
ARG CODEX_VERSION=latest
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv git ca-certificates curl ffmpeg ripgrep \
    && rm -rf /var/lib/apt/lists/* \
    && npm install --global "@anthropic-ai/claude-code@${CLAUDE_VERSION}" "@openai/codex@${CODEX_VERSION}" \
    && npm cache clean --force \
    && install -d -o node -g node -m 0700 /home/node/.codex /home/node/.claude /run/sandbox-proxy \
    && install -d /opt/sandbox /run/sandbox /workspace

COPY sandbox.py inner.py seccomp.py transport.py /opt/sandbox/
COPY docker/entry.py docker/proxy.py docker/selftest.py /opt/sandbox/
COPY AGENT_POLICY.md /run/sandbox/AGENT_POLICY.md
RUN cp /run/sandbox/AGENT_POLICY.md /home/node/.codex/AGENTS.override.md \
    && cp /run/sandbox/AGENT_POLICY.md /home/node/.claude/CLAUDE.md \
    && chown -R node:node /home/node /run/sandbox-proxy

ENV HOME=/home/node \
    CODEX_HOME=/home/node/.codex \
    CLAUDE_CONFIG_DIR=/home/node/.claude \
    DISABLE_AUTOUPDATER=1 \
    DISABLE_UPDATES=1
USER 1000:1000
WORKDIR /workspace
ENTRYPOINT ["python3", "-I", "-S", "/opt/sandbox/entry.py"]
CMD ["bash"]
