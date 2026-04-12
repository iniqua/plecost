FROM python:3.11-slim
LABEL org.opencontainers.image.source=https://github.com/iniqua/plecost
LABEL org.opencontainers.image.description="Plecost - WordPress Security Scanner"
LABEL org.opencontainers.image.licenses=FSL-1.1-MIT

WORKDIR /app
COPY pyproject.toml README.md ./
COPY plecost/ ./plecost/
RUN pip install --no-cache-dir -e ".[fast]"

ENTRYPOINT ["plecost"]
CMD ["--help"]
