FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml .
COPY plecost/ plecost/
RUN pip install --no-cache-dir -e ".[fast]"

ENTRYPOINT ["plecost"]
CMD ["--help"]
