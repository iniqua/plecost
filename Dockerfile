FROM python:3.6-slim

RUN apt-get update && \
    apt-get install -y python3-lxml


RUN /usr/local/bin/python -m pip install -U pip && \
    /usr/local/bin/python -m pip install plecost


ENTRYPOINT ["/usr/local/bin/plecost"]