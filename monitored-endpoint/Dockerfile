# monitored-endpoint/Dockerfile
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends procps iproute2 && rm -rf /var/lib/apt/lists/*
COPY monitored-endpoint/differ.py /poller/differ.py
COPY monitored-endpoint/poller.py /poller/poller.py
CMD ["sleep", "infinity"]
