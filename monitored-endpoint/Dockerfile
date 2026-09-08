# monitored-endpoint/Dockerfile
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends procps iproute2 && rm -rf /var/lib/apt/lists/*
COPY differ.py /poller/differ.py
COPY poller.py /poller/poller.py
CMD ["sleep", "infinity"]
