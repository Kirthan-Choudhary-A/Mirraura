FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends strace bash && rm -rf /var/lib/apt/lists/*
COPY sensor/parser.py /sensor/parser.py
COPY sensor/tracer.py /sensor/tracer.py
COPY sensor/sensor.py /sensor/sensor.py
WORKDIR /samples
CMD ["sleep", "infinity"]
