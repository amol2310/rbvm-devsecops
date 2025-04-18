FROM python:3.11-slim

# Install Trivy
RUN apt-get update && \
    apt-get install -y wget unzip jq curl && \
    wget https://github.com/aquasecurity/trivy/releases/download/v0.61.1/trivy_0.61.1_Linux-64bit.tar.gz && \
    tar -xzf trivy_0.61.1_Linux-64bit.tar.gz && \
    mv trivy /usr/local/bin/ && rm trivy_0.61.1_Linux-64bit.tar.gz

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . /scanner
WORKDIR /scanner

# Entrypoint
ENTRYPOINT ["bash", "entrypoint.sh"]