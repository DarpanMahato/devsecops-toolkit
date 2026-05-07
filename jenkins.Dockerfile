FROM jenkins/jenkins:lts
USER root

# Install Docker CLI, Python, and dependencies
RUN apt-get update && apt-get install -y \
    docker.io \
    python3 \
    python3-pip \
    wget \
    default-jre \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep
RUN pip install semgrep --break-system-packages

# Install Trivy
RUN wget -qO /usr/share/keyrings/trivy.gpg https://aquasecurity.github.io/trivy-repo/deb/public.key && \
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" > /etc/apt/sources.list.d/trivy.list && \
    apt-get update && apt-get install -y trivy

# Install ZAP
RUN wget -q https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz && \
    tar -xzf ZAP_2.17.0_Linux.tar.gz -C /opt/ && \
    ln -s /opt/ZAP_2.17.0/zap.sh /usr/local/bin/zap.sh && \
    rm ZAP_2.17.0_Linux.tar.gz

USER root