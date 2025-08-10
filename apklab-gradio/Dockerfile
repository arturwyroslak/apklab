# Use a Python base image
FROM python:3.10-slim

# Install necessary dependencies
RUN apt-get update && apt-get install -y \
    openjdk-17-jre-headless \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Create directories for tools, temp files, and downloads
RUN mkdir -p tools temp downloads

# Download and install external tools
# 1. apktool
RUN wget https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar -O tools/apktool.jar

# 2. uber-apk-signer
RUN wget https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar -O tools/uber-apk-signer.jar

# 3. jadx
RUN wget https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip -O jadx.zip && \
    unzip jadx-1.4.7.zip -d tools/ && \
    mv tools/jadx-1.4.7 tools/jadx && \
    rm jadx.zip

# Copy the application requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application source code
COPY apklab-gradio-app.py .

# Expose the Gradio port
EXPOSE 7860

# Set the command to run the application
CMD ["python", "apklab-gradio-app.py"]
