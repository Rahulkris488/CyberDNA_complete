FROM python:3.9-slim

# Set working directory
WORKDIR /app

# 1. Install System Dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    tshark \
    wireless-tools \
    net-tools \
    iproute2 \
    aircrack-ng \
    pciutils \
    usbutils \
    rfkill \
    procps \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# 2. Install Python Libraries
RUN pip install --no-cache-dir \
    pandas \
    numpy \
    scikit-learn \
    tensorflow-cpu \
    h5py

# 3. Copy Artifacts
COPY cyberdna_autoencoder.h5 .
COPY scaler.pkl .
COPY model_metadata.pkl .
COPY sentinelv3.py .

# 4. Run Command
CMD ["python", "sentinelv3.py"]
