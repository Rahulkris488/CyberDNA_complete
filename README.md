# CyberDNA

AI-Powered Network Intrusion Detection & Anomaly Monitoring System

## Overview

CyberDNA is a lightweight cybersecurity research and intrusion detection system designed for live network monitoring, anomaly detection, and packet-based behavioral analysis using machine learning.

The project combines:

* Live packet inspection
* Network anomaly detection
* Machine learning inference
* Autoencoder-based behavioral analysis
* Containerized deployment using Docker

CyberDNA is designed to run directly on Linux systems with host-level network access.

---

# Features

* Real-time network packet monitoring
* AI-based anomaly detection
* TensorFlow autoencoder inference
* Host network analysis
* Portable Docker deployment
* Cybersecurity testing support
* Packet injection simulation scripts
* Multiple Sentinel runtime versions

---

# Project Structure

```bash
.
├── Dockerfile
├── requirements.txt
├── sentinel.py
├── sentinelv2.py
├── sentinelv3.py
├── sentinelv4.py
├── cyberdna_autoencoder.h5
├── scaler.pkl
├── model_metadata.pkl
├── fake_attacker_injector.py
├── trigger_attack.sh
├── trigger_demo.sh
├── .dockerignore
├── .gitignore
```

---

# Requirements

## System Requirements

* Linux system recommended
* Docker installed
* Root / sudo privileges
* Host networking support

## Tested Environment

* Arch Linux
* Docker Engine
* Python 3.9 Slim Container

---

# Installation

## Option 1 — Run using Docker Hub (Recommended)

Pull the prebuilt image:

```bash
docker pull rahulkrishnatp/cyberdna:latest
```

Run the container:

```bash
sudo docker run -it --rm --net=host --privileged rahulkrishnatp/cyberdna:latest
```

---

## Option 2 — Build from Source

Clone the repository:

```bash
git clone https://github.com/Rahulkris488/CyberDNA_complete.git
cd CyberDNA_complete
```

Build the Docker image:

```bash
docker build -t cyberdna:arch .
```

Run the container:

```bash
sudo docker run -it --rm --net=host --privileged cyberdna:arch
```

---

# Docker Details

The container uses:

* `--net=host`
* `--privileged`

These permissions are required for:

* Packet capture
* Raw socket operations
* Network interface monitoring
* Cybersecurity packet analysis

---

# Sentinel Versions

## sentinel.py

Basic prototype runtime.

## sentinelv2.py

Improved anomaly detection runtime.

## sentinelv3.py

Primary runtime with enhanced packet analysis and ML integration.

## sentinelv4.py

Experimental runtime with advanced detection features.

---

# Machine Learning

CyberDNA currently uses:

* TensorFlow CPU runtime
* Autoencoder-based anomaly detection
* Serialized scaling and metadata models

Model Files:

```bash
cyberdna_autoencoder.h5
scaler.pkl
model_metadata.pkl
```

---

# Attack Simulation

CyberDNA includes testing utilities:

## Trigger simulated attacks

```bash
./trigger_attack.sh
```

## Run demo workflow

```bash
./trigger_demo.sh
```

## Fake attacker injector

```bash
python fake_attacker_injector.py
```

---

# Security Notice

This project is intended for:

* Educational purposes
* Security research
* Authorized cybersecurity testing
* Network monitoring labs

Do NOT use this project on networks you do not own or have permission to test.

---

# Performance Notes

* TensorFlow significantly increases image size
* Docker image may exceed 2GB
* First-time pull/build may take time
* Runtime performance depends on host network activity

---

# Future Improvements

Planned enhancements:

* Lightweight inference runtime
* ONNX / TensorFlow Lite support
* Distributed monitoring
* Dashboard UI
* Live alerts
* Threat scoring
* Real-time visualization
* Cloud deployment support
* Kubernetes orchestration

---

# Development Goals

CyberDNA is part of an ongoing cybersecurity R&D initiative focused on:

* Intrusion Detection Systems (IDS)
* AI-assisted cybersecurity
* Network behavior analytics
* Packet intelligence
* Lightweight security monitoring systems

---

# Author

Rahul Krishna

Cybersecurity Research & Development

---

# License

This project is provided for educational and research purposes.

Add a proper open-source license before production or public distribution.
