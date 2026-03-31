# 🛡️ Aegis Sentinel v3.0 – Real-Time Threat Detection & Monitoring System

Aegis Sentinel is a full-stack cybersecurity monitoring platform designed to detect, analyze, and respond to suspicious network activity in real time. The system uses rule-based detection and behavioral analysis techniques to identify malicious patterns such as rapid requests, bot activity, and anomalous traffic.

## 🚧 Status

Active Development (Functional Prototype Available)

This project is continuously evolving with enhancements in detection logic, system architecture, and monitoring capabilities.

## 🔥 Key Features
🔐 JWT-Based Authentication System (Login & Role Handling)

📡 Real-Time Request Monitoring & Analysis

🚫 Automated IP Blocking & Rate Limiting

🧠 Threat Scoring Engine (Behavioral + Rule-Based Detection)

📊 Interactive SOC-Style Dashboard

📁 Comprehensive Logging System (Requests, Alerts, Threats)

⚠️ Dynamic Alert Generation & Tracking

🧪 Traffic Simulation & Stress Testing Module

## 🧠 Detection Capabilities

The system analyzes multiple dimensions of incoming traffic:

Request Rate Analysis (DDoS-like behavior)

Suspicious Headers Detection

Bot & Scanner Identification (Nmap, SQLMap, Burp, etc.)

Path-Based Threat Detection (/admin, /wp-login, etc.)

Behavioral Analysis (request frequency, session patterns)

Risk Scoring & Severity Classification (Low → Critical)

## ⚙️ Tech Stack
Backend: FastAPI (Python)

Frontend: HTML, TailwindCSS, JavaScript

Visualization: Chart.js

Authentication: JWT (PyJWT)

Database: SQLite (Tracking, Logs, Alerts)

Security Concepts: Rate Limiting, Threat Detection, Traffic Analysis

## 🏗️ System Architecture

Client Request

↓

FastAPI Backend

↓

Threat Detection Engine (Rule + Scoring)

↓

Database Logging (IP Tracking + Alerts)

↓

JSON Response

↓

Frontend Dashboard (Visualization + Monitoring)

## 📊 Dashboard Capabilities

📈 Traffic Timeline Visualization

🌐 IP Threat Registry (Live Tracking)

⚠️ Active Alerts Panel

🧾 Request Inspector (Detailed Analysis)

💻 Terminal-Style Live Logs

🔍 Threat Score & Risk Level Display


# ▶️ How to Run
### 1️⃣ Clone Repository

```
git clone https://github.com/Ki1shan/Aegis-Sentinel

cd Aegis-Sentinel
```
### 2️⃣ Install Dependencies
```
pip install -r requirements.txt
```
### 3️⃣ Run Server
```
python main.py
```

### 4️⃣ Access Dashboard
```
http://127.0.0.1:8000/
```

### 🔑 Default Credentials
```
Username: admin
Password: aegis2024!
```

## 🚀 Future Enhancements

🔄 Integration with Real Network Traffic (Live Capture)

🤖 Machine Learning Integration (Future Scope)

☁️ Cloud Deployment (AWS / Docker)

📧 Alerting System (Email / Webhooks)

🔐 Role-Based Access Control (RBAC Expansion)

📡 SIEM Integration (Splunk / ELK)

## 📌 Learning Outcomes

Designing a real-time threat detection system

Understanding request behavior & attack patterns

Implementing authentication and secure APIs

Building a full-stack cybersecurity dashboard

Applying detection logic inspired by SOC environments

## ⚠️ Disclaimer
This project is built for educational and demonstration purposes only.
It simulates threat detection using controlled traffic and does not replace production-grade IDS/IPS systems.
