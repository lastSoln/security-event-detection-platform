# Security Event Detection & Analytics Platform

A collaborative cybersecurity and data engineering project that simulates,
ingests, processes, analyzes, and detects security events in real time.

## Project Goal

Build a small-scale security analytics platform that can:

- Generate realistic security events
- Stream events through Kafka
- Process events using Apache Spark
- Store processed security data
- Detect suspicious activity using security detection rules
- Generate security alerts
- Visualize security activity through a dashboard

The project combines:

- Data Engineering
- Cybersecurity
- Streaming Data
- Data Analytics
- Security Monitoring

## Architecture

```text
Security Event Simulator
          |
          v
       Kafka
          |
          v
   Spark Streaming
          |
          v
   Processed Events
          |
          +----------------+
          |                |
          v                v
    Data Storage     Detection Engine
                           |
                           v
                      Security Alerts
                           |
                           v
                       Dashboard

Initial Threats

Our first version will detect:

Brute-force login attempts
Port scanning
Suspicious login activity
HTTP traffic anomalies
Technology Stack
Python
Apache Kafka
Apache Spark
PostgreSQL
Docker
GitHub

docs/           Project documentation
simulator/      Security event generation
ingestion/      Kafka ingestion
processing/     Spark processing
detection/      Security detection engine
storage/        Data storage
dashboard/      Analytics dashboard
tests/          Automated tests
scripts/        Utility scripts

Team
Data Engineering
Data architecture
Data schemas
Kafka ingestion
Spark processing
Data storage
Data quality
Analytics
Cybersecurity
Threat modeling
Attack simulation
Detection rules
Risk scoring
Security validation

Project Status

🚧 Phase 0 — Project Foundation

