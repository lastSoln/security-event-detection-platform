# Security Event Detection & Analytics Platform
# Implementation Plan

## 1. Project Overview

We are building a small-scale, real-time security monitoring and analytics platform combining Data Engineering and Cybersecurity.

The system will:

1. Generate simulated security events
2. Stream events through Apache Kafka
3. Process events using Apache Spark
4. Detect suspicious activity
5. Generate security alerts
6. Store and analyze security data
7. Display the results through a dashboard

The goal is to demonstrate an end-to-end security data pipeline rather than recreate a commercial SIEM such as Splunk.

---

## 2. Why Are We Building This?

Modern systems generate large amounts of security data such as:

- Login events
- HTTP requests
- DNS queries
- Firewall events
- Network activity

Security teams cannot manually inspect all of these events.

Our system will demonstrate how these events can be:

```text
Generated
    ↓
Collected
    ↓
Streamed
    ↓
Processed
    ↓
Analyzed
    ↓
Detected
    ↓
Turned into alerts

3. Team Responsibilities
Data Engineering — Srish

Primary responsibilities:

Data architecture
Security event schema
Data validation
Kafka ingestion
Kafka producer and consumer
Spark Structured Streaming
Data transformations
Windowed aggregations
Data storage
Data quality
Pipeline monitoring
CI/CD
Cybersecurity — Teammate

Primary responsibilities:

Threat modeling
Attack scenario design
Security event requirements
Attack simulation
Detection rules
Severity classification
Risk scoring
Detection validation
Security-focused analytics
4. How We Collaborate

GitHub is the central collaboration platform.

We use:

GitHub Issues
GitHub Milestones
Feature branches
Pull Requests
Code reviews
Automated tests

Neither developer should normally work directly on main.

Branch naming

Use:

feature/<short-description>

Examples:

feature/event-schema
feature/event-simulator
feature/kafka-producer
feature/spark-processing
feature/bruteforce-detection
Development workflow
GitHub Issue
     ↓
Create feature branch
     ↓
Implement
     ↓
Test
     ↓
Commit
     ↓
Push branch
     ↓
Pull Request
     ↓
Code review
     ↓
Merge into main
5. Development Phases
Milestone #1 — Foundation

Goal:

Establish the technical and security foundation.

Data Engineering
Define security event schema
Set up development environment
Configure Python project
Configure dependencies
Cybersecurity
Define threat model
Define attack scenarios
Define attack simulation requirements
Both
Review architecture
Agree on interfaces
Review the event schema
Milestone #2 — Security Event Simulator

Goal:

Build a Python simulator that generates realistic security events.

Initial events:

LOGIN
HTTP
DNS
FIREWALL

The simulator should generate both normal activity and attack scenarios.

Primary owner: Cybersecurity

Data Engineering will validate that generated events conform to the agreed schema.

Milestone #3 — Kafka Ingestion

Goal:

Introduce real-time event streaming.

Event Simulator
      ↓
Kafka Producer
      ↓
Kafka
      ↓
Kafka Consumer

Primary owner: Data Engineering

Cybersecurity will provide attack scenarios and verify that security information is preserved.

Milestone #4 — Spark Processing

Goal:

Process streaming security events using Spark Structured Streaming.

Kafka
  ↓
Spark
  ↓
Validation
  ↓
Cleaning
  ↓
Transformation
  ↓
Aggregation
  ↓
Processed Events

Primary owner: Data Engineering

Cybersecurity will define what information is required by the detection engine.

Milestone #5 — Detection Engine

Goal:

Analyze processed events and generate security alerts.

Initial detections:

Brute-force login
Port scanning
Suspicious login
HTTP traffic anomaly

Primary owner: Cybersecurity

Data Engineering will provide the processed data interface and support storage/querying of detection results.

6. Initial Attack Scenarios

The first version will focus on:

Brute-Force Login

Repeated failed authentication attempts from the same source.

Port Scanning

One source contacting many destination ports within a short period.

Suspicious Login

Multiple failed login attempts followed by a successful login.

HTTP Traffic Anomaly

An unusually high number of HTTP requests from a source within a short period.

Detailed security definitions are maintained in:

threat-model.md

Detection logic is maintained in:

detection-rules.md

7. Technology Stack
Python
Apache Kafka
Apache Spark Structured Streaming
PostgreSQL
Docker / Docker Compose
Pytest
Git
GitHub

Dashboard technology will be selected later.

8. Definition of Done

A task is complete when:

The functionality is implemented
Tests are written where appropriate
The code works locally
Documentation is updated where necessary
The Pull Request has been reviewed
The Pull Request has been merged into main
9. MVP

The first complete version should support:

Security Event
      ↓
Kafka
      ↓
Spark
      ↓
Processed Event
      ↓
Detection Engine
      ↓
Security Alert

The MVP should detect:

Brute-force login
Port scanning
Suspicious login
HTTP anomaly

Additional features such as advanced storage, dashboards, monitoring, and machine learning will be added after the MVP works.

10. Current Status

Current milestone:

Milestone #1 — Foundation

Srish
Define Security Event Schema
Set Up Development Environment
Cybersecurity
Define Threat Model
Define Attack Simulation Requirements
Both
Review Initial Architecture





