# Automated Phishing Email Detection & SOC Alerting Lab

## Project Overview

This project demonstrates an end-to-end phishing email detection and security monitoring workflow using Python, Splunk Enterprise, Gmail, and VirusTotal.

The lab was designed to simulate how a Security Operations Center (SOC) can automatically collect email data, extract potentially suspicious URLs, enrich those URLs with threat intelligence, forward structured security events to a SIEM, detect phishing indicators, and notify an analyst when suspicious activity is identified.

A Python-based phishing simulation generates controlled test emails in the lab environment. A separate email monitoring script retrieves the messages from Gmail, extracts relevant information such as the sender, recipient, subject, body, attachments, and URLs, and submits URLs to VirusTotal for reputation analysis.

The enriched email events are then forwarded to Splunk Enterprise through the HTTP Event Collector (HEC) and stored in a dedicated index for analysis.

Splunk is used to:

- Monitor phishing-related email activity
- Analyze email senders and embedded URLs
- Display VirusTotal enrichment results
- Identify phishing indicators using SPL detection logic
- Visualize security activity through a SOC dashboard
- Generate high-severity scheduled alerts
- Send automated email notifications to the analyst

The project demonstrates the integration of security automation, threat intelligence, SIEM monitoring, detection engineering, and SOC alerting within a controlled lab environment.

## Architecture

The project follows the workflow below:

Phishing Simulation (`phish_sender.py`)
        ↓
Gmail
        ↓
Python Email Monitor (`email_monitor.py`)
        ↓
Email Parsing & URL Extraction
        ↓
VirusTotal API Enrichment
        ↓
Structured JSON Security Event
        ↓
Splunk HTTP Event Collector (HEC)
        ↓
Splunk `gmail_logs` Index
        ↓
SPL Detection & Analysis
        ↓
Phishing Detection Alert
        ↓
SOC Dashboard + Analyst Email Notification

## Technologies Used

- Python 3
- Splunk Enterprise
- Splunk HTTP Event Collector (HEC)
- Splunk Search Processing Language (SPL)
- Gmail / IMAP
- VirusTotal API
- Kali Linux
- Ubuntu Server
- VirtualBox
- SMTP / Gmail App Password
- JSON
- python-dotenv
- Requests

## Lab Environment

The project was developed in a virtualized cybersecurity lab environment using VirtualBox. Separate virtual machines were used to isolate the security monitoring components and simulate a realistic SOC architecture.

### Kali Linux

Kali Linux was used as the automation and security testing system.

Primary functions included:

- Running the `phish_sender.py` phishing simulation script
- Running the `email_monitor.py` monitoring and automation script
- Connecting to Gmail through IMAP
- Extracting URLs and email metadata
- Querying the VirusTotal API for URL reputation
- Sending enriched security events to Splunk through HEC
- Testing connectivity between the monitoring system and Splunk

### Ubuntu Server

Ubuntu Server was used to host Splunk Enterprise.

Primary functions included:

- Hosting the Splunk Enterprise SIEM
- Receiving JSON events through the Splunk HTTP Event Collector (HEC)
- Storing email security events in the `gmail_logs` index
- Running SPL searches and phishing detection rules
- Hosting the phishing monitoring dashboard
- Generating scheduled high-severity alerts
- Sending automated email notifications to the analyst

### Gmail

Gmail was used as the email platform for the controlled phishing simulation.

The Python monitoring script connects to Gmail through IMAP and processes messages from the monitored mailbox. SMTP was also configured in Splunk to deliver automated phishing alert notifications to the analyst.

### VirusTotal

VirusTotal was integrated through its API to provide threat-intelligence enrichment for URLs extracted from monitored emails.

For each extracted URL, the monitoring script records available reputation statistics such as:

- Malicious detections
- Suspicious detections
- Harmless detections
- Undetected results
- VirusTotal analysis ID

This enrichment allows Splunk analysts to examine both email-based phishing indicators and external URL reputation data.

## Network and Data Flow

The primary communication flow in the lab is:

1. `phish_sender.py` generates a controlled phishing simulation email.
2. The simulated email is delivered to the monitored Gmail mailbox.
3. `email_monitor.py` retrieves and parses the email.
4. Embedded URLs are extracted from the message.
5. URLs are submitted to the VirusTotal API for reputation analysis.
6. Email metadata and VirusTotal results are combined into a structured JSON event.
7. The event is transmitted to Splunk Enterprise using HEC over port `8088`.
8. Splunk indexes the event in `gmail_logs` with the `email_event` sourcetype.
9. SPL detection logic evaluates the event for phishing indicators.
10. Matching events trigger a high-severity Splunk alert.
11. Splunk records the alert under Triggered Alerts and sends an automated email notification to the analyst.
