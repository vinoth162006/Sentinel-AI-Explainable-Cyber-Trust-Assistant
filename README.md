# Sentinel-AI-Explainable-Cyber-Trust-Assistant
Sentinel AI is an AI-powered Chrome extension that detects phishing, scam, and suspicious websites using real-time security analysis. It generates an explainable Cyber Trust Score (0–100) based on URL patterns, SSL, domain information, and website behavior, helping users browse the web safely and make informed security decisions.
# Sentinel AI – Explainable Cyber Trust Assistant

## Overview

Sentinel AI is a next-generation AI-powered browser security assistant that helps users determine whether a website can be trusted before they share sensitive information. Instead of displaying generic warnings such as "This website may be dangerous," Sentinel AI provides a transparent **Cyber Trust Score (0–100)** along with detailed explanations of the security risks detected.

The project addresses the growing threat of phishing websites, fake online stores, identity theft, AI-generated scam pages, malicious downloads, and sophisticated social engineering attacks. By combining cybersecurity techniques, artificial intelligence, and explainable machine learning, Sentinel AI empowers users to make informed decisions while browsing the web.

---

## Problem Statement

Cybercriminals continuously create fake websites that imitate trusted brands to steal usernames, passwords, banking details, and personal information. Traditional browser protection mainly relies on blacklists and signature-based detection, which often fail to identify newly created or previously unseen phishing websites.

Furthermore, most security tools simply warn users that a website is unsafe without explaining the reason, making it difficult for non-technical users to understand the risk.

Sentinel AI solves this problem by providing transparent, explainable, and real-time website trust analysis.

---

## Solution

Sentinel AI evaluates multiple website characteristics, including URL patterns, HTTPS configuration, SSL certificate validity, domain age, webpage structure, login forms, suspicious scripts, and scam-related content. These features are analyzed to generate a comprehensive Cyber Trust Score.

Instead of providing only a warning, Sentinel AI explains why a website is considered safe or risky, helping users learn about cybersecurity while protecting them from online threats.

---

## Key Features

* Real-time website security analysis
* Explainable Cyber Trust Score (0–100)
* Phishing website detection
* Suspicious URL analysis
* SSL certificate verification
* HTTPS security validation
* Domain age and reputation analysis
* Scam keyword and social engineering detection
* Login form risk assessment
* Browser extension built using Chrome Manifest V3
* Python FastAPI backend
* AI-ready architecture for future machine learning integration

---

## Technology Stack

### Frontend

* HTML5
* CSS3
* JavaScript

### Browser Extension

* Chrome Extension (Manifest V3)

### Backend

* Python
* FastAPI

### Artificial Intelligence

* Scikit-learn
* TensorFlow (future enhancement)
* Explainable AI (SHAP/LIME)

### Database

* SQLite
* MongoDB (future)

### Development Tools

* Git
* GitHub
* Visual Studio Code

---

## Project Goals

* Protect users from phishing attacks.
* Detect suspicious and malicious websites.
* Explain security risks in simple language.
* Improve cybersecurity awareness.
* Build a scalable AI-powered browser security platform.
* Continuously evolve with modern cyber threats.

---

## Future Roadmap

* AI-powered phishing prediction
* Deepfake website detection
* Fake review detection
* Brand impersonation detection
* QR code scam detection
* Browser behavior analysis
* Threat intelligence integration
* Enterprise dashboard
* Mobile browser support
* Cloud-based threat synchronization

---

## Why Sentinel AI?

Unlike traditional browser security extensions that rely only on blacklists, Sentinel AI focuses on explainable cybersecurity. It helps users understand *why* a website is risky by combining website analysis, AI-driven insights, and transparent security explanations. This approach not only improves protection but also increases user awareness, making the internet a safer place for everyone.

Sentinel AI is designed as a modern cybersecurity research project with the potential to evolve into a practical security solution for individuals, organizations, and educational institutions.
