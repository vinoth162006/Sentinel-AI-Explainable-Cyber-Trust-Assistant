# Sentinel AI – Explainable Cyber Trust Assistant

Sentinel AI is a modular, production-ready Chrome Extension and Python backend system designed to analyze the safety of visited websites in real-time. It computes a **Cyber Trust Score (0–100)**, classifies safety (Safe, Suspicious, Dangerous), and provides granular explanation cards for why a website holds that rating.

---

## Project Structure

```
sentinel-ai/
├── README.md                  # Project documentation & instructions
├── extension/                 # Chrome Extension Source
│   ├── manifest.json          # Manifest V3 configuration
│   ├── popup.html             # Popup GUI structure
│   ├── popup.css              # Cyber-themed styling (Dark Mode)
│   ├── popup.js               # Heuristics analysis & UI controller
│   ├── background.js          # Service worker for background requests
│   ├── content.js             # Webpage DOM risk inspector
│   └── icons/                 # Extension PNG assets
│       ├── generate_icons.py  # Automation script to draw the icon shapes
│       ├── icon16.png
│       ├── icon48.png
│       └── icon128.png
└── backend/                   # Python FastAPI & Machine Learning Backend (Phase 2+)
    ├── requirements.txt       # Dependencies
    ├── main.py                # FastAPI Application Entry
    ├── ml_classifier.py       # Phishing url feature extractor & classifier
    ├── train.py               # ML training script utilizing public datasets
    └── utils/
        ├── ssl_checker.py     # SSL certificate validation helper
        ├── whois_checker.py   # Domain registration age helper
        └── content_analyzer.py# Script parsing helper
```

---

## Getting Started

### Phase 1: Running the Extension

To install and run the Chrome Extension locally:

1. Open Google Chrome.
2. Navigate to `chrome://extensions/` in your address bar.
3. Enable **Developer mode** using the toggle switch in the top-right corner.
4. Click **Load unpacked** in the top-left corner.
5. Select the `extension` folder located inside the `sentinel-ai` project directory (e.g., `d:/sentinel-ai/extension`).
6. Pin the **Sentinel AI** extension from your Extensions toolbar.
7. Click the extension icon to run a client-side scan on any website you are currently visiting!

### Phase 2: Running the Python Backend (FastAPI)

1. Navigate to the `backend/` directory.
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Start the FastAPI server using Uvicorn:
   ```bash
   uvicorn main:app --reload --port 8000
   ```
4. The extension will automatically route analysis requests through this local backend API.

---

## Cybersecurity Heuristics (Phase 1)
The extension implements a weighted scoring algorithm:
* **HTTPS Protocol (-35 pts if missing)**: Checks if the site communicates using insecure HTTP.
* **IP Address Host (-20 pts)**: Detects if the site bypasses domain names and hosts directly on raw IP addresses.
* **Suspicious TLD (-15 pts)**: Flags malicious-prone domains like `.zip`, `.mov`, `.tk`, etc.
* **URL Length (-10 pts)**: Detects lengthy URLs designed to obscure domains.
* **Deep Subdomain Count (-10 pts)**: Counts subdomain layers to detect brand spoofing.
* **URL '@' Character (-15 pts)**: Flags spoof redirection tricks.
* **Excessive Domain Hyphens (-10 pts)**: Detects typosquatting indicators.
