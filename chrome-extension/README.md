# Phishing Detector Chrome Extension

A Chrome extension that detects potential phishing websites using machine learning and DOM analysis techniques.

## Features

- Real-time phishing detection as you browse
- Analysis of URL patterns using machine learning model
- Analysis of web page content and structure
- Detailed reports of suspicious elements
- Visual indicators for safe vs. suspicious sites

## How It Works

This extension analyzes websites in two ways:

1. **URL Analysis**: Using a machine learning model trained on phishing and legitimate URLs, the extension analyzes features of the URL to identify suspicious patterns.

2. **DOM Analysis**: The extension examines the structure and content of web pages to identify suspicious elements commonly found in phishing sites, such as hidden forms, misleading links, and urgency messaging.

The two analysis methods are combined to produce a final assessment of whether a site might be phishing.

## Installation

1. Download or clone this repository to your computer
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode" (toggle in the top right)
4. Click "Load unpacked" and select the extension directory
5. The extension is now installed and will automatically analyze sites as you browse

## Usage

- The extension icon will change color based on the analysis result:
  - Green: Site appears safe
  - Red: Potential phishing site
- Click the extension icon to see detailed analysis results
- Use the tabs in the popup to view specific details about URL and DOM features
- Click "Report Site" to report a confirmed phishing site to Google

## Privacy

This extension performs all analysis locally in your browser. No URLs or website data are sent to any external servers.

## License

MIT
