# Phishing Detector Extension

A browser extension built with [Plasmo](https://www.plasmo.com/) that helps detect potential phishing websites by analyzing both URLs and page content.

## Features

- **URL Analysis**: Uses machine learning to analyze URLs for phishing indicators
- **DOM Analysis**: Inspects page content for suspicious patterns
- **Combined Detection**: Integrates both URL and DOM-based signals for better accuracy
- **Real-time Scanning**: Automatically analyzes pages as you browse

## Technology Stack

- Built with [Plasmo](https://www.plasmo.com/) - a browser extension framework
- React for the popup user interface
- TypeScript for type-safe code
- Service worker background script for continuous protection


### Setup

```bash
# Install dependencies
pnpm install

# Start development server
pnpm dev

# Build for production
pnpm build

```

### Project Structure

- `/background`: Background service worker code
- `/components`: React components for the UI
- `/contents`: Content scripts that run on web pages
- `/lib`: Core functionality and utilities
  - `/dom-detector`: DOM analysis modules
- `/assets`: Extension icons and images
