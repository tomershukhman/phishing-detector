// page-readiness.js - Script that gets injected early to monitor page readiness
// This script runs at document_start to ensure it's loaded as early as possible

// Wrapper function to encapsulate the extension code
(function() {
  // Small logging utility for this script
  const log = (message, data) => {
    if (data) {
      console.log(`[PHISHING-DETECTOR-PAGE-READINESS] ${message}`, data);
    } else {
      console.log(`[PHISHING-DETECTOR-PAGE-READINESS] ${message}`);
    }
  };

  log("Page readiness script injected", { 
    url: window.location.href,
    time: new Date().toISOString(),
    readyState: document.readyState
  });

  // Function to notify the background script that the page is ready
  function notifyPageReady() {
    log("Page ready notification from early script", { readyState: document.readyState });
    
    try {
      // Send a message to the main content script to indicate page is ready
      // We don't send directly to background because DOM analysis will happen in the main content script
      window.dispatchEvent(new CustomEvent('phishing-detector-page-ready', { 
        detail: { timestamp: Date.now() } 
      }));
    } catch (e) {
      log("Error notifying page ready", { error: e.message });
    }
  }

  // Listen for DOMContentLoaded event
  document.addEventListener('DOMContentLoaded', function() {
    log("DOMContentLoaded event fired");
    notifyPageReady();
  });

  // Also check if document is already ready
  if (document.readyState !== 'loading') {
    log("Document already loaded, notifying immediately");
    notifyPageReady();
  }
})();
