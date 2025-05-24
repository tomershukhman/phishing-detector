// Background service worker for phishing detection using Plasmo framework
import handlers from "./messages/handlers";
import { backgroundLogger as logger } from "../lib/logger";

const {
  analyzeTabUrl,
  updateBadge,
  handleGetTabAnalysisData,
  handleAnalyzeUrlManually,
  handlePageReady,
  getAnalyzedTabsData,
  getPendingAnalyses
} = handlers;

// Create a global map to track when pages were loaded
if (typeof self !== "undefined") {
  // @ts-ignore
  self.pageLoadTimestamps = self.pageLoadTimestamps || new Map();
}

// Helper function to access the global page load timestamps map
export function getPageLoadTimestamps() {
  // @ts-ignore
  return self.pageLoadTimestamps;
}

// Helper function for consistent logging
function logBackground(message, data = {}) {
  logger.log(message, data);
}

logger.log("PHISHING DETECTOR BACKGROUND SERVICE WORKER STARTED", {
  timestamp: new Date().toISOString(),
  version: "1.1.0"
});

// Initialize on startup
(async function initializeServiceWorker() {
  logBackground("Background service worker initializing");

  // Check if there are any open tabs we should analyze
  try {
    const tabs = await chrome.tabs.query({
      url: ["http://*/*", "https://*/*"],
      status: "complete"
    });

    logBackground("Found existing tabs to potentially analyze", { count: tabs.length });

    const analyzedTabsData = getAnalyzedTabsData();
    const pendingAnalyses = getPendingAnalyses();

    // Queue analysis for tabs that aren't already analyzed
    tabs.forEach(tab => {
      if (tab.id && tab.url && !analyzedTabsData.has(tab.id) && !pendingAnalyses.has(tab.id)) {
        // We'll trigger analysis for this tab
        setTimeout(() => {
          if (!analyzedTabsData.has(tab.id) && !pendingAnalyses.has(tab.id)) {
            logBackground("Initializing analysis for existing tab", { tabId: tab.id, url: tab.url });
            pendingAnalyses.set(tab.id, Date.now());
            analyzeTabUrl(tab.id, tab.url).then(() => {
              pendingAnalyses.delete(tab.id);
            }).catch(err => {
              logBackground("Error analyzing existing tab", { tabId: tab.id, error: err });
              pendingAnalyses.delete(tab.id);
            });
          }
        }, 1000 + Math.random() * 2000); // Stagger the analyses to not overwhelm
      }
    });
  } catch (error) {
    logBackground("Error during initialization", { error });
  }
})();

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Only care about completed loads of http/https pages
  if (changeInfo.status === "complete" && tab.url && tab.url.startsWith("http")) {
    logBackground("Tab updated with complete status", { tabId, url: tab.url });

    // Record the page load timestamp
    const pageLoadTimestamps = getPageLoadTimestamps();
    const loadTimestamp = Date.now();
    pageLoadTimestamps.set(tabId, loadTimestamp);
    logBackground("Recorded page load timestamp", { tabId, url: tab.url, timestamp: loadTimestamp });

    const analyzedTabsData = getAnalyzedTabsData();
    const pendingAnalyses = getPendingAnalyses();

    // Always perform a new analysis when a page is refreshed/loaded
    // This ensures we get fresh analysis every time a page loads

    // Check if this tab is already being analyzed
    if (pendingAnalyses.has(tabId)) {
      const startTime = pendingAnalyses.get(tabId);
      const timeSinceStart = Date.now() - startTime;

      // If analysis has been running for too long, restart it
      if (timeSinceStart > 10000) { // 10 seconds
        logBackground("Analysis has been pending too long, restarting", { tabId, url: tab.url });
        pendingAnalyses.delete(tabId);
      } else {
        logBackground("Analysis already in progress for this tab", { tabId, url: tab.url });
        return;
      }
    }

    // Start a new analysis
    logBackground("Starting new analysis for updated tab", { tabId, url: tab.url });
    pendingAnalyses.set(tabId, Date.now());

    analyzeTabUrl(tabId, tab.url).then(() => {
      pendingAnalyses.delete(tabId);
    }).catch(err => {
      logBackground("Error during tab analysis", { tabId, url: tab.url, error: err });
      pendingAnalyses.delete(tabId);
    });
  }
});

// Listen for tab removal to clean up our data
chrome.tabs.onRemoved.addListener((tabId) => {
  logBackground("Tab removed, cleaning up data", { tabId });
  const analyzedTabsData = getAnalyzedTabsData();
  const pendingAnalyses = getPendingAnalyses();

  analyzedTabsData.delete(tabId);
  pendingAnalyses.delete(tabId);
});

// Listen for messages from popup or content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  logBackground("Message received in background", {
    action: message.action || message.type,
    sender: sender.tab ? `Tab ${sender.tab.id}` : 'Popup/Extension'
  });

  // Route messages to appropriate handlers
  switch (message.action) {
    case "getTabAnalysisData":
      handleGetTabAnalysisData(message, sender, sendResponse);
      return true;

    case "analyzeUrlManually":
      return handleAnalyzeUrlManually(message, sender, sendResponse);

    case "pageReady":
      if (sender.tab) {
        return handlePageReady(message, sender, sendResponse);
      }
      break;

    case "TEST":
      // Handle performance data from phishing analysis
      if (message.data) {
        logBackground("Performance data received", {
          url: message.data.url,
          groupId: message.data.groupId,
          isPhishing: message.data.isPhishing,
          responseTimeMs: message.data.responseTimeMs,
          heapChangeBytes: message.data.heapChangeBytes
        });
        
        // Send data over HTTP to the verdict endpoint
        const data = message.data;
        fetch('http://127.0.0.1:6543/verdict', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(data)
        })
        .then(response => {
          if (response.ok) {
            logBackground("Performance data sent successfully to verdict endpoint", {
              status: response.status,
              url: data.url
            });
          } else {
            logBackground("Failed to send performance data to verdict endpoint", {
              status: response.status,
              statusText: response.statusText,
              url: data.url
            });
          }
        })
        .catch(error => {
          logBackground("Error sending performance data to verdict endpoint", {
            error: error.message,
            url: data.url
          });
        });
        
        if (sendResponse) {
          sendResponse({ success: true, message: "Performance data received and sent to verdict endpoint" });
        }
        return true;
      }
      break;

    case "forwardLog":
      // Handle forwarded logs from DOM detector or other content scripts
      const { logData } = message;
      if (logData && logData.component && logData.message) {
        const { component, level, message: logMessage, data, timestamp } = logData;
        const prefix = `[FORWARDED-${component}][${timestamp || new Date().toISOString()}]`;

        // Parse data if it's a string
        let parsedData;
        try {
          parsedData = typeof data === 'string' ? JSON.parse(data) : data;
        } catch (e) {
          parsedData = { rawData: data, parseError: true };
        }

        // Log using background logger to ensure visibility in extension console
        switch (level) {
          case 'DEBUG':
            logger.debug(`${prefix} ${logMessage}`, parsedData);
            break;
          case 'INFO':
            logger.log(`${prefix} ${logMessage}`, parsedData);
            break;
          case 'WARN':
            logger.warn(`${prefix} ${logMessage}`, parsedData);
            break;
          case 'ERROR':
            logger.error(`${prefix} ${logMessage}`, parsedData);
            break;
          default:
            logger.log(`${prefix} ${logMessage}`, parsedData);
        }

        if (sendResponse) {
          sendResponse({ success: true });
        }
        return true;
      }
      break;
  }

  // Handle feature state update messages
  if (message.type === "UPDATE_FEATURE_STATE") {
    return handlers.handleUpdateFeatureState(message.data, sender, sendResponse);
  }

  return false; // No async response
});

// Alternative implementation matching the exact format from the example
// This can be used instead of or in addition to the switch-case handler above
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'TEST') {
    const data = message.data;
    
    fetch('http://127.0.0.1:6543/verdict', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data)
    })
    .then(response => {
      logBackground("HTTP POST to verdict endpoint completed", {
        status: response.status,
        ok: response.ok,
        url: data.url
      });
      return response.text();
    })
    .then(responseText => {
      logBackground("Verdict endpoint response", {
        response: responseText,
        url: data.url
      });
    })
    .catch(error => {
      logBackground("Error in verdict endpoint request", {
        error: error.message,
        url: data.url
      });
    });
  }
});
