// Background script for phishing detector extension
// Use Chrome extension compatible module loading
const { backgroundLogger: logger } = chrome.runtime.getURL ? 
  await import(chrome.runtime.getURL('lib/logger.js')) : {};

// Load combined detector
let analyzeForPhishing;
try {
  const module = chrome.runtime.getURL ? 
    await import(chrome.runtime.getURL('combined-detector.js')) : {};
  analyzeForPhishing = module.analyzeForPhishing;
} catch (error) {
  console.error("Failed to load modules:", error);
}

// Create global maps to store state
const analyzedTabsData = new Map();
const pendingAnalyses = new Map();
const pageLoadTimestamps = new Map();

// Helper function for consistent logging
function logBackground(message, data = {}) {
  logger.log(message, data);
}

logger.log("PHISHING DETECTOR BACKGROUND SERVICE WORKER STARTED", {
  timestamp: new Date().toISOString(),
  version: "1.0.0"
});

// Initialize on startup
(async function initializeServiceWorker() {
  logBackground("Background service worker initializing");

  // Pre-load model data to make sure it's ready when needed
  try {
    logBackground("Pre-loading model data...");
    const modelMetadataUrl = chrome.runtime.getURL("model_metadata.json");
    const response = await fetch(modelMetadataUrl);
    
    if (!response.ok) {
      throw new Error(`Failed to load model metadata: ${response.status} ${response.statusText}`);
    }
    
    const modelData = await response.json();
    logBackground("Model data pre-loaded successfully", { 
      features: modelData.feature_names.length,
      constants: Object.keys(modelData.constants || {}).length
    });
  } catch (error) {
    logBackground("Error pre-loading model data", { error: error.message, stack: error.stack });
  }

  // Check if there are any open tabs we should analyze
  try {
    const tabs = await chrome.tabs.query({
      url: ["http://*/*", "https://*/*"],
      status: "complete"
    });

    logBackground("Found existing tabs to potentially analyze", { count: tabs.length });

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
    const loadTimestamp = Date.now();
    pageLoadTimestamps.set(tabId, loadTimestamp);
    logBackground("Recorded page load timestamp", { tabId, url: tab.url, timestamp: loadTimestamp });

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
  analyzedTabsData.delete(tabId);
  pendingAnalyses.delete(tabId);
});

// Main function to analyze a tab's URL
async function analyzeTabUrl(tabId, url, domFeatures = null) {
  if (!url || !url.startsWith('http')) {
    logBackground("Skipping analysis for non-HTTP URL", { tabId, url });
    return;
  }

  try {
    // Start timing the analysis process itself
    const analysisStartTime = Date.now();

    // Get the page load timestamp if available
    const pageLoadTime = pageLoadTimestamps.get(tabId) || analysisStartTime; // Fallback to analysis start time

    logBackground("Analyzing URL for phishing", { tabId, url, pageLoadTime });

    // If DOM features were not provided, try to get them from the content script
    if (!domFeatures) {
      try {
        // getDomFeaturesForTab now always resolves with at least a minimal structure
        logBackground("Attempting to get DOM features from content script", { tabId, url });
        domFeatures = await getDomFeaturesForTab(tabId);

        // Check if we got actual features or just an error indicator
        const hasRealFeatures = domFeatures?.features &&
          domFeatures.features.length > 0 &&
          !domFeatures.features.some(f =>
            ["timeoutError", "communicationError", "invalidResponse", "exceptionError", "analysisError", "criticalError"].includes(f.name));

        logBackground("Retrieved DOM features for analysis", {
          tabId,
          hasDomFeatures: !!domFeatures,
          hasRealFeatures: hasRealFeatures,
          featureCount: domFeatures?.features?.length || 0,
          suspiciousScore: domFeatures?.suspiciousScore || 0
        });

        // If we only got error indicators, log it but continue with the minimal structure
        if (!hasRealFeatures) {
          logBackground("Only error indicators in DOM features, but continuing with analysis", { tabId });
        }
      } catch (error) {
        // This should never happen now, but just in case
        logBackground("Unexpected error getting DOM features, continuing with URL-only analysis", {
          tabId,
          error: error.message,
          stack: error.stack
        });
        // Create a minimal structure to avoid null references
        domFeatures = {
          url: url,
          features: [{ name: "unexpectedError", value: true, weight: 0, impact: 0 }],
          suspiciousScore: 0,
          timestamp: Date.now()
        };
      }
    } else {
      logBackground("Using provided DOM features for analysis", {
        tabId,
        featureCount: domFeatures?.features?.length || 0,
        suspiciousScore: domFeatures?.suspiciousScore || 0
      });
    }

    // Perform actual analysis using combined detector
    const result = await analyzeForPhishing(url, domFeatures);
    const isPhishing = result.isPhishing;

    // Record how long the analysis took
    const analysisElapsedTime = Date.now() - analysisStartTime;
    const totalElapsedTime = Date.now() - pageLoadTime;

    // Add timing information
    result.analysisElapsedTime = analysisElapsedTime;
    result.totalElapsedTime = totalElapsedTime;
    result.autoAnalyzed = true;

    // Store the result (overwriting any previous result for this tab)
    analyzedTabsData.set(tabId, {
      url,
      result,
      timestamp: Date.now()
    });

    // Update the browser action badge
    updateBadge(tabId, isPhishing, result.confidence);

    logBackground("Analysis completed", {
      tabId,
      url,
      isPhishing,
      analysisTime: analysisElapsedTime,
      totalTime: totalElapsedTime
    });

    return result;
  } catch (error) {
    logBackground("Error during analysis", {
      tabId,
      url,
      error: error.message,
      stack: error.stack
    });
    throw error;
  }
}

// Update the extension badge based on analysis results
function updateBadge(tabId, isPhishing, confidence) {
  if (!tabId) return;

  try {
    if (isPhishing) {
      // Red badge for phishing
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#FF0000" });
      chrome.action.setBadgeText({ tabId, text: "⚠️" });
    } else {
      // Green badge for safe
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#00AA00" });
      chrome.action.setBadgeText({ tabId, text: "✓" });
    }
  } catch (error) {
    logBackground("Error updating badge", { tabId, error });
  }
}

// Get DOM features from a tab (communicate with content script)
async function getDomFeaturesForTab(tabId) {
  try {
    logBackground("Requesting DOM features from content script", { tabId });
    
    // Make a query to the content script to run the DOM analysis
    return new Promise((resolve, reject) => {
      try {
        chrome.tabs.sendMessage(tabId, { action: "runDomAnalysis" }, response => {
          if (chrome.runtime.lastError) {
            logBackground("Error communicating with content script", {
              error: chrome.runtime.lastError.message,
              tabId
            });
            
            // Return a default structure with error indication
            resolve({
              url: "",
              features: [{ name: "communicationError", value: true, weight: 0, impact: 0 }],
              suspiciousScore: 0,
              timestamp: Date.now()
            });
            return;
          }

          if (!response) {
            logBackground("No response from content script", { tabId });
            
            // Return a default structure with error indication
            resolve({
              url: "",
              features: [{ name: "invalidResponse", value: true, weight: 0, impact: 0 }],
              suspiciousScore: 0,
              timestamp: Date.now()
            });
            return;
          }

          logBackground("Received DOM features from content script", {
            tabId,
            featureCount: response.features?.length || 0
          });
          
          resolve(response);
        });
      } catch (err) {
        logBackground("Exception in getDomFeaturesForTab", {
          error: err.message,
          stack: err.stack,
          tabId
        });
        
        // Return a default structure with error indication
        resolve({
          url: "",
          features: [{ name: "exceptionError", value: true, weight: 0, impact: 0 }],
          suspiciousScore: 0,
          timestamp: Date.now()
        });
      }
    });
  } catch (error) {
    logBackground("Error in getDomFeaturesForTab", {
      error: error.message,
      stack: error.stack,
      tabId
    });
    
    // Return a default structure with error indication
    return {
      url: "",
      features: [{ name: "criticalError", value: true, weight: 0, impact: 0 }],
      suspiciousScore: 0,
      timestamp: Date.now()
    };
  }
}

// Handler for get tab analysis data
function handleGetTabAnalysisData(message, sender, sendResponse) {
  try {
    const { tabId } = message;
    
    if (!tabId) {
      logBackground("Missing tabId in getTabAnalysisData message");
      sendResponse({ success: false, error: "Missing tabId" });
      return;
    }
    
    // Get the cached analysis data for this tab
    const data = analyzedTabsData.get(tabId);
    
    if (!data) {
      logBackground("No analysis data for tab", { tabId });
      sendResponse({ success: false, error: "No analysis data for this tab" });
      return;
    }
    
    logBackground("Returning tab analysis data", { tabId, url: data.url });
    sendResponse({ success: true, data });
  } catch (error) {
    logBackground("Error handling getTabAnalysisData", { error });
    sendResponse({ success: false, error: error.message });
  }
}

// Handler for analyze URL manually
function handleAnalyzeUrlManually(message, sender, sendResponse) {
  try {
    const { url } = message;
    
    if (!url) {
      logBackground("Missing URL in analyzeUrlManually message");
      sendResponse({ success: false, error: "Missing URL" });
      return false;
    }
    
    logBackground("Manual URL analysis requested", { url });
    
    // Run the analysis
    analyzeForPhishing(url)
      .then(result => {
        logBackground("Manual analysis completed", { url, isPhishing: result.isPhishing });
        sendResponse({ success: true, result });
      })
      .catch(error => {
        logBackground("Error in manual analysis", { url, error });
        sendResponse({ success: false, error: error.message });
      });
    
    return true; // Indicates we will send the response asynchronously
  } catch (error) {
    logBackground("Error handling analyzeUrlManually", { error });
    sendResponse({ success: false, error: error.message });
    return false;
  }
}

// Handler for page ready notification
function handlePageReady(message, sender, sendResponse) {
  try {
    const { url, domFeatures } = message;
    const tabId = sender.tab.id;
    
    if (!tabId || !url) {
      logBackground("Missing data in pageReady message");
      sendResponse({ success: false, error: "Missing data" });
      return false;
    }
    
    logBackground("Page ready notification received", { tabId, url });
    
    // If the page is already being analyzed or has been analyzed, don't start a new analysis
    if (pendingAnalyses.has(tabId)) {
      logBackground("Analysis already in progress for this tab", { tabId });
      sendResponse({ success: true, status: "analysis_in_progress" });
      return false;
    }
    
    if (analyzedTabsData.has(tabId)) {
      const existingData = analyzedTabsData.get(tabId);
      
      // If URL has changed, start a new analysis
      if (existingData.url !== url) {
        logBackground("URL changed, starting new analysis", { 
          tabId, 
          oldUrl: existingData.url, 
          newUrl: url 
        });
        
        // Mark this tab as pending analysis
        pendingAnalyses.set(tabId, Date.now());
        
        // Analyze with the DOM features provided from content script
        analyzeTabUrl(tabId, url, domFeatures)
          .then(() => {
            pendingAnalyses.delete(tabId);
            sendResponse({ 
              success: true, 
              status: "analysis_complete" 
            });
          })
          .catch(error => {
            pendingAnalyses.delete(tabId);
            sendResponse({ 
              success: false, 
              error: error.message 
            });
          });
        
        return true; // Indicates we will send the response asynchronously
      } else {
        logBackground("Tab already analyzed with current URL", { tabId, url });
        sendResponse({ 
          success: true, 
          status: "already_analyzed", 
          result: existingData.result 
        });
        return false;
      }
    }
    
    // This is a new analysis
    logBackground("Starting new analysis from pageReady", { tabId, url });
    
    // Mark this tab as pending analysis
    pendingAnalyses.set(tabId, Date.now());
    
    // Analyze with the DOM features provided from content script
    analyzeTabUrl(tabId, url, domFeatures)
      .then(() => {
        pendingAnalyses.delete(tabId);
        sendResponse({ 
          success: true, 
          status: "analysis_complete" 
        });
      })
      .catch(error => {
        pendingAnalyses.delete(tabId);
        sendResponse({ 
          success: false, 
          error: error.message 
        });
      });
    
    return true; // Indicates we will send the response asynchronously
  } catch (error) {
    logBackground("Error handling pageReady", { error });
    sendResponse({ success: false, error: error.message });
    return false;
  }
}

// Add a diagnostic handler to check service worker state
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "checkBackgroundStatus") {
    try {
      const status = {
        isRunning: true,
        hasLogger: typeof logger !== 'undefined',
        hasAnalyzeFunction: typeof analyzeForPhishing === 'function',
        loadedModules: {
          logger: typeof logger !== 'undefined',
          analyzer: typeof analyzeForPhishing === 'function',
        },
        dataStores: {
          analyzedTabsCount: analyzedTabsData.size,
          pendingAnalysesCount: pendingAnalyses.size
        },
        timestamp: new Date().toISOString()
      };
      
      console.log("Background status check:", status);
      sendResponse({ success: true, status });
    } catch (error) {
      console.error("Error in background status check:", error);
      sendResponse({ 
        success: false, 
        error: error.message,
        stack: error.stack
      });
    }
    return true;
  }
  return false;
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

    case "analyzeUrlDirectly":
      try {
        const { url } = message;
        
        if (!url) {
          console.log("Missing URL in analyzeUrlDirectly message");
          sendResponse({ success: false, error: "Missing URL" });
          return false;
        }
        
        console.log("Direct URL analysis requested:", url);
        
        // Create a very simple analysis result without using modules
        // This is a fallback when the regular analysis is broken
        const result = {
          isPhishing: false,
          confidence: 50,
          urlFeatures: {
            url: url,
            features: {},
            suspiciousKeywordsFound: [],
            probability: 0.5,
            score: 0
          },
          domFeatures: null,
          calculationDetails: {
            urlWeight: 1.0,
            urlScore: 0.5,
            urlContribution: 0.5
          }
        };
        
        // Check for some very basic suspicious patterns
        const lowercaseUrl = url.toLowerCase();
        const suspiciousKeywords = ['login', 'signin', 'account', 'secure', 'password', 'bank'];
        const foundKeywords = suspiciousKeywords.filter(k => lowercaseUrl.includes(k));
        
        if (foundKeywords.length > 0) {
          result.urlFeatures.suspiciousKeywordsFound = foundKeywords;
        }
        
        // Simple heuristics
        if (url.includes('@') || url.includes('data:') || url.includes('javascript:')) {
          result.isPhishing = true;
          result.confidence = 70;
          result.urlFeatures.score = 0.7;
        }
        
        // IP address detection
        const ipRegex = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
        if (ipRegex.test(url)) {
          result.isPhishing = true;
          result.confidence = 65;
          result.urlFeatures.score = 0.65;
        }
        
        console.log("Direct analysis completed:", result);
        sendResponse({ success: true, result });
        
        return false;
      } catch (error) {
        console.error("Error in direct URL analysis:", error);
        sendResponse({ success: false, error: error.message });
        return false;
      }
      break;
  }

  return false; // No async response
});
