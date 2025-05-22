// Content script for phishing detector - runs in the page context
let contentLogger = console;
let analyzeDom = () => ({ 
  url: window.location.href, 
  features: [], 
  suspiciousScore: 0, 
  timestamp: Date.now() 
});

// Load logger and DOM detector modules
(async function loadModules() {
  try {
    // Load logger
    const loggerModule = await import(chrome.runtime.getURL('lib/logger.js'));
    if (loggerModule) {
      contentLogger = loggerModule.contentLogger;
    }
    
    // Load DOM detector
    const domDetectorModule = await import(chrome.runtime.getURL('lib/dom-detector/index.js'));
    if (domDetectorModule) {
      analyzeDom = domDetectorModule.analyzeDom;
    }
    
    contentLogger.log("Modules loaded successfully");
  } catch (error) {
    console.error("Error loading modules:", error);
  }
})();

// Immediately announce presence for debugging
contentLogger.log("PHISHING DETECTOR CONTENT SCRIPT LOADED", {
  url: window.location.href,
  time: new Date().toISOString(),
  version: "1.0.0" // Add version for debugging
});

// Create a flag to track analysis status
let analysisCompleted = false;
let analysisTimestamp = 0;
let analysisResult = null;

// Helper function for logging
function logMessage(message, data = {}) {
  contentLogger.log(message, data);
}

// Notify background script that the page has loaded and is ready for analysis
function notifyPageReady() {
  const url = window.location.href;
  
  // Only notify for http/https URLs
  if (url.startsWith('http')) {
    logMessage("Notifying background script that page is ready for analysis", { url });
    
    // Analyze DOM proactively with error handling
    let domFeatures = null;
    try {
      domFeatures = analyzeDom();
      logMessage("DOM analysis completed successfully", { featureCount: domFeatures?.features?.length || 0 });
    } catch (error) {
      logMessage("Error during DOM analysis, will retry", { error: error.message });
      // If DOM analysis fails, we'll retry once more after a short delay
      setTimeout(() => {
        try {
          domFeatures = analyzeDom();
          logMessage("DOM analysis retry succeeded", { featureCount: domFeatures?.features?.length || 0 });
        } catch (retryError) {
          logMessage("DOM analysis retry also failed", { error: retryError.message });
          // Create a simple error feature to indicate analysis failed
          domFeatures = {
            url: window.location.href,
            features: [{ name: "analysisError", value: true, weight: 0, impact: 0 }],
            suspiciousScore: 0,
            timestamp: Date.now()
          };
        }
        
        // Now send the message with whatever DOM features we have
        sendPageReadyMessage(url, domFeatures);
      }, 500);
      return;
    }
    
    // Send the message with DOM features
    sendPageReadyMessage(url, domFeatures);
  }
}

// Helper to send the pageReady message
function sendPageReadyMessage(url, domFeatures) {
  try {
    chrome.runtime.sendMessage(
      { 
        action: "pageReady", 
        url, 
        domFeatures 
      },
      (response) => {
        if (chrome.runtime.lastError) {
          logMessage("Error sending pageReady message", { error: chrome.runtime.lastError.message });
          return;
        }
        
        if (response.success) {
          logMessage("Page ready notification successful", { status: response.status });
          
          if (response.status === "already_analyzed" && response.result) {
            // Store the analysis result
            analysisCompleted = true;
            analysisTimestamp = Date.now();
            analysisResult = response.result;
            
            logMessage("Retrieved existing analysis result", { 
              isPhishing: response.result.isPhishing,
              confidence: response.result.confidence
            });
          }
        } else {
          logMessage("Page ready notification failed", { error: response.error });
        }
      }
    );
  } catch (error) {
    logMessage("Exception sending pageReady message", { error: error.message });
  }
}

// Listen for messages from the background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const url = window.location.href;
  
  logMessage("Content script received message", { 
    action: message.action, 
    url 
  });
  
  if (message.action === "runDomAnalysis") {
    logMessage("Received request to run DOM analysis", { url });
    
    try {
      // Check if we already have a cached analysis
      if (analysisCompleted && analysisTimestamp > Date.now() - 30000) {
        logMessage("Returning cached DOM analysis", { age: Date.now() - analysisTimestamp });
        sendResponse(analysisResult);
        return false;
      }
      
      // Run a new analysis
      const domFeatures = analyzeDom();
      
      // Cache the result
      analysisCompleted = true;
      analysisTimestamp = Date.now();
      analysisResult = domFeatures;
      
      logMessage("DOM analysis completed for background request", { 
        featureCount: domFeatures.features.length,
        suspiciousScore: domFeatures.suspiciousScore 
      });
      
      sendResponse(domFeatures);
    } catch (error) {
      logMessage("Error during DOM analysis for background request", { error: error.message });
      
      // Return a basic error result
      const errorResult = {
        url,
        features: [{ name: "analysisError", value: true, weight: 0, impact: 0 }],
        suspiciousScore: 0,
        timestamp: Date.now()
      };
      
      sendResponse(errorResult);
    }
    
    return false;
  }
});

// Wait for page to be fully loaded before analyzing
if (document.readyState === 'complete') {
  notifyPageReady();
} else {
  window.addEventListener('load', () => {
    // Wait a bit after load to allow dynamic content to settle
    setTimeout(notifyPageReady, 500);
  });
}
