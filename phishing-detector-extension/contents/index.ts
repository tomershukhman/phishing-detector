// Content script that gets injected into pages
import type { PlasmoCSConfig } from "plasmo"
import { analyzeDom } from "../dom-detector"
import { ensurePageReadiness } from "./page-readiness"
import { contentLogger as logger } from "../lib/logger"

// Plasmo configuration for content script
export const config: PlasmoCSConfig = {
  matches: ["<all_urls>"],
  all_frames: false, // Only run in main frame
  run_at: "document_idle" // Make sure DOM is fully loaded
}

// Immediately announce presence for debugging
logger.log("PHISHING DETECTOR CONTENT SCRIPT LOADED", {
  url: window.location.href,
  time: new Date().toISOString(),
  version: "1.1.0" // Add version for debugging
});

// Create a flag to track analysis status
let analysisCompleted = false;
let analysisTimestamp = 0;
let analysisResult = null;

// Helper function for logging
function logMessage(message, data = {}) {
  logger.log(message, data);
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
          logMessage("DOM analysis retry failed", { error: retryError.message });
        }
      }, 1000);
    }
    
    // Try to notify the background script with retries
    let retryCount = 0;
    const maxRetries = 3;
    
    function attemptNotify() {
      chrome.runtime.sendMessage({
        action: "pageReady",
        url: url,
        domFeatures: domFeatures
      }, response => {
        if (chrome.runtime.lastError) {
          logMessage("Error sending pageReady message", { 
            error: chrome.runtime.lastError.message,
            retry: retryCount
          });
          // CHANGE ME
          if (retryCount < maxRetries) {
            retryCount++;
            setTimeout(attemptNotify, 2000);
          }
        } else if (!response || !response.success) {
          logMessage("Background script returned error", { response });
        } else {
          logMessage("Background script notified successfully", { response });
          
          if (response.status === "completed" && response.result) {
            // We already have analysis results, process them immediately
            processAnalysisResults(response.result);
          }
        }
      });
    }
    
    attemptNotify();
  }
}

// Process analysis results from background script
function processAnalysisResults(result) {
  if (!result) return;
  
  analysisResult = result;
  analysisCompleted = true;
  analysisTimestamp = Date.now();
  
  logMessage("Received analysis results", { 
    isPhishing: result.isPhishing,
    confidence: result.confidence,
    url: result.url
  });
  
  // Add any UI indicators or warnings if needed
  if (result.isPhishing && result.confidence > 0.7) {
    // High confidence phishing - could add UI warning here
  }
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "analysisCompleted" && message.result) {
    logMessage("Received analysis results from background", { 
      result: message.result
    });
    
    processAnalysisResults(message.result);
  }
  
  // Handle request to analyze DOM
  if (message.action === "analyzeDom") {
    logMessage("Received request to analyze DOM");
    
    // Perform DOM analysis
    const domFeatures = analyzeDom();
    
    // Return the analysis results
    logMessage("Sending DOM analysis results", { features: domFeatures });
    sendResponse(domFeatures);
    return true; // Will respond asynchronously
  }
  
  // Handle request for DOM features
  if (message.action === "getDomFeatures") {
    logMessage("Received request for DOM features");
    
    try {
      // Perform DOM analysis with timeout protection
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error("DOM analysis timed out")), 5000);
      });
      
      const analysisPromise = new Promise(resolve => {
        try {
          logMessage("Starting DOM feature extraction");
          const domFeatures = analyzeDom();
          logMessage("DOM feature extraction completed successfully", {
            featureCount: domFeatures?.features?.length || 0,
            suspiciousScore: domFeatures?.suspiciousScore || 0
          });
          resolve(domFeatures);
        } catch (error) {
          logMessage("Error in DOM analysis, trying fallback approach", { error: error.message });
          // Fallback to a more basic analysis if the full one fails
          try {
            // Create a minimal set of DOM features to avoid complete failure
            const fallbackFeatures = {
              url: window.location.href,
              features: [
                { name: "fallbackMode", value: true, weight: 0, impact: 0 },
                { name: "hasPasswordField", value: !!document.querySelector('input[type="password"]'), weight: 0.7, impact: 0.5 },
                { name: "hasLoginForm", value: !!document.querySelector('form'), weight: 0.8, impact: 0.6 }
              ],
              suspiciousScore: document.querySelector('input[type="password"]') ? 0.6 : 0.3,
              timestamp: Date.now()
            };
            logMessage("Using fallback DOM features", { 
              features: fallbackFeatures.features.length,
              hasPasswordField: !!document.querySelector('input[type="password"]'),
              hasLoginForm: !!document.querySelector('form')
            });
            resolve(fallbackFeatures);
          } catch (fallbackError) {
            // If even the fallback fails, resolve with an empty structure
            logMessage("Fallback analysis also failed", { error: fallbackError.message });
            resolve({
              url: window.location.href,
              features: [{ name: "analysisError", value: true, weight: 0, impact: 0 }],
              suspiciousScore: 0,
              timestamp: Date.now()
            });
          }
        }
      });
      
      // Race between timeout and analysis
      Promise.race([analysisPromise, timeoutPromise])
        .then((domFeatures: any) => {
          if (!domFeatures) {
            logMessage("Analysis promise resolved but didn't return any DOM features, using error fallback");
            domFeatures = {
              url: window.location.href,
              features: [{ name: "emptyResultError", value: true, weight: 0, impact: 0 }],
              suspiciousScore: 0,
              timestamp: Date.now()
            };
          }
          
          logMessage("Sending DOM features", { 
            featureCount: domFeatures?.features?.length || 0,
            score: domFeatures?.suspiciousScore || 0,
            url: domFeatures?.url
          });
          
          sendResponse({
            success: true,
            domFeatures: domFeatures
          });
        })
        .catch((error) => {
          logMessage("DOM analysis failed or timed out", { error: error.message });
          // Send a minimal response even on failure
          const errorDomFeatures = {
            url: window.location.href,
            features: [{ name: "timeoutError", value: true, weight: 0, impact: 0 }],
            suspiciousScore: 0,
            timestamp: Date.now()
          };
          
          logMessage("Sending minimal error DOM features");
          sendResponse({
            success: true,
            domFeatures: errorDomFeatures
          });
        });
      
      return true; // Will respond asynchronously
    } catch (error) {
      // Final fallback if everything else fails
      logMessage("Critical error in getDomFeatures handler", { error: error.message });
      sendResponse({
        success: true,
        domFeatures: {
          url: window.location.href,
          features: [{ name: "criticalError", value: true, weight: 0, impact: 0 }],
          suspiciousScore: 0,
          timestamp: Date.now()
        }
      });
      return true;
    }
  }
  
  // Handle request for analysis status
  if (message.action === "getAnalysisStatus") {
    logMessage("Received request for analysis status");
    sendResponse({
      completed: analysisCompleted,
      timestamp: analysisTimestamp,
      result: analysisResult
    });
    return true;
  }
  
  return false; // No async response
});

// Initialize when page is loaded
window.addEventListener("load", () => {
  logMessage("Page load event fired");
  
  // Make sure page is fully loaded before analysis
  // Use readiness helper to ensure DOM and title are fully available
  setTimeout(async () => {
    try {
      // Wait for page to be completely ready
      await ensurePageReadiness();
      notifyPageReady();
    } catch (error) {
      logMessage("Error in page readiness or analysis", { error: error.message });
      // Retry once more after a delay if it fails
      setTimeout(async () => {
        try {
          await ensurePageReadiness();
          notifyPageReady();
        } catch (retryError) {
          logMessage("Retry also failed", { error: retryError.message });
        }
      }, 3000);
    }
  }, 1000); // Reduced initial wait since we have proper readiness checks
});

// Fallback - if load event already fired, run immediately
if (document.readyState === "complete") {
  logMessage("Document already complete on script load");
  setTimeout(async () => {
    try {
      // Still use readiness helper to ensure title and dynamic content is ready
      await ensurePageReadiness();
      notifyPageReady();
    } catch (error) {
      logMessage("Error in page readiness or analysis (fallback)", { error: error.message });
      // Retry once more after a delay if it fails
      setTimeout(async () => {
        try {
          await ensurePageReadiness();
          notifyPageReady();
        } catch (retryError) {
          logMessage("Retry also failed (fallback)", { error: retryError.message });
        }
      }, 3000);
    }
  }, 1000); // Reduced from 3000ms since we have proper readiness checks
}
