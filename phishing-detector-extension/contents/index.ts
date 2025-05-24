// Content script that gets injected into pages
// NOTE: Content script logs are automatically forwarded to the background console for better visibility
console.log("[PHISHING-DETECTOR] Content script starting to load");

import type { PlasmoCSConfig } from "plasmo"
import { analyzeDom } from "../dom-detector"
import { ensurePageReadiness } from "./page-readiness"
import { contentLogger as logger } from "../lib/logger"

console.log("[PHISHING-DETECTOR] Content script imports loaded");

// Plasmo configuration for content script
export const config: PlasmoCSConfig = {
  matches: ["<all_urls>"],
  all_frames: false, // Only run in main frame
  run_at: "document_idle" // Make sure DOM is fully loaded
}

console.log("[PHISHING-DETECTOR] Content script config set");

// Immediately announce presence for debugging
console.log("[PHISHING-DETECTOR] About to call logger.log");
logger.log("PHISHING DETECTOR CONTENT SCRIPT LOADED", {
  url: window.location.href,
  time: new Date().toISOString(),
  version: "1.1.0" // Add version for debugging
});
console.log("[PHISHING-DETECTOR] logger.log called");

// Create a flag to track analysis status
let analysisCompleted = false;
let analysisTimestamp = 0;
let analysisResult = null;

// Performance measurement function as specified in the email instructions
async function measureHeapAndTime(fn, ...args) {
  // Debug the performance API availability
  console.log("[PHISHING-DETECTOR-PERF] Performance API debug", {
    hasWindow: typeof window !== 'undefined',
    hasPerformance: typeof performance !== 'undefined',
    performanceKeys: performance ? Object.keys(performance) : [],
    hasMemoryProperty: performance && 'memory' in performance,
    memoryValue: performance && (performance as any).memory,
    isSecureContext: window.isSecureContext,
    origin: window.location.origin
  });
  
  logger.log("Performance API debug", {
    hasWindow: typeof window !== 'undefined',
    hasPerformance: typeof performance !== 'undefined',
    performanceKeys: performance ? Object.keys(performance) : [],
    hasMemoryProperty: performance && 'memory' in performance,
    memoryValue: performance && (performance as any).memory,
    isSecureContext: window.isSecureContext,
    origin: window.location.origin
  });

  const hasMemoryAPI = window.performance && (performance as any).memory;
  
  console.log("[PHISHING-DETECTOR-PERF] Starting performance measurement", { 
    functionName: fn.name || 'anonymous',
    args: args.length,
    memoryAPIAvailable: hasMemoryAPI
  });
  
  logger.log("Starting performance measurement", { 
    functionName: fn.name || 'anonymous',
    args: args.length,
    memoryAPIAvailable: hasMemoryAPI
  });

  if (!hasMemoryAPI) {
    logger.log("Heap measurement not available for:", fn.name || 'anonymous');
  }

  // Record initial heap stats (or 0 if not available)
  const startHeap = hasMemoryAPI ? (performance as any).memory.usedJSHeapSize : 0;
  const startTime = performance.now();

  logger.log("Performance baseline recorded", {
    startTime,
    startHeapMB: hasMemoryAPI ? (startHeap / 1024 / 1024).toFixed(2) : 'N/A'
  });

  // Run the function (supports async)
  let functionOutput, error = null;
  try {
    logger.log("Executing measured function...");
    functionOutput = await fn(...args);
    logger.log("Function execution completed", {
      hasResult: !!functionOutput,
      resultType: typeof functionOutput
    });
  } catch (e) {
    error = e;
    logger.error("Function execution failed", { error: e.message });
  }

  const endTime = performance.now();
  const endHeap = hasMemoryAPI ? (performance as any).memory.usedJSHeapSize : 0;

  const heapDelta = endHeap - startHeap;
  const timeMs = endTime - startTime;

  logger.log("Performance measurement completed", {
    timeMs: timeMs.toFixed(2),
    heapDeltaKB: hasMemoryAPI ? (heapDelta / 1024).toFixed(2) : 'N/A',
    endHeapMB: hasMemoryAPI ? (endHeap / 1024 / 1024).toFixed(2) : 'N/A'
  });

  return {
    functionOutput,
    error,
    heapChangeBytes: heapDelta,
    timeMs,
    heapBefore: startHeap,
    heapAfter: endHeap
  };
}

// Import the main classification function
import { analyzeForPhishing } from "../combined-detector"

// Wrapper function to run the main phishing classification with performance tracking and send results
async function runMainClassificationWithPerformanceTracking() {
  console.log("[PHISHING-DETECTOR] Starting main classification with performance tracking");
  logger.log("Starting main classification with performance tracking");
  
  // Get DOM features for the main classification
  let domFeatures = null;
  try {
    domFeatures = analyzeDom();
    logger.log("DOM analysis completed for main classification", { featureCount: domFeatures?.features?.length || 0 });
  } catch (error) {
    logger.log("Error during DOM analysis for main classification", { error: error.message });
  }

  try {
    // Create a wrapper function that ensures we measure the complete classification process
    const classificationFunction = async () => {
      console.log("[PHISHING-DETECTOR] Starting complete phishing analysis");
      logger.log("Starting complete phishing analysis");
      const result = await analyzeForPhishing(window.location.href, domFeatures);
      console.log("[PHISHING-DETECTOR] Complete phishing analysis finished", { 
        isPhishing: result.isPhishing, 
        confidence: result.confidence 
      });
      logger.log("Complete phishing analysis finished", { 
        isPhishing: result.isPhishing, 
        confidence: result.confidence 
      });
      return result;
    };

    console.log("[PHISHING-DETECTOR] About to call measureHeapAndTime");
    // Run the main classification function with performance tracking
    const measurementResult = await measureHeapAndTime(classificationFunction);
    console.log("[PHISHING-DETECTOR] measureHeapAndTime completed", measurementResult);
    
    const data = {
      'url': window.location.href,
      'groupId': 28,
      'isPhishing': measurementResult.functionOutput.isPhishing,
      'responseTimeMs': measurementResult.timeMs,
      'heapChangeBytes': measurementResult.heapChangeBytes
    };

    console.log("[PHISHING-DETECTOR] About to send TEST message", data);
    chrome.runtime.sendMessage({
      action: 'TEST', // send a message to the background with the `data` object
      data: data,
    });

    console.log("[PHISHING-DETECTOR] TEST message sent successfully");
    logger.log("Main classification performance data sent", { 
      data,
      analysisResult: measurementResult.functionOutput 
    });
  } catch (error) {
    console.error("[PHISHING-DETECTOR] ERROR in main classification:", error);
    logger.error("Error in main classification performance tracking", { error: error.message, stack: error.stack });
  }
}

// Notify background script that the page has loaded and is ready for analysis
function notifyPageReady() {
  const url = window.location.href;
  
  // Only notify for http/https URLs
  if (url.startsWith('http')) {
    logger.log("Notifying background script that page is ready for analysis", { url });
    
    // Analyze DOM proactively with error handling
    let domFeatures = null;
    try {
      domFeatures = analyzeDom();
      logger.log("DOM analysis completed successfully", { featureCount: domFeatures?.features?.length || 0 });
    } catch (error) {
      logger.log("Error during DOM analysis, will retry", { error: error.message });
      // If DOM analysis fails, we'll retry once more after a short delay
      setTimeout(() => {
        try {
          domFeatures = analyzeDom();
          logger.log("DOM analysis retry succeeded", { featureCount: domFeatures?.features?.length || 0 });
        } catch (retryError) {
          logger.log("DOM analysis retry failed", { error: retryError.message });
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
          logger.log("Error sending pageReady message", { 
            error: chrome.runtime.lastError.message,
            retry: retryCount
          });
          // CHANGE ME
          if (retryCount < maxRetries) {
            retryCount++;
            setTimeout(attemptNotify, 2000);
          }
        } else if (!response || !response.success) {
          logger.log("Background script returned error", { response });
        } else {
          logger.log("Background script notified successfully", { response });
          
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
  
  logger.log("Received analysis results", { 
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
    logger.log("Received analysis results from background", { 
      result: message.result
    });
    
    processAnalysisResults(message.result);
  }
  
  // Handle request to analyze DOM
  if (message.action === "analyzeDom") {
    logger.log("Received request to analyze DOM");
    
    // Perform DOM analysis
    const domFeatures = analyzeDom();
    
    // Return the analysis results
    logger.log("Sending DOM analysis results", { features: domFeatures });
    sendResponse(domFeatures);
    return true; // Will respond asynchronously
  }
  
  // Handle request for DOM features
  if (message.action === "getDomFeatures") {
    logger.log("Received request for DOM features");
    
    try {
      // Perform DOM analysis with timeout protection
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error("DOM analysis timed out")), 5000);
      });
      
      const analysisPromise = new Promise(resolve => {
        try {
          logger.log("Starting DOM feature extraction");
          const domFeatures = analyzeDom();
          logger.log("DOM feature extraction completed successfully", {
            featureCount: domFeatures?.features?.length || 0,
            suspiciousScore: domFeatures?.suspiciousScore || 0
          });
          resolve(domFeatures);
        } catch (error) {
          logger.log("Error in DOM analysis, trying fallback approach", { error: error.message });
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
            logger.log("Using fallback DOM features", { 
              features: fallbackFeatures.features.length,
              hasPasswordField: !!document.querySelector('input[type="password"]'),
              hasLoginForm: !!document.querySelector('form')
            });
            resolve(fallbackFeatures);
          } catch (fallbackError) {
            // If even the fallback fails, resolve with an empty structure
            logger.log("Fallback analysis also failed", { error: fallbackError.message });
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
            logger.log("Analysis promise resolved but didn't return any DOM features, using error fallback");
            domFeatures = {
              url: window.location.href,
              features: [{ name: "emptyResultError", value: true, weight: 0, impact: 0 }],
              suspiciousScore: 0,
              timestamp: Date.now()
            };
          }
          
          logger.log("Sending DOM features", { 
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
          logger.log("DOM analysis failed or timed out", { error: error.message });
          // Send a minimal response even on failure
          const errorDomFeatures = {
            url: window.location.href,
            features: [{ name: "timeoutError", value: true, weight: 0, impact: 0 }],
            suspiciousScore: 0,
            timestamp: Date.now()
          };
          
          logger.log("Sending minimal error DOM features");
          sendResponse({
            success: true,
            domFeatures: errorDomFeatures
          });
        });
      
      return true; // Will respond asynchronously
    } catch (error) {
      // Final fallback if everything else fails
      logger.log("Critical error in getDomFeatures handler", { error: error.message });
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
    logger.log("Received request for analysis status");
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
  console.log("[PHISHING-DETECTOR] Page load event fired");
  logger.log("Page load event fired");
  
  // Make sure page is fully loaded before analysis
  // Use readiness helper to ensure DOM and title are fully available
  setTimeout(async () => {
    try {
      console.log("[PHISHING-DETECTOR] Running performance tracking on load");
      // Wait for page to be completely ready
      await ensurePageReadiness();
      notifyPageReady();
      
      // Run the main classification with performance tracking
      await runMainClassificationWithPerformanceTracking();
    } catch (error) {
      logger.log("Error in page readiness or analysis", { error: error.message });
      // Retry once more after a delay if it fails
      setTimeout(async () => {
        try {
          await ensurePageReadiness();
          notifyPageReady();
          await runMainClassificationWithPerformanceTracking();
        } catch (retryError) {
          logger.log("Retry also failed", { error: retryError.message });
        }
      }, 3000);
    }
  }, 1000); // Reduced initial wait since we have proper readiness checks
});

// Fallback - if load event already fired, run immediately
if (document.readyState === "complete") {
  console.log("[PHISHING-DETECTOR] Document already complete on script load");
  logger.log("Document already complete on script load");
  setTimeout(async () => {
    try {
      console.log("[PHISHING-DETECTOR] Running fallback performance tracking");
      // Still use readiness helper to ensure title and dynamic content is ready
      await ensurePageReadiness();
      notifyPageReady();
      
      // Run the main classification with performance tracking
      await runMainClassificationWithPerformanceTracking();
    } catch (error) {
      logger.log("Error in page readiness or analysis (fallback)", { error: error.message });
      // Retry once more after a delay if it fails
      setTimeout(async () => {
        try {
          await ensurePageReadiness();
          notifyPageReady();
          await runMainClassificationWithPerformanceTracking();
        } catch (retryError) {
          logger.log("Retry also failed (fallback)", { error: retryError.message });
        }
      }, 3000);
    }
  }, 1000); // Reduced from 3000ms since we have proper readiness checks
}
