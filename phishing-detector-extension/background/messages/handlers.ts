// Handlers for different message types received by the background service worker

import { analyzeForPhishing } from "../../combined-detector";
import { messageLogger as logger } from "../../lib/logger";
import { getPageLoadTimestamps } from "../index";

// Persistent data store - use shared global store
// Initialize global storage if not already done
if (typeof self !== "undefined") {
  // @ts-ignore
  self.analyzedTabsData = self.analyzedTabsData || new Map();
  // @ts-ignore
  self.pendingAnalyses = self.pendingAnalyses || new Map();
}

// Helper function for consistent logging
function logMessage(message, data = {}) {
  logger.log(message, data);
}

// Update the extension badge based on analysis results
export function updateBadge(tabId, isPhishing, confidence) {
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
    logMessage("Error updating badge", { tabId, error });
  }
}

// Main function to analyze a tab's URL
export async function analyzeTabUrl(tabId, url, domFeatures = null) {
  if (!url || !url.startsWith('http')) {
    logMessage("Skipping analysis for non-HTTP URL", { tabId, url });
    return;
  }

  try {
    // Start timing the analysis process itself
    const analysisStartTime = Date.now();

    // Get the page load timestamp if available
    const pageLoadTimestamps = getPageLoadTimestamps();
    const pageLoadTime = pageLoadTimestamps.get(tabId) || analysisStartTime; // Fallback to analysis start time

    logMessage("Analyzing URL for phishing", { tabId, url, pageLoadTime });

    // If DOM features were not provided, try to get them from the content script
    if (!domFeatures) {
      try {
        // getDomFeaturesForTab now always resolves with at least a minimal structure
        logMessage("Attempting to get DOM features from content script", { tabId, url });
        domFeatures = await getDomFeaturesForTab(tabId);

        // Check if we got actual features or just an error indicator
        const hasRealFeatures = domFeatures?.features &&
          domFeatures.features.length > 0 &&
          !domFeatures.features.some(f =>
            ["timeoutError", "communicationError", "invalidResponse", "exceptionError", "analysisError", "criticalError"].includes(f.name));

        logMessage("Retrieved DOM features for analysis", {
          tabId,
          hasDomFeatures: !!domFeatures,
          hasRealFeatures: hasRealFeatures,
          featureCount: domFeatures?.features?.length || 0,
          suspiciousScore: domFeatures?.suspiciousScore || 0
        });

        // If we only got error indicators, log it but continue with the minimal structure
        if (!hasRealFeatures) {
          logMessage("Only error indicators in DOM features, but continuing with analysis", { tabId });
        }
      } catch (error) {
        // This should never happen now, but just in case
        logMessage("Unexpected error getting DOM features, continuing with URL-only analysis", {
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
      logMessage("Using provided DOM features for analysis", {
        tabId,
        featureCount: domFeatures?.features?.length || 0,
        suspiciousScore: domFeatures?.suspiciousScore || 0
      });
    }

    // Analyze the URL with DOM features if available
    logMessage("Calling analyzeForPhishing with URL and DOM features", {
      url,
      hasDomFeatures: !!domFeatures,
      domFeaturesCount: domFeatures?.features?.length || 0
    });

    const result = await analyzeForPhishing(url, domFeatures);

    // Calculate elapsed time for analysis process
    const analysisElapsedTime = Date.now() - analysisStartTime;

    // Calculate elapsed time from page load to completion
    const totalElapsedTime = Date.now() - pageLoadTime;

    logMessage("Analysis completed successfully", {
      tabId,
      url,
      isPhishing: result.isPhishing,
      confidence: result.confidence,
      hasUrlResults: !!result.urlFeatures,
      hasDomResults: !!result.domFeatures,
      analysisElapsedTime: analysisElapsedTime,
      totalElapsedTime: totalElapsedTime
    });

    // Store the result for this tab
    // @ts-ignore
    self.analyzedTabsData.set(tabId, {
      url: url,
      result: result,
      domFeatures: domFeatures,
      timestamp: Date.now(),
      analysisElapsedTime: analysisElapsedTime,
      totalElapsedTime: totalElapsedTime
    });

    // Update the badge
    updateBadge(tabId, result.isPhishing, result.confidence);

    logMessage("URL analysis completed", {
      tabId,
      url,
      isPhishing: result.isPhishing,
      confidence: result.confidence,
      analysisElapsedTime: analysisElapsedTime,
      totalElapsedTime: totalElapsedTime
    });

    return result;
  } catch (error) {
    logMessage("Error analyzing URL", {
      tabId,
      url,
      error: error.message,
      stack: error.stack
    });

    // Create a fallback result in case of error
    const fallbackResult = {
      isPhishing: false,
      urlDetectorResult: false,
      confidence: 0,
      url,
      urlFeatures: {
        url,
        features: [],
        topContributingFeatures: [],
        suspiciousKeywordsFound: [],
        probability: 0,
        phishingProbability: 0,
        score: 0
      },
      calculationDetails: {
        urlWeight: 1.0,
        urlScore: 0,
        urlContribution: 0
      }
    };

    // Still store the fallback result to avoid repeated errors
    // @ts-ignore
    self.analyzedTabsData.set(tabId, {
      url: url,
      result: fallbackResult,
      error: error.message,
      timestamp: Date.now(),
      analysisElapsedTime: 0,
      totalElapsedTime: 0
    });

    // Update badge to indicate error
    try {
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#888888" });
      chrome.action.setBadgeText({ tabId, text: "!" });
    } catch (badgeError) {
      logMessage("Error updating badge", { tabId, error: badgeError.message });
    }

    throw error;
  }
}

// Handler for getTabAnalysisData message
export function handleGetTabAnalysisData(message, sender, sendResponse) {
  // @ts-ignore
  if (self.analyzedTabsData.has(message.tabId)) {
    // @ts-ignore
    const data = self.analyzedTabsData.get(message.tabId);
    sendResponse({ success: true, data });
  } else {
    sendResponse({ success: false });
  }
}

// Handler for analyzeUrlManually message
export function handleAnalyzeUrlManually(message, sender, sendResponse) {
  const url = message.url;
  const tabId = message.tabId;

  // Clean up any pending analysis
  // @ts-ignore
  self.pendingAnalyses.delete(tabId);

  // Run the analysis
  analyzeTabUrl(tabId, url).then(result => {
    sendResponse({ success: true, result });
  }).catch(error => {
    logMessage("Error during manual analysis", { tabId, url, error });
    sendResponse({ success: false, error: error.toString() });
  });

  return true; // Will respond asynchronously
}

// Handler for pageReady message from content script
export function handlePageReady(message, sender, sendResponse) {
  const url = message.url;
  const tabId = sender.tab.id;

  // Check if an analysis is already pending
  // @ts-ignore
  if (self.pendingAnalyses.has(tabId)) {
    logMessage("Analysis already pending for this tab", { tabId, url });
    sendResponse({ success: true, status: "pending" });
    return true;
  }

  // Always start a new analysis when page is ready
  logMessage("Starting fresh analysis for every page load", { tabId, url });

  // Start a new analysis
  logMessage("Starting analysis for content script request", { tabId, url });
  // @ts-ignore
  self.pendingAnalyses.set(tabId, Date.now());

  analyzeTabUrl(tabId, url).then(result => {
    // @ts-ignore
    self.pendingAnalyses.delete(tabId);

    // Send a message back to the content script with results
    chrome.tabs.sendMessage(tabId, {
      action: "analysisCompleted",
      result: result
    }).catch(err => {
      logMessage("Error sending results to content script", { tabId, error: err });
    });

    sendResponse({ success: true, status: "started" });
  }).catch(error => {
    // @ts-ignore
    self.pendingAnalyses.delete(tabId);
    logMessage("Error during analysis from content script", { tabId, url, error });
    sendResponse({ success: false, error: error.toString() });
  });

  return true; // Will respond asynchronously
}

// Helper function to get DOM features from tab via content script
async function getDomFeaturesForTab(tabId) {
  logMessage("Getting DOM features for tab", { tabId });

  return new Promise((resolve) => {
    try {
      // Set a timeout to ensure we don't wait forever
      const timeoutId = setTimeout(() => {
        logMessage("DOM feature request timed out", { tabId });
        // Return a minimal fallback structure instead of rejecting
        resolve({
          url: "",
          features: [{ name: "timeoutError", value: true, weight: 0, impact: 0 }],
          suspiciousScore: 0,
          timestamp: Date.now()
        });
      }, 8000); // 8 second timeout - increased for reliability

      // Try to get DOM features from content script
      logMessage("Sending getDomFeatures message to content script", { tabId });
      chrome.tabs.sendMessage(tabId, { action: "getDomFeatures" }, response => {
        clearTimeout(timeoutId); // Clear the timeout

        if (chrome.runtime.lastError) {
          logMessage("Error getting DOM features", {
            tabId,
            error: chrome.runtime.lastError.message
          });
          // Return a minimal fallback structure instead of rejecting
          resolve({
            url: "",
            features: [{ name: "communicationError", value: true, weight: 0, impact: 0 }],
            suspiciousScore: 0,
            timestamp: Date.now()
          });
        } else if (response && response.domFeatures) {
          const domFeatures = response.domFeatures;

          // Check if we got a valid structure
          if (!domFeatures.features || !Array.isArray(domFeatures.features)) {
            logMessage("Invalid DOM features structure received", { tabId, domFeatures });
            resolve({
              url: domFeatures.url || "",
              features: [{ name: "invalidStructure", value: true, weight: 0, impact: 0 }],
              suspiciousScore: 0,
              timestamp: Date.now()
            });
            return;
          }

          logMessage("Successfully received DOM features", {
            tabId,
            featureCount: domFeatures.features.length,
            suspiciousScore: domFeatures.suspiciousScore || 0,
            url: domFeatures.url || ""
          });

          resolve(domFeatures);
        } else {
          logMessage("Invalid response from content script", { tabId, response });
          // Return a minimal fallback structure
          resolve({
            url: "",
            features: [{ name: "invalidResponse", value: true, weight: 0, impact: 0 }],
            suspiciousScore: 0,
            timestamp: Date.now()
          });
        }
      });
    } catch (error) {
      logMessage("Exception in getDomFeaturesForTab", {
        tabId,
        error: error.message,
        stack: error.stack
      });
      // Return a minimal fallback structure instead of rejecting
      resolve({
        url: "",
        features: [{ name: "exceptionError", value: true, weight: 0, impact: 0 }],
        suspiciousScore: 0,
        timestamp: Date.now()
      });
    }
  });
}

// Get the map of analyzed tab data
export function getAnalyzedTabsData() {
  // @ts-ignore
  return self.analyzedTabsData;
}

// Get the map of pending analyses
export function getPendingAnalyses() {
  // @ts-ignore
  return self.pendingAnalyses;
}

// Handle feature state update messages (for dynamic updates)
export function handleUpdateFeatureState(message, sender, sendResponse) {
  // This function is called when content scripts detect updates to features
  // after the initial analysis (e.g., when title becomes available after a delay)
  if (!message.feature) {
    sendResponse({ success: false, error: "Missing feature name" });
    return false;
  }

  try {
    // Get the tab ID from the sender
    const tabId = sender.tab?.id;
    if (!tabId) {
      sendResponse({ success: false, error: "No tab ID available" });
      return false;
    }

    // Add tabId to message data for easier tracking
    message.tabId = tabId;

    // Get the current analysis data for this tab
    const analyzedTabsData = getAnalyzedTabsData();
    const tabData = analyzedTabsData.get(tabId);

    if (!tabData) {
      sendResponse({ success: false, error: "No existing analysis for this tab" });
      return false;
    }

    // Log the update in a simple format
    if (message.feature === "titleMatchesDomain") {
      logMessage(`Title match updated for tab ${tabId}: ${message.value ? "MATCH" : "NO MATCH"}`);
    }

    sendResponse({ success: true, message: "Feature update acknowledged" });
  } catch (error) {
    sendResponse({ success: false, error: error.toString() });
  }

  return true;
}

// Default export with all handlers
export default {
  updateBadge,
  analyzeTabUrl,
  handleGetTabAnalysisData,
  handleAnalyzeUrlManually,
  handlePageReady,
  handleUpdateFeatureState,
  getAnalyzedTabsData,
  getPendingAnalyses
};
