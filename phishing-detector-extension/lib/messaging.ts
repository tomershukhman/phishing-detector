// API for communicating with the background service worker
import { sendToBackground } from "@plasmohq/messaging"
import type { PhishingAnalysisResult } from "../combined-detector"
import { modelLogger as logger } from "./logger"

// Helper function to safely get DOM features from a tab
async function getDomFeaturesFromTab(tabId: number): Promise<any> {
  logger.log(`Attempting to get DOM features from tab ${tabId}`);
  try {
    return await new Promise((resolve) => {
      try {
        // Add a timeout to prevent hanging if the content script doesn't respond
        const timeoutId = setTimeout(() => {
          logger.log(`DOM features request timed out for tab ${tabId}`);
          resolve(null);
        }, 3000);

        chrome.tabs.sendMessage(tabId, { action: "getDomFeatures" }, (response) => {
          clearTimeout(timeoutId);

          if (chrome.runtime.lastError) {
            logger.log(`Content script not available for tab ${tabId}:`, chrome.runtime.lastError.message);
            resolve(null); // Not an error, just can't get DOM features
          } else {
            logger.log(`Received DOM features from tab ${tabId}:`, response ? "success" : "empty response");
            resolve(response);
          }
        });
      } catch (err) {
        logger.log(`Error sending message to content script for tab ${tabId}:`, err);
        resolve(null);
      }
    });
  } catch (error) {
    console.error(`Error in getDomFeaturesFromTab for tab ${tabId}:`, error);
    return null;
  }
}

// Get the analysis data for a specific tab
export async function getTabAnalysisData(tabId: number): Promise<{
  success: boolean;
  data?: {
    url: string;
    result: PhishingAnalysisResult;
    timestamp: number;
    analysisElapsedTime?: number;
    totalElapsedTime?: number;
  };
}> {
  return sendToBackground({
    name: "getTabAnalysisData",
    body: { tabId }
  })
}

// Manually trigger an analysis for a URL
export async function analyzeUrlManually(url: string, tabId: number): Promise<{
  success: boolean;
  result?: PhishingAnalysisResult;
  analysisElapsedTime?: number;
  totalElapsedTime?: number;
  error?: string;
}> {
  logger.log(`Manual analysis requested for URL: ${url}, tabId: ${tabId}`);

  // First try to get DOM features from the content script
  let domFeatures = null;

  try {
    // Ask the content script for DOM features
    const domResponse = await getDomFeaturesFromTab(tabId);

    if (domResponse && domResponse.domFeatures) {
      domFeatures = domResponse.domFeatures;
      logger.log(`Successfully got DOM features for ${url} with ${domFeatures.features?.length || 0} features`);
    } else {
      logger.log(`No DOM features available for ${url}, proceeding with URL-only analysis`);
    }
  } catch (error) {
    console.error(`Error getting DOM features for ${url}:`, error);
    // Continue without DOM features
  }

  // Now send the analysis request to the background
  logger.log(`Sending analysis request to background for ${url}${domFeatures ? " with DOM features" : ""}`);
  try {
    const result = await sendToBackground({
      name: "analyzeUrl",
      body: { url, tabId, domFeatures }
    });
    logger.log(`Analysis result for ${url}:`, result);
    return result;
  } catch (error) {
    console.error(`Error during background analysis for ${url}:`, error);
    return { success: false, error: error.toString() };
  }
}

// Force a refresh of the analysis for a URL


// Get the current tab URL
export function getCurrentTabUrl(): Promise<string> {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs[0]?.url || "";
      resolve(url);
    });
  });
}

// Get the current tab ID
export function getCurrentTabId(): Promise<number | undefined> {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id;
      resolve(tabId);
    });
  });
}
