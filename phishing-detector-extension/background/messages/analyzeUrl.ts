// Using Plasmo messaging API
import type { PlasmoMessaging } from "@plasmohq/messaging"
import { analyzeForPhishing, analyzeForPhishingWithPerformanceTracking } from "~combined-detector"
import { getPageLoadTimestamps } from "../index"

// Global persistent data store - will be shared across message handlers
if (typeof self !== "undefined") {
  // @ts-ignore
  self.analyzedTabsData = self.analyzedTabsData || new Map()
  // @ts-ignore
  self.pendingAnalyses = self.pendingAnalyses || new Map()
}

// Handler for analyzing a URL
const handler: PlasmoMessaging.MessageHandler = async (req, res) => {
  const { url, tabId, domFeatures } = req.body

  try {
    // Start timing the analysis process itself
    const analysisStartTime = Date.now();

    // Get the page load timestamp if available
    const pageLoadTimestamps = getPageLoadTimestamps();
    const pageLoadTime = pageLoadTimestamps.get(tabId) || analysisStartTime; // Fallback to analysis start time

    // Analyze the URL
    const result = await analyzeForPhishingWithPerformanceTracking(url, domFeatures)

    // Calculate elapsed time for the analysis itself
    const analysisElapsedTime = Date.now() - analysisStartTime;

    // Calculate total elapsed time from page load to completion
    const totalElapsedTime = Date.now() - pageLoadTime;

    // Store the result for this tab (in background context)
    // @ts-ignore
    self.analyzedTabsData.set(tabId, {
      url: url,
      result: result,
      domFeatures: domFeatures,
      timestamp: Date.now(),
      analysisElapsedTime: analysisElapsedTime,
      totalElapsedTime: totalElapsedTime
    })

    // Set badge based on result
    try {
      if (result.isPhishing) {
        // Red badge for phishing
        chrome.action.setBadgeBackgroundColor({ tabId, color: "#FF0000" })
        chrome.action.setBadgeText({ tabId, text: "⚠️" })
      } else {
        // Green badge for safe
        chrome.action.setBadgeBackgroundColor({ tabId, color: "#00AA00" })
        chrome.action.setBadgeText({ tabId, text: "✓" })
      }
    } catch (error) {
      console.error("Error updating badge", error)
    }

    res.send({ success: true, result, analysisElapsedTime, totalElapsedTime })
  } catch (error) {
    console.error("Error analyzing URL", error)
    res.send({ success: false, error: error.toString() })
  }
}

export default handler
