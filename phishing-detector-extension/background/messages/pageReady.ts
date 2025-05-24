// Using Plasmo messaging API
import type { PlasmoMessaging } from "@plasmohq/messaging"
import { analyzeForPhishing, analyzeForPhishingWithPerformanceTracking } from "~combined-detector"

// Global persistent data store - will be shared across message handlers
if (typeof self !== "undefined") {
  // @ts-ignore
  self.analyzedTabsData = self.analyzedTabsData || new Map()
  // @ts-ignore
  self.pendingAnalyses = self.pendingAnalyses || new Map()
}

// Handler for pageReady message from content script
const handler: PlasmoMessaging.MessageHandler = async (req, res) => {
  const { url } = req.body
  const tabId = req.sender?.tab?.id
  
  if (!tabId) {
    return res.send({ success: false, error: "No tab ID provided" })
  }
  
  // Check if an analysis is already pending
  // @ts-ignore
  if (self.pendingAnalyses && self.pendingAnalyses.has(tabId)) {
    logger.log(`[PHISHING-DETECTOR][${new Date().toISOString()}] Analysis already pending for tab ${tabId}`)
    return res.send({ success: true, status: "pending" })
  }
  
  // Check if we already have a recent analysis for this URL
  // @ts-ignore
  const existingData = self.analyzedTabsData?.get(tabId)
  if (existingData && existingData.url === url) {
    const timeSinceAnalysis = Date.now() - existingData.timestamp
    // If analysis is less than 5 minutes old, reuse it
    if (timeSinceAnalysis < 5 * 60 * 1000) {
      logger.log(`[PHISHING-DETECTOR][${new Date().toISOString()}] Reusing recent analysis for ${url}`)
      return res.send({ 
        success: true, 
        status: "completed", 
        result: existingData.result 
      })
    }
  }
  
  // Start a new analysis
  logger.log(`[PHISHING-DETECTOR][${new Date().toISOString()}] Starting analysis for ${url}`)
  // @ts-ignore
  self.pendingAnalyses.set(tabId, Date.now())
  
  try {
    // Get the DOM features from the content script
    const domFeatures = req.body.domFeatures;
    
    // Analyze the URL with DOM features if available
    const result = await analyzeForPhishingWithPerformanceTracking(url, domFeatures)
    
    // Store the result for this tab
    // @ts-ignore
    self.analyzedTabsData.set(tabId, {
      url: url,
      result: result,
      domFeatures: domFeatures,
      timestamp: Date.now()
    })
    
    // Update the badge
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
    
    // Send a message back to the content script with results
    try {
      await chrome.tabs.sendMessage(tabId, {
        action: "analysisCompleted",
        result: result
      })
    } catch (err) {
      console.error("Error sending results to content script", err)
    }
    
    // @ts-ignore
    self.pendingAnalyses.delete(tabId)
    res.send({ success: true, status: "completed", result })
  } catch (error) {
    // @ts-ignore
    self.pendingAnalyses.delete(tabId)
    console.error("Error during analysis from content script", error)
    res.send({ success: false, error: error.toString() })
  }
}

export default handler
