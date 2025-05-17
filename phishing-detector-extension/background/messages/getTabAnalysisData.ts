// Using Plasmo messaging API
import type { PlasmoMessaging } from "@plasmohq/messaging"

// Global persistent data store - will be shared across message handlers
if (typeof self !== "undefined") {
  // @ts-ignore
  self.analyzedTabsData = self.analyzedTabsData || new Map()
  // @ts-ignore
  self.pendingAnalyses = self.pendingAnalyses || new Map()
}

// Handler for getTabAnalysisData message
const handler: PlasmoMessaging.MessageHandler = async (req, res) => {
  const { tabId } = req.body
  
  // Track active tabs that have been analyzed with their results (stored in background context)
  // @ts-ignore
  if (self.analyzedTabsData && self.analyzedTabsData.has(tabId)) {
    // @ts-ignore
    const data = self.analyzedTabsData.get(tabId)
    res.send({ success: true, data })
  } else {
    res.send({ success: false })
  }
}

export default handler
