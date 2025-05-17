// Centralized messaging utilities that follow Plasmo best practices
import { sendToBackground } from "@plasmohq/messaging";

/**
 * Send a message from the content script to extension components (popup/background)
 * with proper error handling and retry logic
 * 
 * @param type Message type identifier 
 * @param data Message data payload
 * @param maxRetries Number of retries on failure
 * @returns Promise that resolves to true if message was delivered successfully
 */
export function sendContentScriptMessage(type: string, data: any, maxRetries = 2): Promise<boolean> {
  return new Promise((resolve) => {
    let retryCount = 0;
    
    function attemptSend() {
      try {
        chrome.runtime.sendMessage({ type, data }, (response) => {
          if (chrome.runtime.lastError) {
            console.debug(`Error sending ${type} message:`, chrome.runtime.lastError.message);
            
            if (retryCount < maxRetries) {
              retryCount++;
              console.debug(`Retrying send (${retryCount}/${maxRetries})...`);
              setTimeout(attemptSend, 500 * retryCount); // Exponential backoff
            } else {
              console.debug(`Failed to send ${type} after ${maxRetries} retries`);
              resolve(false);
            }
          } else if (response && response.received) {
            console.debug(`${type} message delivered successfully`);
            resolve(true);
          } else {
            console.debug(`${type} message sent but no confirmation received`);
            resolve(true); // Still count as success since message was sent
          }
        });
      } catch (error) {
        console.debug(`Exception sending ${type} message:`, error);
        
        if (retryCount < maxRetries) {
          retryCount++;
          console.debug(`Retrying send after exception (${retryCount}/${maxRetries})...`);
          setTimeout(attemptSend, 500 * retryCount); // Exponential backoff
        } else {
          console.debug(`Failed to send ${type} after ${maxRetries} retries due to exceptions`);
          resolve(false);
        }
      }
    }
    
    attemptSend();
  });
}

/**
 * Safely get DOM features from a tab with proper error handling
 * @param tabId Chrome tab ID to get features from
 * @returns Promise resolving to DOM features or null if unavailable
 */
export async function getDomFeaturesFromTab(tabId: number): Promise<any> {
  console.debug(`Attempting to get DOM features from tab ${tabId}`);
  try {
    return await new Promise((resolve) => {
      try {
        // Add a timeout to prevent hanging if the content script doesn't respond
        const timeoutId = setTimeout(() => {
          console.debug(`DOM features request timed out for tab ${tabId}`);
          resolve(null);
        }, 3000);
        
        chrome.tabs.sendMessage(tabId, { action: "getDomFeatures" }, (response) => {
          clearTimeout(timeoutId);
          
          if (chrome.runtime.lastError) {
            console.debug(`Content script not available for tab ${tabId}:`, chrome.runtime.lastError.message);
            resolve(null); // Not an error, just can't get DOM features
          } else {
            console.debug(`Received DOM features from tab ${tabId}:`, response ? "success" : "empty response");
            resolve(response);
          }
        });
      } catch (err) {
        console.debug(`Error sending message to content script for tab ${tabId}:`, err);
        resolve(null);
      }
    });
  } catch (error) {
    console.error(`Error in getDomFeaturesFromTab for tab ${tabId}:`, error);
    return null;
  }
}

/**
 * Create a proper message listener that handles responses correctly
 * @param handler Function to handle incoming messages
 * @returns Function to be used for removing the listener
 */
export function createMessageListener(
  handler: (message: any, sender: chrome.runtime.MessageSender, sendResponse: (response?: any) => void) => boolean | void
): (message: any, sender: chrome.runtime.MessageSender, sendResponse: (response?: any) => void) => boolean | void {
  const wrappedHandler = (message: any, sender: chrome.runtime.MessageSender, sendResponse: (response?: any) => void) => {
    try {
      return handler(message, sender, sendResponse);
    } catch (error) {
      console.error("Error in message handler:", error);
      sendResponse({ error: true, message: error.message });
      return false;
    }
  };
  
  chrome.runtime.onMessage.addListener(wrappedHandler);
  return wrappedHandler;
}

/**
 * Get the current tab URL
 * @returns Promise resolving to the URL of the current active tab
 */
export function getCurrentTabUrl(): Promise<string> {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs[0]?.url || "";
      resolve(url);
    });
  });
}

/**
 * Get the current tab ID
 * @returns Promise resolving to the ID of the current active tab
 */
export function getCurrentTabId(): Promise<number | undefined> {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id;
      resolve(tabId);
    });
  });
}
