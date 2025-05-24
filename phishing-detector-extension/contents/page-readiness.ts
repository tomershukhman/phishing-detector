// Function to ensure the page is fully loaded before extracting features
import { contentLogger as logger } from "../lib/logger"

export function ensurePageReadiness(): Promise<void> {
  return new Promise(resolve => {
    const log = (msg: string) => logger.log(`[PHISHING-DETECTOR] ${msg}`);
    
    // If document is complete, resolve after a short delay
    if (document.readyState === 'complete') {
      log("Document loaded, waiting briefly for dynamic content");
      setTimeout(resolve, 300);
      return;
    }
    
    // Otherwise wait for load event
    log("Document not fully loaded, waiting for load event");
    window.addEventListener('load', () => {
      setTimeout(resolve, 300);
    }, { once: true });
  });
}
