// Central utility for handling suspicious words data to avoid duplication
import { SUSPICIOUS_WORDS } from "./dom-detector/constants";
import { sendContentScriptMessage } from "./messaging-utils";

/**
 * Interface for suspicious words detection data
 */
export interface SuspiciousWordsData {
  timestamp: number;
  url: string;
  fraudTextScore: number;
  calculatedImpact: number;
  suspiciousWordCounts: {
    total: number;
    unique: number;
  };
  topSuspiciousWords: Array<{ word: string; count: number }>;
  allDetectedWords: Record<string, number>;
  visibilityDebugInfo?: {
    totalTextElements: number;
    visibleElements: number;
    hiddenElements: number;
    visibilityRatio: number;
  };
}

/**
 * Store suspicious words data in localStorage
 * @param data The suspicious words data to store
 */
export function storeSuspiciousWordsData(data: SuspiciousWordsData): void {
  try {
    localStorage.setItem('phishing_detector_suspicious_words', JSON.stringify(data));
  } catch (error) {
    console.error("Failed to store suspicious words data:", error);
  }
}

/**
 * Retrieve suspicious words data from localStorage
 * @returns The parsed suspicious words data or null if not available
 */
export function getSuspiciousWordsData(): SuspiciousWordsData | null {
  try {
    const data = localStorage.getItem('phishing_detector_suspicious_words');
    return data ? JSON.parse(data) : null;
  } catch (error) {
    console.error("Failed to retrieve suspicious words data:", error);
    return null;
  }
}

/**
 * Update and send suspicious words data based on detection conditions
 * @param data The suspicious words data to send
 * @param forceUpdate Whether to force update regardless of conditions
 */
export async function updateAndSendSuspiciousWordsData(
  data: SuspiciousWordsData, 
  forceUpdate = false
): Promise<boolean> {
  // Store data first
  storeSuspiciousWordsData(data);
  
  // Determine if we should send a message
  const shouldSendMessage = forceUpdate || 
    !localStorage.getItem('phishing_detector_suspicious_words_sent') || 
    localStorage.getItem('phishing_detector_suspicious_words_refresh_requested');
  
  if (shouldSendMessage) {
    // Set flags to avoid repeated messages
    localStorage.setItem('phishing_detector_suspicious_words_sent', 'true');
    localStorage.removeItem('phishing_detector_suspicious_words_refresh_requested');
    
    // Send message using the utility
    return await sendContentScriptMessage("SUSPICIOUS_WORDS_DATA", data);
  }
  
  return true;
}

/**
 * Update the impact value for suspicious words data
 * @param calculatedImpact The new impact value to set
 * @returns Whether the update was sent successfully
 */
export async function updateSuspiciousWordsImpact(calculatedImpact: number): Promise<boolean> {
  try {
    // Get existing data
    const data = getSuspiciousWordsData();
    if (!data) return false;
    
    // Update the impact
    data.calculatedImpact = calculatedImpact;
    storeSuspiciousWordsData(data);
    
    // Determine if we should send an update based on impact difference
    const previousImpact = parseFloat(localStorage.getItem('phishing_detector_last_impact') || '0');
    const impactDifference = Math.abs(calculatedImpact - previousImpact);
    const refreshRequested = !!localStorage.getItem('phishing_detector_suspicious_words_refresh_requested');
    
    if (impactDifference > 0.1 || refreshRequested) {
      // Store the new impact value
      localStorage.setItem('phishing_detector_last_impact', calculatedImpact.toString());
      // Clear refresh request flag
      localStorage.removeItem('phishing_detector_suspicious_words_refresh_requested');
      
      // Send updated data
      return await sendContentScriptMessage("SUSPICIOUS_WORDS_DATA_UPDATED", data);
    }
    
    return true;
  } catch (error) {
    console.error("Failed to update suspicious words impact:", error);
    return false;
  }
}

/**
 * Request a refresh of suspicious words data
 */
export function requestSuspiciousWordsRefresh(): void {
  localStorage.setItem('phishing_detector_suspicious_words_refresh_requested', 'true');
}

/**
 * Get the suspicious words list from constants
 * @returns Array of suspicious words
 */
export function getSuspiciousWordsList(): string[] {
  return SUSPICIOUS_WORDS;
}
