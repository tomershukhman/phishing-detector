// Cookie consent and privacy popup detector
import type { DomFeature } from "./types"
import { domLogger as logger } from "../logger"

// Store detection result for later use with potential async detection
let lastDetectionResult = false;
let lastDetectionTime = 0;

// Set up delayed detection for cookie consent popups that may appear after page load
// This runs only once per page load
(function setupDelayedDetection() {
  // Don't run in non-browser environments (for testing)
  if (typeof window === 'undefined' || typeof document === 'undefined') return;
  
  // Check for popups after short delays to catch dynamically added consent popups
  const checkTimes = [1500, 3000, 5000]; // Check after 1.5s, 3s, and 5s
  
  checkTimes.forEach(delay => {
    setTimeout(() => {
      const hasPopup = detectConsentElements();
      if (hasPopup) {
        logger.log(`Delayed consent popup detection (${delay}ms): FOUND`);
        // Update the cached result
        lastDetectionResult = true;
        lastDetectionTime = Date.now();
        // Save to localStorage for retrieval by other parts of the extension
        try {
          localStorage.setItem('phishing_detector_consent_details', JSON.stringify({ 
            hasConsentPopup: true,
            detectedAt: lastDetectionTime,
            delayedDetection: true
          }));
        } catch (e) {
          logger.error("Error storing delayed consent details:", e);
        }
      } else {
        logger.log(`Delayed consent popup detection (${delay}ms): not found`);
      }
    }, delay);
  });
})();

// Extract cookie consent and privacy agreement popup features
export function extractCookieConsentFeatures(features: DomFeature[]): void {
  // Check for any visible consent buttons (combined cookie/privacy detection)
  // or use cached result if we found one in delayed detection
  const recentDetection = Date.now() - lastDetectionTime < 30000; // Within last 30 seconds
  const hasConsentPopup = detectConsentElements() || (recentDetection && lastDetectionResult);

  // Add the single consent popup feature
  features.push({
    name: "hasConsentPopup",
    value: hasConsentPopup,
    weight: 0.85, 
    impact: hasConsentPopup ? -0.5 : 0 // Negative impact means it's a legitimate site indicator
  });

  // Record detection info for debugging
  try {
    localStorage.setItem('phishing_detector_consent_details', JSON.stringify({ 
      hasConsentPopup,
      cachedResult: lastDetectionResult && recentDetection,
      timestamp: Date.now()
    }));
    logger.log("Cookie consent detection details:", { hasConsentPopup });
  } catch (e) {
    // Ignore storage errors
    logger.error("Error storing consent details:", e);
  }
}

/**
 * Detects cookie consent and privacy agreement buttons
 * Simple implementation that only checks for visible buttons with agreement terms
 * Returns true if any consent-related button is found
 */
function detectConsentElements(): boolean {
  // Combined list of words for cookie consent and privacy agreement buttons
  const consentWords = [
    // Cookie consent related
    'accept', 'agree', 'cookie', 'consent', 
    'accept all', 'i agree', 'got it',
    'accept cookies', 'allow cookies', 'allow all',
    // Privacy agreement related
    'privacy', 'policy', 'terms', 'conditions',
    'privacy policy', 'terms of use', 'terms of service'
  ];
  
  // Also check for simple matches (for cases like "Accept All" that might not get caught)
  const simpleMatches = ['accept', 'allow', 'agree', 'consent'];

  // Selectors for common buttons
  const buttonSelectors = [
    'button', '.button', '[role="button"]', 'a.btn', 'a.button',
    'input[type="button"]', 'input[type="submit"]', '.btn', '.accept-btn',
    '.agree-button', '.consent-btn', '.consent-button', '.cookie-btn',
    '.cookie-button', '.privacy-btn', '.privacy-button'
  ];

  // Find all potential buttons
  const potentialButtons = document.querySelectorAll(buttonSelectors.join(', '));
  logger.log(`Found ${potentialButtons.length} potential consent buttons to check`);
  
  // Check if any visible button contains consent-related text
  for (const button of Array.from(potentialButtons)) {
    // Skip invisible buttons
    if (!isElementVisible(button)) {
      continue;
    }

    const buttonText = (button.textContent || '').toLowerCase().trim();
    
    // Skip buttons with no text
    if (!buttonText) {
      continue;
    }

    // Check if button text contains any consent keywords
    if (consentWords.some(word => buttonText.includes(word))) {
      // Log for debugging
      logger.log('Consent/privacy button detected (phrase match):', buttonText);
      return true;
    }
    
    // Also check for simple word matches (like just "Accept" in "Accept All")
    const buttonWords = buttonText.split(/\s+/);
    if (buttonWords.some(word => simpleMatches.includes(word))) {
      logger.log('Consent/privacy button detected (word match):', buttonText);
      return true;
    }
    
    // Check for data attributes that might indicate consent buttons
    const element = button as HTMLElement;
    if (element.dataset && (
        element.dataset.action === 'consent' || 
        element.dataset.actionType === 'accept' ||
        element.dataset.cookieAction ||
        element.dataset.consent ||
        element.id === 'accept' ||
        element.id === 'acceptAll' ||
        element.id === 'agree'
      )) {
      logger.log('Consent/privacy button detected (data attribute):', element.dataset);
      return true;
    }
    
    // Extra debug logging for buttons that don't match
    logger.log('Button found but not matching consent patterns:', buttonText);
  }

  return false;
}

/**
 * Checks if an element is visible on the page
 */
function isElementVisible(element: Element): boolean {
  // Get computed style
  const style = window.getComputedStyle(element);
  
  // Check basic visibility properties
  if (style.display === 'none' || 
      style.visibility === 'hidden' || 
      style.opacity === '0' || 
      parseFloat(style.opacity) < 0.1) {
    return false;
  }
  
  // Check if element has dimensions
  const rect = element.getBoundingClientRect();
  if (rect.width <= 1 || rect.height <= 1) {
    return false;
  }
  
  // Check if element is outside viewport
  const viewportWidth = window.innerWidth || document.documentElement.clientWidth;
  const viewportHeight = window.innerHeight || document.documentElement.clientHeight;
  
  if (rect.right < 0 || rect.bottom < 0 || 
      rect.left > viewportWidth || rect.top > viewportHeight) {
    return false;
  }
  
  return true;
}
