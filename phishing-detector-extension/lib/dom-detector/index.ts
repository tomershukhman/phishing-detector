// DOM phishing detector main entry point
import type { DomFeature, DomFeatures } from "./types"
import { extractFormFeatures } from "./form-features"
import { extractLinkFeatures } from "./link-features"
import { extractContentFeatures } from "./content-features"
import { extractSecurityFeatures } from "./security-features"
import { extractInvisibleFeatures } from "./invisible-features"
import { extractCookieConsentFeatures } from "./cookie-consent-detector"
import { calculateSuspiciousScore } from "./scoring"
import { domLogger as logger } from "../logger"
import { logHighlighted, enhanceDomLogging } from "./debug-utils"

// Enable enhanced logging for better visibility
try {
  enhanceDomLogging();
} catch (e) {
  console.error("Failed to enhance DOM logging:", e);
}

// Analyze the DOM for potential phishing indicators
export function analyzeDom(): DomFeatures {
  const url = window.location.href;
  const features = [];
  const startTime = performance.now();
  
  // Enhanced logging for better visibility
  logger.log(`DOM detector analyzing ${url} (document ready: ${document.readyState}, title: ${document.title ? 'yes' : 'no'})`);
  logger.debug(`DOM detector debug mode: window size ${window.innerWidth}x${window.innerHeight}, doctype: ${document.doctype ? 'yes' : 'no'}`);
  
  // Log DOM analysis start with a distinctive message that's easy to spot
  logHighlighted(`Starting DOM analysis for ${url}`);

  try {
    logger.log("Extracting DOM features...");
    // 1. Form-related features
    logger.log("Extracting form features...");
    extractFormFeatures(features);
    
    // 2. Link-related features
    logger.log("Extracting link features...");
    extractLinkFeatures(features);
    
    // 3. Content-related features
    logger.log("Extracting content features...");
    extractContentFeatures(features);
    
    // 4. Security-related features
    logger.log("Extracting security features...");
    extractSecurityFeatures(features);

    // 5. Invisible element features (strong phishing indicators)
    logger.log("Extracting invisible element features...");
    extractInvisibleFeatures(features);
    
    // 6. Cookie consent and privacy popup features
    logger.log("Extracting cookie consent features...");
    extractCookieConsentFeatures(features);

    // Calculate final suspiciousness score (0-1 range)
    logger.log("Calculating suspiciousness score...");
    const suspiciousScore = calculateSuspiciousScore(features);
    
    // Duration of analysis for debugging
    const duration = Math.round(performance.now() - startTime);
    
    logger.log(`DOM analysis completed in ${duration}ms with score: ${suspiciousScore.toFixed(4)}, found ${features.length} features`);
    
    const result = {
      url,
      features,
      suspiciousScore,
      timestamp: Date.now()
    };
    
    logger.log("DOM analysis result:", { summary: JSON.stringify(result).substring(0, 200) + "..." });
    return result;
  } catch (error) {
    logger.error("Error during DOM analysis:", error);
    logger.error("Stack trace:", { stack: error.stack });
    
    // Return a safe default with error indication
    const errorResult = {
      url,
      features: [{
        name: "analysisError",
        value: true,
        weight: 0,
        impact: 0
      }],
      suspiciousScore: 0,
      timestamp: Date.now()
    };
    
    logger.log("Returning error result due to DOM analysis failure");
    return errorResult;
  }
}
