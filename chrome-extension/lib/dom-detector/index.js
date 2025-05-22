// DOM detector main entry point - analyzes DOM for phishing indicators
let logger = console;

// Make logger available immediately
const domLogger = {
  log: (...args) => console.log('[PHISHING-DETECTOR-DOM]', ...args),
  error: (...args) => console.error('[PHISHING-DETECTOR-DOM]', ...args),
  warn: (...args) => console.warn('[PHISHING-DETECTOR-DOM]', ...args),
  debug: (...args) => console.debug('[PHISHING-DETECTOR-DOM]', ...args)
};

// Try to load the logger module
(async function loadLogger() {
  try {
    const loggerModule = await import(chrome.runtime.getURL('../logger.js'));
    if (loggerModule && loggerModule.domLogger) {
      logger = loggerModule.domLogger;
      logger.log("DOM detector logger loaded successfully");
    }
  } catch (error) {
    console.error("Error loading logger:", error);
  }
})();

// Analyze the DOM for potential phishing indicators
export function analyzeDom() {
  const url = window.location.href;
  const features = [];
  const startTime = performance.now();
  
  logger.log(`DOM detector analyzing ${url} (document ready: ${document.readyState}, title: ${document.title ? 'yes' : 'no'})`);
  logger.debug(`DOM detector debug mode: window size ${window.innerWidth}x${window.innerHeight}, doctype: ${document.doctype ? 'yes' : 'no'}`);

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

    // 5. Invisible element features
    logger.log("Extracting invisible element features...");
    extractInvisibleFeatures(features);

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
    
    return result;
  } catch (error) {
    logger.error("Error during DOM analysis:", error);
    
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

// Form feature extraction
function extractFormFeatures(features) {
  try {
    // Check for login/password forms
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    const forms = document.forms;
    
    // Add password field feature
    features.push({
      name: "has_password_field",
      value: passwordInputs.length > 0,
      weight: 0.7,
      impact: passwordInputs.length > 0 ? 0.7 : 0
    });
    
    // Add login form feature
    const hasLoginForm = Array.from(forms).some(form => {
      const formHTML = form.innerHTML.toLowerCase();
      return (formHTML.includes('login') || 
              formHTML.includes('signin') || 
              formHTML.includes('log in')) && 
             form.querySelector('input[type="password"]');
    });
    
    features.push({
      name: "has_login_form",
      value: hasLoginForm,
      weight: 0.8,
      impact: hasLoginForm ? 0.8 : 0
    });
    
    // Add hidden form field feature (possible phishing indicator)
    const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
    const hasSuspiciousHiddenFields = Array.from(hiddenInputs).some(input => {
      const name = input.name.toLowerCase();
      return name.includes('redirect') || name.includes('return') || name.includes('target');
    });
    
    features.push({
      name: "has_suspicious_hidden_fields",
      value: hasSuspiciousHiddenFields,
      weight: 0.6,
      impact: hasSuspiciousHiddenFields ? 0.6 : 0
    });
    
  } catch (error) {
    logger.error("Error extracting form features:", error);
  }
}

// Link feature extraction
function extractLinkFeatures(features) {
  try {
    const links = document.querySelectorAll('a[href]');
    const currentDomain = window.location.hostname;
    
    // Calculate the ratio of external links
    let externalLinkCount = 0;
    let totalLinkCount = links.length;
    
    if (totalLinkCount > 0) {
      links.forEach(link => {
        try {
          const href = link.href;
          if (href.startsWith('http')) {
            const linkDomain = new URL(href).hostname;
            if (linkDomain !== currentDomain) {
              externalLinkCount++;
            }
          }
        } catch (e) {
          // Ignore invalid URLs
        }
      });
      
      const externalLinkRatio = externalLinkCount / totalLinkCount;
      
      features.push({
        name: "external_link_ratio",
        value: externalLinkRatio,
        weight: 0.5,
        impact: externalLinkRatio * 0.5
      });
      
      // Check for deceptive link text
      let deceptiveLinkCount = 0;
      
      links.forEach(link => {
        try {
          const href = link.href;
          const text = link.textContent.trim().toLowerCase();
          
          if (href.startsWith('http')) {
            const linkDomain = new URL(href).hostname;
            
            // Check if link text contains a different domain than the actual link
            const commonDomains = ['google', 'facebook', 'apple', 'microsoft', 'paypal', 'amazon'];
            
            const hasMismatchedDomain = commonDomains.some(domain => {
              return text.includes(domain) && !linkDomain.includes(domain);
            });
            
            if (hasMismatchedDomain) {
              deceptiveLinkCount++;
            }
          }
        } catch (e) {
          // Ignore invalid URLs
        }
      });
      
      const hasDeceptiveLinks = deceptiveLinkCount > 0;
      
      features.push({
        name: "has_deceptive_links",
        value: hasDeceptiveLinks,
        weight: 0.9,
        impact: hasDeceptiveLinks ? 0.9 : 0
      });
    } else {
      // No links is unusual for legitimate sites
      features.push({
        name: "no_links",
        value: true,
        weight: 0.4,
        impact: 0.4
      });
    }
  } catch (error) {
    logger.error("Error extracting link features:", error);
  }
}

// Content feature extraction
function extractContentFeatures(features) {
  try {
    const bodyText = document.body ? document.body.textContent.toLowerCase() : '';
    
    // Check for security/urgency keywords
    const securityKeywords = ['security', 'verify', 'confirmation', 'account', 'login', 'submit', 'update'];
    const urgencyKeywords = ['urgent', 'immediately', 'alert', 'warning', 'limited', 'expire'];
    
    const securityCount = securityKeywords.filter(kw => bodyText.includes(kw)).length;
    const urgencyCount = urgencyKeywords.filter(kw => bodyText.includes(kw)).length;
    
    const hasSuspiciousContent = securityCount >= 3 || urgencyCount >= 2;
    
    features.push({
      name: "has_suspicious_content",
      value: hasSuspiciousContent,
      weight: 0.7,
      impact: hasSuspiciousContent ? 0.7 : 0
    });
    
    // Check for poor grammar/spelling (simplified heuristic)
    // In a real implementation, this would use a more sophisticated approach
    const misspelledWords = ['acces', 'accout', 'verifiy', 'pasword', 'securty', 'usename'];
    const hasMisspelledWords = misspelledWords.some(word => bodyText.includes(word));
    
    features.push({
      name: "has_spelling_errors",
      value: hasMisspelledWords,
      weight: 0.5,
      impact: hasMisspelledWords ? 0.5 : 0
    });
    
    // Check for brand names
    const brandNames = ['paypal', 'apple', 'microsoft', 'amazon', 'netflix', 'facebook'];
    const brandMentioned = brandNames.filter(brand => bodyText.includes(brand));
    
    const hasBrandNames = brandMentioned.length > 0;
    
    features.push({
      name: "mentions_brands",
      value: hasBrandNames,
      weight: 0.3,
      impact: hasBrandNames ? 0.3 : 0
    });
  } catch (error) {
    logger.error("Error extracting content features:", error);
  }
}

// Security feature extraction
function extractSecurityFeatures(features) {
  try {
    // Check if the page is served over HTTPS (for completeness, already in URL features)
    const isHttps = window.location.protocol === 'https:';
    
    features.push({
      name: "is_https",
      value: isHttps,
      weight: 0.8,
      impact: isHttps ? 0 : 0.8 // Only impact if NOT https (negative signal)
    });
    
    // Check for security-related HTML meta tags
    const hasCspTag = !!document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    
    features.push({
      name: "has_csp",
      value: hasCspTag,
      weight: 0.4,
      impact: hasCspTag ? 0 : 0.4 // Only impact if missing (negative signal)
    });
  } catch (error) {
    logger.error("Error extracting security features:", error);
  }
}

// Invisible elements feature extraction
function extractInvisibleFeatures(features) {
  try {
    // Look for invisible forms or fields that might be hiding phishing content
    const allInputs = document.querySelectorAll('input');
    
    let invisibleInputCount = 0;
    
    allInputs.forEach(input => {
      if (input.type !== 'hidden') { // Exclude legitimate hidden inputs
        const style = window.getComputedStyle(input);
        
        // Check various ways elements might be hidden
        if (style.display === 'none' || 
            style.visibility === 'hidden' || 
            style.opacity === '0' || 
            parseInt(style.height) === 0 || 
            parseInt(style.width) === 0) {
          invisibleInputCount++;
        }
      }
    });
    
    const hasInvisibleInputs = invisibleInputCount > 0;
    
    features.push({
      name: "has_invisible_inputs",
      value: hasInvisibleInputs,
      weight: 0.9,
      impact: hasInvisibleInputs ? 0.9 : 0
    });
    
    // Check for layered elements (potentially hiding content)
    const hasLayeredElements = document.querySelectorAll('[style*="position: absolute"]').length > 3;
    
    features.push({
      name: "has_many_absolute_elements",
      value: hasLayeredElements,
      weight: 0.5,
      impact: hasLayeredElements ? 0.5 : 0
    });
  } catch (error) {
    logger.error("Error extracting invisible features:", error);
  }
}

// Calculate a suspiciousness score from the extracted features
function calculateSuspiciousScore(features) {
  try {
    if (!features || features.length === 0) {
      return 0;
    }
    
    // Calculate weighted sum of feature impacts
    let totalImpact = 0;
    let totalWeight = 0;
    
    features.forEach(feature => {
      if (typeof feature.impact === 'number' && typeof feature.weight === 'number') {
        totalImpact += feature.impact;
        totalWeight += feature.weight;
      }
    });
    
    // Normalize to 0-1 range
    return totalWeight > 0 ? Math.min(totalImpact / totalWeight, 1) : 0;
  } catch (error) {
    logger.error("Error calculating suspicious score:", error);
    return 0;
  }
}
