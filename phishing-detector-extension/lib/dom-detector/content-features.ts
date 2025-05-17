// Content features extraction for DOM detector
import type { DomFeature } from "./types"
import { extractDomainName } from "./utils"
import { updateAndSendSuspiciousWordsData, updateSuspiciousWordsImpact } from "../suspicious-words-utils"
import { domLogger as logger } from "../logger"
import { isElementVisible, shouldSkipDueToProcessedParent } from "./visibility-utils"

// Extract content-related features
export function extractContentFeatures(features: DomFeature[]): void {
  // 1. iframes with suspicious sources
  const iframes = document.querySelectorAll('iframe');
  let iframeSrcCount = 0;
  let dynamicIframeDetected = false;
  
  // Get the base domain for more consistent comparison
  const currentDomain = extractDomainName(window.location.hostname);
  
  iframes.forEach(iframe => {
    const src = iframe.getAttribute('src') || '';
    
    // Skip about:blank, javascript: and empty sources
    if (!src || src === 'about:blank' || src.startsWith('javascript:')) {
      return;
    }
    
    try {
      // Handle relative URLs by converting to absolute
      const absoluteUrl = new URL(src, window.location.href);
      const iframeDomain = extractDomainName(absoluteUrl.hostname);
      
      // Compare base domains instead of checking if one contains the other
      if (iframeDomain && iframeDomain !== currentDomain) {
        iframeSrcCount++;
      }
    } catch (e) {
      // Invalid URL, skip this iframe
    }
  });
  
  // New: Look for dynamically created iframes in script tags
  const scriptElements = document.querySelectorAll('script');
  for (const script of Array.from(scriptElements)) {
    const scriptContent = script.textContent || '';
    
    // Look for common iframe creation patterns
    if (
      // Pattern 1: createElement('iframe') with document.body.appendChild
      (scriptContent.includes('createElement') && 
       scriptContent.includes('iframe') && 
       scriptContent.includes('appendChild')) ||
       
      // Pattern 2: Common obfuscation techniques with small iframe dimensions
      (scriptContent.includes('iframe') && 
       (scriptContent.match(/height\s*[:=]\s*("|')?1(px)?("|')?/) ||
        scriptContent.match(/width\s*[:=]\s*("|')?1(px)?("|')?/) ||
        scriptContent.includes('visibility:hidden') ||
        scriptContent.includes('display:none'))) ||
        
      // Pattern 3: Specific to iframe creation with style manipulation (like in the example)
      ((scriptContent.includes('createElement(\'iframe\')') || 
       scriptContent.includes('createElement("iframe")') ||
       scriptContent.includes('createElement(`iframe`)') ||
       scriptContent.includes('createElement("iframe")') ||
       // More generic detection for minified/obfuscated code
       scriptContent.match(/createElement\(['"`]iframe['"`]\)/i)) &&
       (scriptContent.includes('style.position') ||
        scriptContent.includes('style.visibility') ||
        scriptContent.includes('style.display') ||
        scriptContent.includes('style.border') ||
        scriptContent.includes('style.top') ||
        scriptContent.includes('style.left'))) ||
        
      // Pattern 4: Specific pattern from the example - self-executing function that creates hidden iframe
      (scriptContent.includes('function(') && 
       scriptContent.includes('document.createElement(') && 
       scriptContent.includes('iframe') && 
       scriptContent.includes('document.body') &&
       scriptContent.includes('appendChild') &&
       (scriptContent.includes('height=1') || scriptContent.includes('height:1') ||
        scriptContent.includes('width=1') || scriptContent.includes('width:1') ||
        scriptContent.includes('visibility:hidden') || scriptContent.includes('visibility=hidden') ||
        scriptContent.includes('position:absolute') || scriptContent.includes('border:none'))) ||
        
      // Pattern 5: Detect CF (Cloudflare) bypass iframe pattern specifically
      (scriptContent.includes('__CF$cv$params') && 
       scriptContent.includes('createElement') && 
       scriptContent.includes('iframe'))
    ) {
      logger.log("Dynamic iframe creation detected in script:", 
                  scriptContent.substring(0, 100) + "...");
      dynamicIframeDetected = true;
      break;
    }
  }
  
  // Update impact based on whether we detected dynamic iframe creation
  const iframeImpact = dynamicIframeDetected ? 
                        0.9 :  // High phishing signal for dynamic iframe creation
                       (iframeSrcCount > 0 ? 0.5 : -0.1); // Original impact logic
  
  features.push({
    name: "iframeSrcCount",
    value: dynamicIframeDetected ? iframeSrcCount + 1 : iframeSrcCount, // Increment count for dynamic detection
    weight: dynamicIframeDetected ? 0.8 : 0.6, // Increase weight for dynamic iframes
    impact: iframeImpact
  });
  
  // Add debug logging for dynamic iframe detection
  logger.log("iframe analysis:", {
    staticIframeCount: iframeSrcCount,
    dynamicIframeDetected,
    finalImpact: iframeImpact,
    weightAssigned: dynamicIframeDetected ? 0.8 : 0.6,
    notes: dynamicIframeDetected ? "Dynamic iframe creation detected - high phishing risk" : 
           (iframeSrcCount > 0 ? "External iframes detected" : "No suspicious iframes found")
  });
  
  // 2. Empty or suspicious href links
  const blankLinks = document.querySelectorAll('a[href="#"], a[href=""], a[href="javascript:void(0)"]');
  
  features.push({
    name: "blankLinksCount",
    value: blankLinks.length,
    weight: 0.4,
    impact: blankLinks.length > 5 ? 0.3 : -0.1
  });
  
  // 4. Hidden elements that might be used for clickjacking
  const hiddenElements = document.querySelectorAll('[style*="opacity: 0"], [style*="display: none"], [hidden]');
  
  features.push({
    name: "hiddenElementsCount",
    value: hiddenElements.length,
    weight: 0.4,
    impact: hiddenElements.length > 5 ? 0.3 : -0.1
  });
  
  // 5. Enhanced favicon analysis
  // Check for favicon and analyze its quality/properties
  const faviconElements = document.querySelectorAll('link[rel*="icon"], link[rel="shortcut icon"], link[rel="apple-touch-icon"]');
  
  // Helper function to check if the site is using a default fallback favicon
  // This looks for direct favicon.ico in root if no explicit link tag exists
  const checkForRootFavicon = (): Promise<boolean> => {
    return new Promise(resolve => {
      // If we already have favicon elements, no need to check for default
      if (faviconElements.length > 0) {
        resolve(false);
        return;
      }
      
      // Try to fetch the default favicon.ico from site root
      const rootFaviconUrl = `${window.location.origin}/favicon.ico`;
      
      // Use fetch with a small timeout to check if the favicon exists
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 1000); // 1 second timeout
      
      fetch(rootFaviconUrl, {
        method: 'HEAD',
        signal: controller.signal
      })
      .then(response => {
        clearTimeout(timeoutId);
        if (response.ok) {
          // Root favicon exists
          resolve(true);
        } else {
          resolve(false);
        }
      })
      .catch(() => {
        clearTimeout(timeoutId);
        resolve(false);
      });
    });
  };
  
  // For synchronous execution, we'll assume no root favicon initially
  let hasRootFavicon = false;
  
  // Try to check for root favicon but don't wait for it
  checkForRootFavicon().then(result => {
    hasRootFavicon = result;
    logger.log("Root favicon.ico check:", hasRootFavicon);
  });
  
  const faviconExists = faviconElements.length > 0 || hasRootFavicon;
  
  // Enhanced detection - check if we have a valid favicon with a proper path
  let hasQualityFavicon = false;
  let faviconQualityScore = 0;
  const faviconDetails: Array<{href: string, rel: string, domain?: string, standardName: boolean}> = [];
  
  if (faviconExists) {
    for (const favicon of Array.from(faviconElements)) {
      const href = favicon.getAttribute('href');
      const rel = favicon.getAttribute('rel') || '';
      
      // Skip if no href attribute
      if (!href) continue;
      
      const faviconDetail = {
        href, 
        rel,
        domain: undefined as string | undefined,
        standardName: false
      };
      
      // Try to resolve the favicon URL
      let faviconUrl: string;
      try {
        faviconUrl = new URL(href, window.location.href).href;
        faviconQualityScore += 1; // Basic point for having a valid URL
        
        // Check if favicon is from same domain (more trustworthy)
        const faviconDomain = extractDomainName(new URL(faviconUrl).hostname);
        const pageDomain = extractDomainName(window.location.hostname);
        faviconDetail.domain = faviconDomain;
        
        if (faviconDomain === pageDomain) {
          faviconQualityScore += 2; // Same domain favicon is a good sign
          hasQualityFavicon = true;
        }
        
        // Check for standard favicon paths/names
        const isStandardName = href.includes('favicon.ico') || 
                              href.includes('favicon.png') || 
                              href.match(/icon-\d+x\d+/) || 
                              href.match(/apple-touch-icon/);
                              
        if (isStandardName) {
          faviconQualityScore += 1; // Standard naming convention
          faviconDetail.standardName = true;
        }
        
        // Additional bonus for apple-touch-icon (usually higher quality)
        if (rel.includes('apple-touch-icon')) {
          faviconQualityScore += 0.5;
        }
        
        faviconDetails.push(faviconDetail);
      } catch (e) {
        // Invalid URL, might be a relative path or malformed
        logger.log("Error parsing favicon URL:", { error: e.message });
        faviconDetails.push(faviconDetail); // Still store for logging
      }
    }
  }
  
  // Detailed logging for favicon analysis
  logger.log("Favicon detection details:", {
    count: faviconElements.length,
    details: faviconDetails,
    qualityScore: faviconQualityScore,
    hasQualityFavicon
  });
  
  // Calculate the final impact based on both existence and quality
  let faviconImpact: number;
  
  if (!faviconExists) {
    // No favicon at all - very strong indicator of potential phishing
    faviconImpact = 0.45; // Increased from 0.25 to apply a much stronger penalty
  } else if (hasQualityFavicon) {
    // Quality favicon from same domain - strong indicator of legitimacy
    faviconImpact = -0.4;
  } else if (faviconQualityScore >= 2) {
    // Some quality indicators but not fully trusted - moderate indicator of legitimacy
    faviconImpact = -0.3;
  } else {
    // Basic favicon exists but low quality - weak indicator of legitimacy
    faviconImpact = -0.2;
  }
  
  features.push({
    name: "faviconExists",
    value: faviconExists, // Keep the boolean value for compatibility
    weight: 0.6, // Increased from 0.3 to make favicon a more significant factor
    impact: faviconImpact // Graduated impact based on favicon quality
  });
  
  // Add a second feature for the quality score for more granular analysis
  features.push({
    name: "faviconQuality",
    value: faviconQualityScore,
    weight: 0.4, // Slightly lower weight than existence
    impact: faviconQualityScore >= 2 ? -0.2 : 0.1 // Basic impact based on score
  });
  
  // Add debug information for favicon analysis
  logger.log("Favicon analysis:", {
    exists: faviconExists, 
    qualityScore: faviconQualityScore,
    hasQualityFavicon: hasQualityFavicon,
    calculatedImpact: faviconImpact,
    faviconCount: faviconElements.length,
    rootFaviconChecked: hasRootFavicon,
    notes: !faviconExists ? "Missing favicon: applying strong phishing penalty (0.45)" : 
           hasQualityFavicon ? "Quality favicon detected: strong benign signal" : 
           "Basic favicon detected"
  });
  
  // Update extension state if root favicon check resolves later
  checkForRootFavicon().then(result => {
    if (result && !faviconExists) {
      // We found a root favicon when initially we thought there was none
      logger.log("Root favicon found - updating scores");
      
      // Attempt to update the phishing detection state
      try {
        chrome.runtime.sendMessage({
          type: "UPDATE_FEATURE_STATE",
          data: {
            feature: "faviconExists",
            value: true,
            impact: -0.2 // Default impact for basic favicon (no need to change this as it's already found)
          }
        });
      } catch (e) {
        logger.log("Could not update favicon state dynamically", e);
      }
    }
  });
  
  // 6. Check if title matches domain using robust comparison with brand name detection
  // Ensure we have a title, use a fallback if not yet available
  const title = (document.title || window.location.hostname).toLowerCase();
  const hostname = window.location.hostname.toLowerCase();
  
  // Extract domain parts - handle both with and without www prefix
  const domainParts = hostname.split('.');
  let domainToCheck: string[] = [];
  
  // Enhanced domain part extraction to handle various scenarios
  // For example, for account.bbc.com we want to check:
  // - account (subdomain)
  // - bbc (main domain)
  // - bbc.com (main domain with TLD)
  // - account.bbc.com (full hostname)
  
  // Handle all possible parts of the domain
  if (domainParts.length > 2) {
    // Handle multi-part domains (subdomains or country codes)
    
    // Add the first part (usually subdomain)
    if (domainParts[0] !== 'www') {
      domainToCheck.push(domainParts[0]); 
    }
    
    // Add the second part (usually the main brand/domain name)
    // This is critical for cases like account.bbc.com where "bbc" is the brand
    domainToCheck.push(domainParts[domainParts.length - 2]);
    
    // Add the main domain with its TLD (e.g., bbc.com)
    domainToCheck.push(domainParts.slice(-2).join('.'));
    
    // If it's a subdomain, also check the full domain without www
    if (domainParts[0] !== 'www') {
      domainToCheck.push(hostname);
    } else {
      domainToCheck.push(domainParts.slice(1).join('.'));
    }
    
    // Special case for UK and similar domains (e.g., co.uk, org.uk)
    if (domainParts.length > 3 && ['co', 'org', 'gov', 'ac', 'net'].includes(domainParts[domainParts.length - 2])) {
      domainToCheck.push(domainParts[domainParts.length - 3]); // e.g., "example" from example.co.uk
      domainToCheck.push(domainParts.slice(-3).join('.')); // e.g., "example.co.uk"
    }
  } else if (domainParts.length === 2) {
    // Standard domain like example.com
    domainToCheck.push(domainParts[0]); // Just the domain name
    domainToCheck.push(hostname); // Full hostname
  } else {
    // Single-part domain (very rare)
    domainToCheck.push(hostname);
  }
  
  // Remove duplicates
  domainToCheck = [...new Set(domainToCheck)];
  
  // Special case for handling brands that might appear differently in titles
  // For example, "account.bbc.com" with title "BBC - Signin"
  const titleWords = title.split(/[\s\-_:.,;!?()[\]{}|\/\\'"]+/).filter(word => word.length > 0);
  
  // SIMPLIFIED TITLE MATCHING ALGORITHM
  // Simply compare domain and title with spaces removed
  const titleMatchesDomain = domainToCheck.some(domain => {
    // Skip very short domains (less than 3 chars) to avoid false positives
    if (domain.length < 3) return false;
    
    // Remove spaces and special characters from both title and domain
    const titleNoSpaces = title.replace(/[\s\-_:.,;!?()[\]{}|\/\\'"]+/g, '').toLowerCase();
    const domainNoSpaces = domain.replace(/[\s\-_:.,;!?()[\]{}|\/\\'"]+/g, '').toLowerCase();
    
    // Check if domain is a substring of the title
    if (titleNoSpaces.includes(domainNoSpaces)) {
      logger.log(`Domain match found: "${domain}" in title: "${title}" (simplified comparison)`);
      return true;
    }
    
    return false;
  });
  
  // Log title match results including key match data
  logger.log(`Title match result: ${titleMatchesDomain ? 'MATCHED' : 'NO MATCH'} for "${document.title || "(empty)"}" with domain ${hostname}`);
  
  // If title is empty or very short, mark this feature as inconclusive rather than penalizing
  // This prevents race conditions where title isn't loaded yet from affecting results
  const titleIsEmpty = !title || title.trim().length < 3;
  
  features.push({
    name: "titleMatchesDomain",
    value: titleMatchesDomain,
    weight: titleIsEmpty ? 0.1 : 0.7, // Reduce weight if title is empty/missing
    impact: titleIsEmpty ? 0 : (titleMatchesDomain ? -0.5 : 0.9) // No impact if title is missing
  });
  
  // Add additional feature to track if title was available
  features.push({
    name: "titleAvailable",
    value: !titleIsEmpty,
    weight: 0.1,
    impact: 0 // Just for diagnostic purposes
  });
  
  // Add specific information about the title match for debugging
  logger.log("Title match details:", {
    title: document.title,
    hostname: window.location.hostname,
    domainVariants: domainToCheck,
    matched: titleMatchesDomain
  });

  // If title is empty, set up a retry mechanism to check again after a short delay
  // This helps with race conditions where the title is set dynamically by JavaScript
  if (titleIsEmpty) {
    // Use a single, simpler retry after 1.5 seconds
    setTimeout(() => {
      try {
        const retryTitle = document.title?.toLowerCase() || '';
        
        // Only proceed if we have a title now
        if (retryTitle && retryTitle.length > 3) {
          // SIMPLIFIED RETRY TITLE MATCHING
          // Simply check if domain is part of title with spaces removed
          const retryTitleMatchesDomain = domainToCheck.some(domain => {
            if (domain.length < 3) return false;
            
            // Remove spaces and special characters from both title and domain
            const titleNoSpaces = retryTitle.replace(/[\s\-_:.,;!?()[\]{}|\/\\'"]+/g, '').toLowerCase();
            const domainNoSpaces = domain.replace(/[\s\-_:.,;!?()[\]{}|\/\\'"]+/g, '').toLowerCase();
            
            // Check if domain is a substring of the title
            return titleNoSpaces.includes(domainNoSpaces);
          });
          
          logger.log("Title available after retry:", {
            title: retryTitle,
            matches: retryTitleMatchesDomain
          });
          
          // Try to notify background script of updated feature
          try {
            chrome.runtime.sendMessage({
              type: "UPDATE_FEATURE_STATE",
              data: {
                feature: "titleMatchesDomain",
                value: retryTitleMatchesDomain,
                weight: 0.6,
                impact: retryTitleMatchesDomain ? -0.5 : 0.6,
                tabId: null // This will be filled in by the background script
              }
            });
          } catch (e) {
            // Silently fail, not critical
          }
        }
      } catch (error) {
        // Silent fail
      }
    }, 1500); // Wait a bit longer to ensure title is loaded
  }
  
  // 7. Check for fraud-related text in visible DOM elements
  // List of suspicious words that are strong indicators of phishing
  const suspiciousWords = [
    // Urgency terms
    'urgent', 'immediately', 'quick', 'hurry', 'limited time', 'expires', 'act now', 'deadline',
    // Security terms
    'verify', 'confirm', 'validate', 'secure', 'protect', 'alert', 'warning',
    // Account terms
    'account', 'password', 'login', 'credentials', 'profile', 'suspended', 'disabled', 'blocked', 'sign in',
    // Financial terms
    'pay', 'bank', 'debit', 'transfer', 'transaction', 'money', 'financial','revenue', 'profit', 'investment','donate',
    // Reward terms
    'free', 'prize', 'winner', 'reward', 'gift', 'bonus', 'discount', 'offer',
    // Crypto terms
    'crypto', 'bitcoin', 'eth','btc', 'wallet', 'blockchain', 'token', 'mining', 'coin',
    // Threat terms
    'suspicious', 'unauthorized', 'unusual', 'risk', 'compromised', 'threat', 'breach', 'violation',
    // Action terms
    'click', 'download', 'submit', 'provide'
  ];
  
  // Get all potential text elements from the DOM
  const textElements = document.querySelectorAll('p, h1, h2, h3, h4, h5, h6, span, div, label, a, button, td, th, li, dd, dt, figcaption, legend');
  let fraudTextScore = 0;
  const processedElements = new Set(); // Track elements we've counted
  
  // Track occurrences of each suspicious word across all elements
  const wordOccurrences: Record<string, number> = {};

  // First pass: Collect visible text content and count suspicious words
  textElements.forEach(element => {
    // Skip if already processed (for nested elements)
    if (processedElements.has(element)) return;
    
    // Skip if the element is not visible to the user
    if (!isElementVisible(element)) {
      return;
    }
    
    // Process all child text nodes to get only visible text content
    let visibleText = '';
    const textWalker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT, {
      acceptNode: function(node) {
        // Skip text nodes that are in non-visible elements
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;
        
        // Skip hidden elements
        if (!isElementVisible(parent)) return NodeFilter.FILTER_REJECT;
        
        // Skip script, style, noscript, and other non-content tags
        const tagName = parent.tagName || '';
        if (['SCRIPT', 'STYLE', 'NOSCRIPT', 'CODE', 'PRE', 'TEMPLATE', 'IFRAME', 'META', 'LINK'].includes(tagName)) {
          return NodeFilter.FILTER_REJECT;
        }
        
        // Accept this node
        return NodeFilter.FILTER_ACCEPT;
      }
    } as NodeFilter);
    
    let textNode;
    
    while ((textNode = textWalker.nextNode()) !== null) {
      // Get the text and normalize it (remove extra whitespace)
      const nodeText = textNode.nodeValue || '';
      
      // Add a space between text nodes for proper word separation
      if (nodeText.trim() && visibleText) {
        visibleText += ' ';
      }
      
      visibleText += nodeText;
    }
    
    // Skip if the processed visible text is too short
    visibleText = visibleText.toLowerCase().trim();
    if (!visibleText || visibleText.length < 5) return;
    
    processedElements.add(element);
    
    // Count suspicious words in this element
    let elementSuspiciousWordCount = 0;
    const elementWordOccurrences: Record<string, number> = {};
    
    for (const suspiciousTerm of suspiciousWords) {
      let occurrences = 0;
      let searchIndex = 0;
      
      // Find all occurrences of this term in the visible text
      while (true) {
        const foundIndex = visibleText.indexOf(suspiciousTerm, searchIndex);
        if (foundIndex === -1) break;
        
        // Check if it's a whole word or part of a larger word
        const beforeChar = foundIndex === 0 ? ' ' : visibleText[foundIndex - 1];
        const afterChar = foundIndex + suspiciousTerm.length >= visibleText.length ? 
          ' ' : visibleText[foundIndex + suspiciousTerm.length];
        
        // Count it if it's a phrase (contains space) or it's a whole word
        // This helps avoid counting 'crypto' in 'cryptocurrency' twice
        if (suspiciousTerm.includes(' ') || 
            (!(/[a-z0-9]/.test(beforeChar)) && !(/[a-z0-9]/.test(afterChar)))) {
          occurrences++;
        }
        
        // Move search position forward
        searchIndex = foundIndex + suspiciousTerm.length;
      }
      
      if (occurrences > 0) {
        elementSuspiciousWordCount += occurrences;
        elementWordOccurrences[suspiciousTerm] = occurrences;
        
        // Add to global counts
        if (!wordOccurrences[suspiciousTerm]) {
          wordOccurrences[suspiciousTerm] = occurrences;
        } else {
          wordOccurrences[suspiciousTerm] += occurrences;
        }
      }
    }
    
    // Calculate score for this element - higher score for concentrated occurrences
    let elementScore = 0;
    
    if (elementSuspiciousWordCount >= 1) {
      // Base score is higher for elements with suspicious terms
      elementScore += 2;
      
      // Add points for each suspicious word (more words = higher score)
      elementScore += Math.min(10, Object.keys(elementWordOccurrences).length * 1.5);
      
      // Add points for repetition of suspicious words
      elementScore += Math.min(15, elementSuspiciousWordCount * 2);
      
      // Boost score if the element has multiple different suspicious words
      // This helps identify patterns like "Confirm your account immediately" which has multiple triggers
      if (Object.keys(elementWordOccurrences).length >= 3) {
        elementScore *= 1.8;  // Big multiplier for multiple different terms
      } else if (Object.keys(elementWordOccurrences).length >= 2) {
        elementScore *= 1.4;  // Smaller multiplier for two different terms
      }
      
      // Higher weight for elements with headline tags
      if (['H1', 'H2', 'H3'].includes(element.tagName)) {
        elementScore *= 2;
      }
    }
    
    fraudTextScore += elementScore;
  });
  
  // Add page-level bonuses based on total suspicious word counts
  const totalSuspiciousWordCount = Object.values(wordOccurrences).reduce((sum, count) => sum + count, 0);
  const uniqueSuspiciousWordCount = Object.keys(wordOccurrences).length;
  
  // Bonus for total number of suspicious words across the page
  if (totalSuspiciousWordCount >= 15) {
    fraudTextScore += 15;
  } else if (totalSuspiciousWordCount >= 10) {
    fraudTextScore += 10;
  } else if (totalSuspiciousWordCount >= 5) {
    fraudTextScore += 5;
  }
  
  // Bonus for diversity of suspicious words
  if (uniqueSuspiciousWordCount >= 8) {
    fraudTextScore *= 1.5; // Big multiplier for many different types of suspicious words
  } else if (uniqueSuspiciousWordCount >= 5) {
    fraudTextScore *= 1.3; // Medium multiplier
  } else if (uniqueSuspiciousWordCount >= 3) {
    fraudTextScore *= 1.1; // Small multiplier
  }

  // Get the top suspicious words for display
  const topSuspiciousWords = Object.entries(wordOccurrences)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([word, count]) => ({ word, count }));
  
  // Log detailed information about detected suspicious words
  logger.log("--- Suspicious Text Detection Results ---");
  logger.log("Total fraudTextScore:", fraudTextScore.toFixed(2));
  logger.log("Total suspicious word count:", totalSuspiciousWordCount);
  logger.log("Unique suspicious word count:", uniqueSuspiciousWordCount);
  logger.log("Top suspicious words:", topSuspiciousWords);
  logger.log("All detected words:", wordOccurrences);
  
  // Log visibility statistics for debugging
  const totalElements = textElements.length;
  const processedVisibleElements = processedElements.size;
  logger.log("Text visibility statistics:", {
    totalTextElementsFound: totalElements,
    visibleElementsProcessed: processedVisibleElements,
    hiddenElementsSkipped: totalElements - processedVisibleElements,
    visibilityRatio: (processedVisibleElements / totalElements).toFixed(2)
  });
  
  // Store the data in localStorage for persistence and send via message
  try {
    // Create visibility debug information
    const visibilityDebugInfo = {
      totalTextElements: textElements.length,
      visibleElements: processedElements.size,
      hiddenElements: textElements.length - processedElements.size,
      visibilityRatio: processedElements.size / textElements.length
    };
    
    // Create a data object with all the suspicious words data
    const suspiciousWordsData = {
      timestamp: Date.now(),
      url: window.location.href,
      fraudTextScore,
      calculatedImpact: 0, // Will be updated after impact calculation
      suspiciousWordCounts: {
        total: totalSuspiciousWordCount,
        unique: uniqueSuspiciousWordCount
      },
      topSuspiciousWords,
      allDetectedWords: wordOccurrences,
      visibilityDebugInfo
    };
    
    // Store in localStorage for persistence between refreshes/reopens
    localStorage.setItem('phishing_detector_suspicious_words', JSON.stringify(suspiciousWordsData));
    
    // Only send message if this is the first time or if explicitly requested
    // This prevents flooding the console with messages
    const shouldSendMessage = !localStorage.getItem('phishing_detector_suspicious_words_sent') || 
                              localStorage.getItem('phishing_detector_suspicious_words_refresh_requested');
    
    if (shouldSendMessage) {
      // Set flag to avoid repeated messages
      localStorage.setItem('phishing_detector_suspicious_words_sent', 'true');
      // Clear any refresh request
      localStorage.removeItem('phishing_detector_suspicious_words_refresh_requested');
      
      // Send message using the centralized utility
      updateAndSendSuspiciousWordsData(suspiciousWordsData, true);
    }    } catch (e) {
      // Might fail if not running in extension context
      logger.error("Failed to send suspicious words data:", e);
    }
  
  // Calculate impact with logarithmic scaling for very high scores
  // This allows differentiation between moderate (6) and extreme (150) scores
  // while maintaining a reasonable maximum impact
  let calculatedImpact: number;
  
  if (fraudTextScore <= 0) {
    calculatedImpact = -0.05; // Very benign - no suspicious words at all
  } else if (fraudTextScore <= 2) {
    calculatedImpact = -0.1; // Minimal suspicious words - likely benign
  } else if (fraudTextScore <= 4) {
    calculatedImpact = -0.15; // Few suspicious words - probably benign
  } else if (fraudTextScore <= 5) {
    calculatedImpact = -0.2; // Some suspicious words but still under threshold
  } else if (fraudTextScore <= 8) {
    calculatedImpact = 0.3; // Moderate impact starts at higher threshold
  } else if (fraudTextScore <= 10) {
    calculatedImpact = 0.5; // Medium impact
  } else if (fraudTextScore <= 17) {
    calculatedImpact = 0.7; // High impact
  } else {
    // Custom scaling function for better differentiation between high scores:
    // - Score of 20 gives 0.7 (base)
    // - Score of 25 gives ~0.78
    // - Score of 35 gives ~0.87
    // - Score of 60 gives ~0.93
    // - Score of 140+ gives ~0.97
    // This creates a significant difference while staying under cap
    calculatedImpact = 0.7 + (0.27 * (1 - Math.exp(-0.03 * (fraudTextScore - 20))));
  }
  
  // Update the stored suspicious words data with the calculated impact
  try {
    const storedData = localStorage.getItem('phishing_detector_suspicious_words');
    if (storedData) {
      const suspiciousWordsData = JSON.parse(storedData);
      suspiciousWordsData.calculatedImpact = calculatedImpact;
      localStorage.setItem('phishing_detector_suspicious_words', JSON.stringify(suspiciousWordsData));
      
      // Only send update if there's a significant change to impact or if explicitly requested
      const previousImpact = parseFloat(localStorage.getItem('phishing_detector_last_impact') || '0');
      const impactDifference = Math.abs(calculatedImpact - previousImpact);
      const refreshRequested = localStorage.getItem('phishing_detector_suspicious_words_refresh_requested');
      
      if (impactDifference > 0.1 || refreshRequested) {
        // Update impact using centralized utility
        updateSuspiciousWordsImpact(calculatedImpact);
      }
    }
  } catch (e) {
    logger.error("Failed to update suspicious words data with impact:", e);
  }
  
  // Add a meta tag with the fraudTextScore feature impact to the DOM
  // This will allow the popup to access the impact value directly if needed
  try {
    let metaTag = document.querySelector('meta[name="phishing-detector-feature-fraudTextScore"]');
    if (!metaTag) {
      metaTag = document.createElement('meta');
      metaTag.setAttribute('name', 'phishing-detector-feature-fraudTextScore');
      document.head.appendChild(metaTag);
    }
    metaTag.setAttribute('content', calculatedImpact.toString());
  } catch (e) {
    logger.error("Failed to add meta tag for fraudTextScore:", e);
  }
  
  features.push({
    name: "fraudTextScore",
    value: fraudTextScore,
    weight: 0.7, // High weight as this is a strong indicator
    impact: calculatedImpact // Logarithmically scaled impact for high scores
  });
  
  // New feature: Detect large image dominance in page (common phishing technique)
  const detectLargeImageDominance = (): { dominated: boolean, coverage: number, largeImagesCount: number, viewportImages: Array<{element: HTMLImageElement, area: number, coverage: number}> } => {
    // Get the viewport dimensions
    const viewportWidth = window.innerWidth || document.documentElement.clientWidth;
    const viewportHeight = window.innerHeight || document.documentElement.clientHeight;
    const viewportArea = viewportWidth * viewportHeight;
    
    // Find all images in the viewport
    const allImages = document.querySelectorAll('img');
    const viewportImages: Array<{element: HTMLImageElement, area: number, coverage: number}> = [];
    
    // Calculate the total image area and individual image sizes
    let totalImageArea = 0;
    let largeImagesCount = 0;
    
    allImages.forEach(img => {
      const imgElement = img as HTMLImageElement;
      
      // Skip images that aren't loaded or have no dimensions
      if (!imgElement.complete || !imgElement.naturalWidth || !imgElement.naturalHeight) {
        return;
      }
      
      // Get the rendered size of the image
      const rect = imgElement.getBoundingClientRect();
      
      // Skip if image is not in viewport
      if (rect.right <= 0 || rect.bottom <= 0 || 
          rect.left >= viewportWidth || rect.top >= viewportHeight) {
        return;
      }
      
      // Calculate the visible area within the viewport
      const visibleLeft = Math.max(0, rect.left);
      const visibleRight = Math.min(viewportWidth, rect.right);
      const visibleTop = Math.max(0, rect.top);
      const visibleBottom = Math.min(viewportHeight, rect.bottom);
      
      const visibleWidth = visibleRight - visibleLeft;
      const visibleHeight = visibleBottom - visibleTop;
      const visibleArea = visibleWidth * visibleHeight;
      
      // Calculate what percentage of the viewport this image covers
      const coveragePercent = (visibleArea / viewportArea) * 100;
      
      // Track images that cover a significant portion of the viewport
      if (coveragePercent >= 30) {
        largeImagesCount++;
      }
      
      totalImageArea += visibleArea;
      
      viewportImages.push({
        element: imgElement,
        area: visibleArea,
        coverage: coveragePercent
      });
    });
    
    // Calculate the total percentage of viewport covered by images
    const totalCoveragePercent = (totalImageArea / viewportArea) * 100;
    
    // Sort images by area (largest first) for analysis
    viewportImages.sort((a, b) => b.area - a.area);
    
    // Determine if the page is dominated by large images
    // This is a common phishing technique where a legitimate site's UI is
    // replicated as a single large image with a login form overlaid
    
    // Strong indicators:
    // 1. One very large image covering >60% of viewport
    // 2. 2-3 large images covering >75% of viewport combined
    // 3. Total image coverage >85% with at least one large image
    
    const isDominated = 
      (viewportImages.length > 0 && viewportImages[0].coverage > 60) || 
      (viewportImages.length >= 2 && totalCoveragePercent > 75 && largeImagesCount >= 2) ||
      (totalCoveragePercent > 85 && largeImagesCount >= 1);
    
    // Log details for debugging
    logger.log("Large image analysis:", {
      viewportArea,
      totalCoveragePercent: totalCoveragePercent.toFixed(2) + "%",
      largeImagesCount,
      isDominated,
      largestImages: viewportImages.slice(0, 3).map(img => ({
        src: img.element.src.substring(0, 100) + (img.element.src.length > 100 ? '...' : ''),
        coverage: img.coverage.toFixed(2) + "%",
        width: img.element.width,
        height: img.element.height
      }))
    });
    
    return {
      dominated: isDominated,
      coverage: totalCoveragePercent,
      largeImagesCount,
      viewportImages
    };
  };
  
  // Run the large image dominance detection
  const imageDominanceResult = detectLargeImageDominance();
  
  // Calculate impact based on severity
  let imageDominanceImpact = 0;
  
  if (imageDominanceResult.dominated) {
    // Strong phishing signal - scale based on coverage
    if (imageDominanceResult.coverage > 90) {
      imageDominanceImpact = 0.8; // Extremely strong signal - almost entire page is images
    } else if (imageDominanceResult.coverage > 80) {
      imageDominanceImpact = 0.7; // Very strong signal
    } else {
      imageDominanceImpact = 0.5; // Moderate signal
    }
  } else if (imageDominanceResult.largeImagesCount > 0) {
    // Some large images but not dominating
    imageDominanceImpact = imageDominanceResult.largeImagesCount * 0.05;
  } else {
    // No large images - slightly reduces phishing likelihood
    imageDominanceImpact = -0.1;
  }
  
  // Add more detailed information as a separate feature - focusing on single large image dominance
  // Check for single image dominance (a strong phishing signal when one large image takes over the page)
  const hasSingleLargeImage = imageDominanceResult.viewportImages && 
                              imageDominanceResult.viewportImages.length === 1 && 
                              imageDominanceResult.viewportImages[0].coverage >= 40;
  
  const singleImageCoverage = hasSingleLargeImage ? imageDominanceResult.viewportImages[0].coverage : 0;
  
  logger.log("Single image dominance analysis:", {
    hasSingleLargeImage,
    singleImageCoverage: hasSingleLargeImage ? singleImageCoverage.toFixed(2) + "%" : "N/A",
    image: hasSingleLargeImage ? imageDominanceResult.viewportImages[0].element.src : "N/A"
  });
  
  features.push({
    name: "imageCoverage",
    value: hasSingleLargeImage && singleImageCoverage >= 40,
    weight: 0.9,
    impact: hasSingleLargeImage && singleImageCoverage >= 50 ? 0.95 : 
            hasSingleLargeImage && singleImageCoverage >= 40 ? 0.6 : 0
  });
  
  // 18. Check for lack of navigation structure
  // Legitimate sites typically have navigation menus and internal links
  // Phishing sites often lack proper navigation structure
  const navigationLinks = [...document.querySelectorAll("a")]
    .filter(a => {
      const href = a.getAttribute("href");
      // Consider navigation links those that:
      // 1. Are internal page links (#)
      // 2. Are relative links to other pages 
      // 3. Link to the same domain
      if (!href) return false;
      
      if (href.startsWith("#")) return true;
      if (!href.includes("://") && !href.startsWith("mailto:") && !href.startsWith("tel:")) return true;
      
      try {
        const url = new URL(href, window.location.href);
        return url.hostname === window.location.hostname;
      } catch {
        return false;
      }
    }).length;
  const noNavigationLinks = navigationLinks === 0;
  const noMenus = document.querySelectorAll("ul, ol, nav").length === 0;
  const hasNoNavStructure = noNavigationLinks && noMenus;
  
  console.log("Navigation structure analysis:", {
    noNavigationLinks,
    noMenus,
    hasNoNavStructure
  });
  
  features.push({
    name: "hasNoNavStructure",
    value: hasNoNavStructure,
    weight: 0.7,
    impact: hasNoNavStructure ? 0.7 : -0.2
  });
  
  // 19. Check for suspicious fake clickable elements
  // Phishing pages often use div/span elements with click handlers instead of proper buttons/links
  const clickableDivs = [...document.querySelectorAll("div, span")]
    .filter(el => {
      return el.hasAttribute("onclick") || 
             el.getAttribute("role") === "button" || 
             (el as HTMLElement).onclick !== null || 
             (el as HTMLElement).style.cursor === "pointer";
    });
  const suspiciousFakeClickables = clickableDivs.length > 5;
  
  console.log("Suspicious clickable elements analysis:", {
    clickableDivsCount: clickableDivs.length,
    suspiciousFakeClickables,
    examples: clickableDivs.slice(0, 3).map(el => ({
      tagName: el.tagName,
      text: el.textContent?.substring(0, 50),
      hasOnClick: el.hasAttribute("onclick"),
      role: el.getAttribute("role"),
      cursor: (el as HTMLElement).style.cursor
    }))
  });
  
  features.push({
    name: "suspiciousFakeClickables",
    value: suspiciousFakeClickables,
    weight: 0.8,
    impact: suspiciousFakeClickables ? 0.8 : -0.01
  });

  // 20. Detect suspicious fonts
  // Phishing sites often use uncommon or system fonts to mimic legitimate sites
  // We specifically look for fonts that are commonly used by phishing sites
  // but rarely used by legitimate websites
  // Only include extremely rare fonts that legitimate sites would never use
  // but are sometimes found in phishing attempts
  const safeFonts = ["roboto", "open sans", "arial", "helvetica", "lato", "system-ui", "sans-serif"];

  const usedFonts = new Set<string>();
  [...document.querySelectorAll("body *")].forEach(el => {
    const font = getComputedStyle(el).fontFamily.toLowerCase();
    usedFonts.add(font);
  });

  const usesSuspiciousFonts = [...usedFonts].some(font =>
    !safeFonts.some(safe => font.includes(safe))
  );
  
  // Simplified binary impact when suspicious fonts found
  const suspiciousFontsImpact = usesSuspiciousFonts ? 0.6 : -0.5;
  
  features.push({
    name: "hasSuspiciousFonts",
    value: usesSuspiciousFonts,
    weight: 0.8,  // Using weight of 0.8 as specified
    impact: suspiciousFontsImpact
  });
}