// Security features extraction for DOM detector
import type { DomFeature } from "./types"
import { domLogger as logger } from "../logger"

// Extract security-related features
export function extractSecurityFeatures(features: DomFeature[]): void {
  // 1. Enhanced SSL/TLS security assessment
  const pageText = document.body.innerText.toLowerCase();
  
  // Check for basic SSL warning indicators in page text
  const sslTextWarnings = pageText.includes('ssl error') || 
                        pageText.includes('certificate error') || 
                        pageText.includes('security warning') ||
                        pageText.includes('connection not secure') ||
                        pageText.includes('connection isn\'t secure') ||
                        pageText.includes('certificate expired') ||
                        pageText.includes('certificate not valid') ||
                        pageText.includes('certificate warning') ||
                        pageText.includes('privacy warning') ||
                        pageText.includes('your connection is not private') ||
                        pageText.includes('invalid certificate') ||
                        pageText.includes('unsafe connection');

  // Detect URL mismatches that could indicate SSL spoofing
  const currentProtocol = window.location.protocol;
  const currentHostname = window.location.hostname;
  let protocolMismatch = false;
  let certificateHostnameMismatch = false;
  
  // Check for SSL usage on phishing-prone protocols
  const isInsecureProtocol = currentProtocol !== 'https:';
  
  // Get current URL indicators for potential mismatches
  const hasSecureWords = currentHostname.includes('secure') || 
                        currentHostname.includes('ssl') || 
                        currentHostname.includes('safety') || 
                        currentHostname.includes('safe');
                        
  // Check if we have a secure-themed domain but using insecure protocol
  protocolMismatch = hasSecureWords && isInsecureProtocol;
  
  // Look for signs of deceptive TLS presentation
  const sslSpoofingIndicators = document.querySelectorAll('img[src*="lock"], img[src*="ssl"], img[src*="secure"], .lock, .ssl-icon');
  const hasSslSpoofingElements = sslSpoofingIndicators.length > 0 && isInsecureProtocol;
  
  // Check for links claiming to be secure but aren't
  const securityClaimLinks = Array.from(document.querySelectorAll('a'))
    .filter(link => {
      const linkText = (link.textContent || '').toLowerCase();
      return (linkText.includes('secure') || 
              linkText.includes('safe') || 
              linkText.includes('protected') ||
              linkText.includes('verified')) &&
              link.href && link.href.startsWith('http:');
    });
  
  const hasDeceptiveSecurityClaims = securityClaimLinks.length > 0;

  // Detect HTTPS downgrade attempts
  const mixedContentWarning = document.querySelectorAll('form[action^="http:"]').length > 0 && currentProtocol === 'https:';
  
  // Common financial/sensitive domains that might be impersonated
  const sensitiveDomainsPatterns = [
    'paypal', 'bank', 'apple', 'google', 'microsoft', 'amazon', 'facebook',
    'instagram', 'netflix', 'credit', 'chase', 'wellsfargo', 'citibank', 
    'capitalone', 'amex', 'americanexpress', 'bankofamerica', 'tdbank',
    'schwab', 'vanguard', 'fidelity', 'coinbase', 'binance', 'twitter',
    'linkedin', 'dropbox', 'icloud', 'gmail', 'outlook', 'office365'
  ];
  
  // Check if the URL looks like it's impersonating a sensitive domain
  const domainNameOnly = currentHostname.replace(/^www\./, '').split('.')[0].toLowerCase();
  const potentialDomainSpoofing = sensitiveDomainsPatterns.some(pattern => {
    // Check for typosquatting or domain impersonation patterns
    return (domainNameOnly.includes(pattern) && !domainNameOnly.endsWith(pattern)) || 
           (domainNameOnly !== pattern && domainNameOnly.includes(pattern) && 
            (domainNameOnly.includes('-') || domainNameOnly.includes('_') || /\d/.test(domainNameOnly)));
  });
  
  // Combined SSL security assessment
  const hasSslWarnings = sslTextWarnings || 
                         protocolMismatch || 
                         certificateHostnameMismatch || 
                         hasSslSpoofingElements || 
                         hasDeceptiveSecurityClaims || 
                         mixedContentWarning ||
                         (potentialDomainSpoofing && isInsecureProtocol);

  // Calculate impact score based on severity of issues
  let sslWarningImpact = -0.2; // Default benign score
  
  if (hasSslWarnings) {
    // Start with base impact for any warning
    sslWarningImpact = 0.3;
    
    // Add impact for more severe issues
    if (sslTextWarnings) sslWarningImpact += 0.1;
    if (protocolMismatch) sslWarningImpact += 0.15;
    if (hasSslSpoofingElements) sslWarningImpact += 0.2;
    if (hasDeceptiveSecurityClaims) sslWarningImpact += 0.15;
    if (mixedContentWarning) sslWarningImpact += 0.1;
    if (potentialDomainSpoofing && isInsecureProtocol) sslWarningImpact += 0.25;
    
    // Cap at 0.9 for worst cases
    sslWarningImpact = Math.min(0.9, sslWarningImpact);
  }

  // Track SSL security details for reporting
  try {
    const sslSecurityDetails = {
      hasSslWarnings,
      isInsecureProtocol,
      sslTextWarnings,
      protocolMismatch,
      hasSslSpoofingElements,
      securityClaimLinks: securityClaimLinks.length,
      hasDeceptiveSecurityClaims,
      mixedContentWarning,
      potentialDomainSpoofing,
      impact: sslWarningImpact
    };
    
    // Store for potential access in popup
    localStorage.setItem('phishing_detector_ssl_details', JSON.stringify(sslSecurityDetails));
    
    // Send to background script for analysis
    chrome.runtime.sendMessage({
      type: "SSL_SECURITY_DETAILS",
      data: sslSecurityDetails
    }).catch(e => {
      // Ignore errors from sending message
      logger.debug("Could not send SSL details message", e);
    });
  } catch (e) {
    // Ignore errors with message sending
  }
  
  // 2. Check for masked links (href doesn't match displayed text)
  const links = document.querySelectorAll('a');
  const maskedLinksCount = Array.from(links).filter(link => {
    const href = link.getAttribute('href') || '';
    const displayText = link.textContent || '';
    
    return href.includes('://') && 
           displayText.includes('://') && 
           !displayText.includes(new URL(link.href).hostname);
  }).length;
  
  features.push({
    name: "maskedLinks",
    value: maskedLinksCount > 0,
    weight: 0.8,
    impact: maskedLinksCount > 0 ? 0.7 : -0.1
  });
  
  // 3. Check for suspicious redirects
  const hasSuspiciousRedirects = !!document.querySelector('meta[http-equiv="refresh"]');
  
  features.push({
    name: "suspiciousRedirects",
    value: hasSuspiciousRedirects,
    weight: 0.6,
    impact: hasSuspiciousRedirects ? 0.5 : -0.1
  });
}
