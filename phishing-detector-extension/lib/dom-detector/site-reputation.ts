// Site reputation and trust scoring
// This file provides utilities for determining a site's reputation
// without hardcoding specific domains

import { CONFIG } from './constants';
import { domLogger as logger } from "../logger"

/**
 * Score a site's reputation based on various indicators
 * Returns a score from 0 (suspicious) to 1 (highly trusted)
 */
export function scoreWebsiteReputation(): number {
  // Start with a neutral score
  let score = 0.5;
  
  // Check for HTTPS (basic security)
  if (window.location.protocol === 'https:') {
    score += 0.1;
  } else {
    score -= 0.3; // HTTP is a significant negative
  }
  
  // Look for common indicators of legitimate sites
  
  // Check for security badges/seals
  const securityBadges = document.querySelectorAll(
    '.secure-badge, .ssl-badge, .trust-badge, .verified-seal, ' +
    '.security-verified, .secure-checkout, .secure-payment, ' +
    '[class*="secure"], [class*="verified"], [class*="trusted"]'
  );
  if (securityBadges.length > 0) {
    score += 0.1;
  }
  
  // Check for legitimate site structure elements
  const hasFooterLinks = document.querySelectorAll(
    'footer a[href*="privacy"], footer a[href*="terms"], ' +
    'footer a[href*="about"], footer a[href*="contact"]'
  ).length > 0;
  
  if (hasFooterLinks) {
    score += 0.1;
  }
  
  // Check for contact information
  const hasContactInfo = document.querySelectorAll(
    '[href^="tel:"], [href^="mailto:"], address, ' +
    '.contact-info, .contact-details, .phone-number'
  ).length > 0;
  
  if (hasContactInfo) {
    score += 0.05;
  }
  
  // Check for proper login/account management structure
  const hasAccountSection = document.querySelectorAll(
    'header [href*="account"], nav [href*="account"], ' +
    'header [href*="profile"], nav [href*="profile"], ' +
    '.user-account, .account-menu, .user-profile'
  ).length > 0;
  
  if (hasAccountSection) {
    score += 0.1;
  }
  
  // Content quality checks
  const hasRichContent = document.querySelectorAll('article, section, .content, .main-content').length > 3;
  if (hasRichContent) {
    score += 0.05;
  }
  
  // Advanced checks that could be added:
  // - Domain age (via API)
  // - SSL certificate details
  // - External reputation database lookups
  // - History of user interactions with the site
  
  // Ensure score stays within 0-1 range
  return Math.max(0, Math.min(1, score));
}

/**
 * Determine if a site has a good enough reputation to be trusted
 * for financial or personal data collection
 */
export function hasTrustedReputation(): boolean {
  const score = scoreWebsiteReputation();
  // Use the configurable threshold
  return score > CONFIG.reputation.trustThreshold;
}

/**
 * Enhanced check that evaluates context for a specific form
 * to determine if it's likely legitimate
 */
export function isLikelyLegitimateForm(formElement: HTMLFormElement): boolean {
  // Check if the form has proper structure
  const hasLabels = formElement.querySelectorAll('label').length > 0;
  const hasSubmitButton = !!formElement.querySelector('button[type="submit"], input[type="submit"]');
  
  // Check for suspicious form attributes
  const action = formElement.getAttribute('action') || '';
  const method = formElement.getAttribute('method') || '';
  
  const hasProperAction = action && action !== '#' && !action.includes('javascript:');
  const hasProperMethod = method && (method.toLowerCase() === 'post' || method.toLowerCase() === 'get');
  
  // Check for proper error handling (legitimate forms often have this)
  const hasErrorHandling = !!formElement.querySelector('.error, .form-error, .help-block, .form-text');
  
  // Check if form is within a legitimate-looking page section
  const isInMainContent = !!formElement.closest('main, .main, .content, .container, article');
  
  // Combined score
  const formScore = [
    hasLabels,
    hasSubmitButton,
    hasProperAction,
    hasProperMethod,
    hasErrorHandling,
    isInMainContent
  ].filter(Boolean).length;
  
  // Form needs to meet at least 4 of the 6 criteria
  return formScore >= 4;
}
