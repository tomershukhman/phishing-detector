// Invisible element detection features for phishing identification
import type { DomFeature } from "./types";
import { domLogger as logger } from "../logger";

/**
 * Extracts features related to invisible elements that may indicate phishing
 * 
 * Focusing on specifically suspicious patterns that don't appear on legitimate sites:
 * 1. Invisible password fields or credential inputs
 * 2. Overlapping stacked inputs that "trick" users
 * 3. Transparent clickable overlays with suspicious attributes
 */
export function extractInvisibleFeatures(features: DomFeature[]): void {
  // 1. Detect suspicious invisible credential inputs (strong phishing indicator)
  // More targeted than just any invisible input
  const suspiciousInvisibleCredentialInputs = detectSuspiciousInvisibleCredentialInputs();
  features.push({
    name: "hasSuspiciousInvisibleCredentialInputs",
    value: suspiciousInvisibleCredentialInputs > 0,
    weight: 0.9, // Very high weight as this is a strong signal
    impact: suspiciousInvisibleCredentialInputs > 0 ? 0.85 : -0.1 // Less negative impact if not found
  });
  
  // 2. Detect input field traps - overlapping fields that can trick users
  const overlappingInputTraps = detectOverlappingInputTraps();
  features.push({
    name: "hasOverlappingInputTraps",
    value: overlappingInputTraps,
    weight: 0.9,
    impact: overlappingInputTraps ? 0.8 : -0.1
  });

  // 3. Detect transparent overlays with suspicious properties
  const suspiciousTransparentOverlays = detectSuspiciousTransparentOverlays();
  features.push({
    name: "hasSuspiciousTransparentOverlays",
    value: suspiciousTransparentOverlays > 0,
    weight: 0.85,
    impact: calculateOverlayImpact(suspiciousTransparentOverlays)
  });
  
  // 4. New feature: Smart hidden input analysis
  // This is more specific than the credential inputs check
  // It analyzes the ratio of suspicious vs legitimate hidden inputs 
  const hiddenInputAnalysis = analyzeHiddenInputs();
  
  features.push({
    name: "hiddenInputsSuspiciousRatio",
    value: hiddenInputAnalysis.suspiciousRatio,
    weight: 0.7,
    impact: calculateHiddenInputImpact(hiddenInputAnalysis)
  });
}

/**
 * Detects invisible input fields specifically for credentials (password, email, etc.)
 * and filters out legitimate uses of hidden inputs like CSRF tokens
 * Enhanced to be smarter about legitimate hidden inputs used by sites like PayPal
 */
function detectSuspiciousInvisibleCredentialInputs(): number {
  let count = 0;
  const inputs = document.querySelectorAll('input');
  
  // First, identify credential-related inputs - only focus on these
  const loginRelatedInputs = Array.from(inputs).filter(input => {
    const type = input.getAttribute('type')?.toLowerCase() || '';
    const name = input.getAttribute('name')?.toLowerCase() || '';
    const id = input.getAttribute('id')?.toLowerCase() || '';
    const placeholder = input.getAttribute('placeholder')?.toLowerCase() || '';
    const autocomplete = input.getAttribute('autocomplete')?.toLowerCase() || '';
    
    // Only track inputs that appear to be collecting truly sensitive credential information
    const isCredentialInput = (
      // Password fields are clearly credential-related
      type === 'password' || 
      
      // Email fields only when they appear to be for login purposes
      (type === 'email' && (
        name.includes('login') ||
        id.includes('login') ||
        autocomplete === 'username' ||
        name === 'email' ||
        id === 'email'
      )) ||
      
      // Text fields explicitly for passwords or usernames
      (type === 'text' && (
        name.includes('pass') ||
        id.includes('pass') ||
        placeholder.includes('password') ||
        autocomplete === 'current-password' ||
        autocomplete === 'new-password' ||
        
        // Username fields that are clearly for authentication
        (name.includes('user') && name.includes('name')) ||
        (id.includes('user') && id.includes('name')) ||
        placeholder.includes('username') ||
        autocomplete === 'username'
      ))
    );
    
    return isCredentialInput;
  });
  
  loginRelatedInputs.forEach(input => {
    const style = window.getComputedStyle(input);
    const rect = input.getBoundingClientRect();
    
    // Check for invisibility techniques
    const isInvisible = (
      // Zero opacity password field is highly suspicious
      (style.opacity === '0' && input.type === 'password') ||
      
      // Hidden visibility when not part of a toggle UI pattern
      (style.visibility === 'hidden' && !isHiddenByToggle(input)) ||
      
      // Extremely small size that renders input unusable
      (parseInt(style.width, 10) <= 1 && parseInt(style.height, 10) <= 1) ||
      (rect.width <= 1 && rect.height <= 1) ||
      
      // Off-screen positioning when not part of legitimate dynamic UI
      // Be more careful with thresholds to avoid false positives
      (rect.top < -150 && !isInDynamicUI(input)) || 
      (rect.left < -150 && !isInDynamicUI(input))
    );
    
    // Don't count if this is a legitimate hidden input (e.g. CSRF token)
    // This function has been enhanced to recognize legitimate patterns in major websites
    const isSuspicious = isInvisible && !isLegitimateHiddenInput(input);
    
    // Add extra check: is this invisible input not visibly labeled?
    // This helps identify truly deceptive fields vs. legitimate design patterns
    let hasVisibleLabel = false;
    
    // Check if the input has an associated label
    const inputId = input.getAttribute('id');
    if (inputId) {
      const associatedLabel = document.querySelector(`label[for="${inputId}"]`);
      if (associatedLabel) {
        const labelStyle = window.getComputedStyle(associatedLabel);
        // Check if the label is visible
        hasVisibleLabel = 
          labelStyle.display !== 'none' && 
          labelStyle.visibility !== 'hidden' && 
          parseFloat(labelStyle.opacity) > 0.2;
      }
    }
    
    // For invisible credential fields, it's suspicious only if they also lack visible labels
    // This helps avoid false positives for legitimate UX patterns
    if (isSuspicious && !hasVisibleLabel) {
      count++;
    }
  });
  
  return count;
}

/**
 * Detects overlapping input traps - a technique where visible input fields
 * are overlaid with invisible ones to capture credentials
 */
function detectOverlappingInputTraps(): boolean {
  const inputFields = document.querySelectorAll('input[type="password"], input[type="email"], input[type="text"]');
  const inputRects = Array.from(inputFields).map(input => {
    return {
      element: input,
      rect: input.getBoundingClientRect()
    };
  });
  
  // Check for overlapping input fields
  for (let i = 0; i < inputRects.length; i++) {
    for (let j = i + 1; j < inputRects.length; j++) {
      const rect1 = inputRects[i].rect;
      const rect2 = inputRects[j].rect;
      
      // Check if these two elements overlap significantly
      const overlaps = !(
        rect1.right < rect2.left || 
        rect1.left > rect2.right || 
        rect1.bottom < rect2.top || 
        rect1.top > rect2.bottom
      );
      
      if (overlaps) {
        // Examine the elements to determine if one is visible and one is capturing input
        const style1 = window.getComputedStyle(inputRects[i].element);
        const style2 = window.getComputedStyle(inputRects[j].element);
        
        const isFirstInvisible = style1.opacity === '0' || style1.visibility === 'hidden';
        const isSecondInvisible = style2.opacity === '0' || style2.visibility === 'hidden';
        
        // If one is visible and one is not, this is suspicious
        if ((isFirstInvisible && !isSecondInvisible) || (!isFirstInvisible && isSecondInvisible)) {
          // Don't flag if they are part of the same component (e.g., search box with hidden state)
          if (!arePartOfSameComponent(inputRects[i].element, inputRects[j].element)) {
            return true;
          }
        }
      }
    }
  }
  
  return false;
}

/**
 * Detects suspicious transparent overlays while filtering out legitimate uses
 * Specifically targets deceptive techniques used in phishing
 */
function detectSuspiciousTransparentOverlays(): number {
  let count = 0;
  const overlays = document.querySelectorAll('div, a');
  
  overlays.forEach(element => {
    const style = window.getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    
    // Focus on suspicious patterns that exclude legitimate uses
    const isLargeElement = rect.width > 300 && rect.height > 200;
    const isPositionedStrategically = style.position === 'absolute' || style.position === 'fixed';
    const isInvisibleButClickable = 
      parseFloat(style.opacity) < 0.2 &&
      style.pointerEvents !== 'none' &&
      ((element as HTMLElement).onclick !== null || element.getAttribute('onclick') || element.tagName === 'A');
    const hasFormOverlap = isOverlappingForms(element);
    
    // Exclude legitimate design patterns
    const isNotLegitimateOverlay = 
      !isPartOfModalDialog(element) && 
      !isPartOfCarousel(element) && 
      !isPartOfDropdown(element);
    
    if (isLargeElement && 
        isPositionedStrategically && 
        isInvisibleButClickable && 
        hasFormOverlap && 
        isNotLegitimateOverlay) {
      count++;
    }
  });
  
  return count;
}

/**
 * Helper function to check if an element is hidden as part of a toggle UI pattern
 * (like show/hide password, collapsible sections, etc.)
 */
function isHiddenByToggle(element: Element): boolean {
  // Check if it has siblings with toggle controls
  const parent = element.parentElement;
  if (!parent) return false;
  
  // Look for common toggle patterns
  const hasToggleButton = !!parent.querySelector('button[aria-controls], [aria-expanded], [data-toggle]');
  const hasShowHidePattern = !!parent.querySelector('.show, .hide, [class*="toggle"], [class*="visibility"]');
  
  return hasToggleButton || hasShowHidePattern;
}

/**
 * Helper function to check if an element is part of a dynamic UI
 * (like carousels, tab panels, etc.)
 */
function isInDynamicUI(element: Element): boolean {
  let el: Element | null = element;
  // Walk up 3 levels to check for dynamic UI containers
  for (let i = 0; i < 3 && el; i++) {
    const classAttr = el.getAttribute('class') || '';
    if (classAttr.match(/carousel|slider|tabs|accordion|drawer|panel|swiper|scroll|overflow/i)) {
      return true;
    }
    if (el.getAttribute('role') === 'tabpanel' || el.getAttribute('aria-hidden') === 'true') {
      return true;
    }
    el = el.parentElement;
  }
  return false;
}

/**
 * Helper function to identify legitimate hidden inputs (CSRF tokens, config values, etc.)
 * Enhanced to handle patterns seen in major legitimate websites like PayPal, banks, etc.
 */
function isLegitimateHiddenInput(input: Element): boolean {
  const type = input.getAttribute('type');
  const name = input.getAttribute('name')?.toLowerCase() || '';
  const id = input.getAttribute('id')?.toLowerCase() || '';
  const value = input.getAttribute('value') || '';
  
  // 1. Explicitly hidden inputs are generally legitimate by design
  if (type === 'hidden') return true;
  
  // 2. Common legitimate hidden input patterns for names and IDs
  const legitimatePatterns = [
    // Security & authentication related
    /csrf/i, /token/i, /nonce/i, /security/i, /auth/i, /captcha/i, /recaptcha/i,
    /hash/i, /signature/i, /verify/i, /validation/i, /challenge/i, /fingerprint/i,
    
    // State management and technical metadata
    /hidden/i, /state/i, /timestamp/i, /context/i, /session/i, /flow/i, /step/i,
    /initialized/i, /config/i, /param/i, /setting/i, /env/i, /mode/i, /version/i,
    
    // Analytics, tracking and attribution
    /analytics/i, /tracking/i, /utm_/i, /campaign/i, /source/i, /referrer/i, /visitor/i,
    
    // Navigation and flow control
    /redirect/i, /return/i, /next/i, /prev/i, /back/i, /origin/i, /destination/i,
    /target/i, /success/i, /cancel/i, /callback/i, /fallback/i, /continue/i,
    
    // Localization and preferences
    /locale/i, /language/i, /country/i, /region/i, /timezone/i, /currency/i,
    
    // Form processing controls
    /process/i, /action/i, /method/i, /handler/i, /submit/i, /form/i, /field/i,
    /request/i, /response/i, /dataType/i, /format/i, /encoding/i,
    
    // Feature flags and capabilities
    /enable/i, /disable/i, /show/i, /hide/i, /toggle/i, /feature/i, /support/i,
    /capability/i, /experiment/i, /test/i, /flag/i, /allowPasskey/i, 
    
    // Integration related
    /client/i, /api/i, /service/i, /partner/i, /vendor/i, /integration/i, /connect/i,
    /endpoint/i, /app/i, /application/i, /platform/i, /device/i, /sdk/i,
    
    // UX/UI related
    /theme/i, /style/i, /layout/i, /display/i, /view/i, /screen/i, /page/i, /component/i,
    
    // Common in payment forms
    /payment/i, /transaction/i, /order/i, /invoice/i, /billing/i, /shipping/i,
    
    // Identity and account management
    /account/i, /user/i, /profile/i, /member/i, /registration/i, /login/i, /signin/i,
    /signup/i, /initial/i, /split/i, /isValid/i, /check/i, /exists/i, /available/i,
    
    // Common name patterns seen in legitimate sites like PayPal
    /^fn_/i, /Type$/i, /Id$/i, /Key$/i, /Code$/i, /Url$/i, /Path$/i, /Name$/i
  ];
  
  // 3. Check attribute values against legitimate patterns
  if (name && legitimatePatterns.some(pattern => pattern.test(name))) return true;
  if (id && legitimatePatterns.some(pattern => pattern.test(id))) return true;
  
  // 4. Special case handling for common legitimate value patterns
  
  // Boolean flags (true/false, yes/no, 1/0)
  if (/^(true|false|yes|no|1|0)$/i.test(value)) return true;
  
  // UUIDs, hashes, or other security tokens
  if (/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value) || // UUID format
      /^[a-f0-9]{32,64}$/i.test(value) ||                          // Hash format
      /^[A-Za-z0-9+/=]{20,}$/i.test(value)) {                      // Base64 encoded data
    return true;
  }
  
  // 5. Check for typical patterns in form structure
  
  // Is this in a form with other legitimate elements?
  const parentForm = input.closest('form');
  if (parentForm) {
    // Form with password field is likely legitimate auth
    if (parentForm.querySelector('input[type="password"]')) return true;
    
    // Form with standard submit button is likely legitimate
    if (parentForm.querySelector('button[type="submit"], input[type="submit"]')) return true;
  }
  
  // 6. Common value patterns for configuration
  if (value && (
      // Empty string, common valid default
      value === '' ||
      // URLs or paths 
      value.startsWith('/') || 
      value.startsWith('http') ||
      // Language codes
      /^[a-z]{2}(_[A-Z]{2})?$/.test(value) ||
      // Technical configuration
      value === 'fn_sync_data' ||
      value === 'main' ||
      value === 'inputEmail'
  )) {
    return true;
  }
  
  return false;
}

/**
 * Analyzes hidden input fields on the page to calculate a suspicious ratio
 * Sophisticated analysis that recognizes legitimate cases (like PayPal's checkout)
 */
function analyzeHiddenInputs(): { 
  total: number; 
  suspicious: number; 
  legitimate: number; 
  suspiciousRatio: number;
  patterns: { [key: string]: number };
} {
  const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
  const result = {
    total: hiddenInputs.length,
    suspicious: 0,
    legitimate: 0,
    suspiciousRatio: 0,
    patterns: {} as { [key: string]: number }
  };
  
  // No hidden inputs, return early
  if (result.total === 0) return result;
  
  // Count legitimate vs suspicious hidden inputs
  hiddenInputs.forEach(input => {
    const name = input.getAttribute('name')?.toLowerCase() || '';
    const value = input.getAttribute('value') || '';
    
    // Skip inputs without names
    if (!name) return;
    
    // Group hidden inputs by common name patterns for analysis
    // Extract the base pattern (e.g., "csrf_token_123" -> "csrf_token")
    let pattern = name.replace(/[0-9]+$/, '');
    
    // For numbered fields like field1, field2, extract the base
    pattern = pattern.replace(/^(.*?)[\d]+$/, '$1');
    
    // Record frequency of patterns
    if (!result.patterns[pattern]) {
      result.patterns[pattern] = 1;
    } else {
      result.patterns[pattern]++;
    }
    
    // Determine if this is a suspicious hidden input
    const isSuspicious = isSuspiciousHiddenInput(input);
    
    if (isSuspicious) {
      result.suspicious++;
    } else {
      result.legitimate++;
    }
  });
  
  // Calculate the ratio of suspicious to total hidden inputs
  result.suspiciousRatio = result.total > 0 ? result.suspicious / result.total : 0;
  
  // Log detailed information for debugging
  logger.log("Hidden input analysis:", {
    total: result.total,
    suspicious: result.suspicious,
    legitimate: result.legitimate,
    suspiciousRatio: result.suspiciousRatio.toFixed(2),
    topPatterns: Object.entries(result.patterns)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
  });
  
  return result;
}

/**
 * Determine if a hidden input is suspicious
 * Specifically looking for cases where hidden inputs appear to be collecting
 * sensitive information deceptively
 */
function isSuspiciousHiddenInput(input: Element): boolean {
  // If it's already been classified as legitimate, return false
  if (isLegitimateHiddenInput(input)) return false;
  
  const name = input.getAttribute('name')?.toLowerCase() || '';
  const id = input.getAttribute('id')?.toLowerCase() || '';
  const value = input.getAttribute('value') || '';
  
  // Suspicious name patterns for hidden inputs
  const suspiciousPatterns = [
    // Credentials
    /password/i, /passwd/i, /passphrase/i, /pin/i,
    
    // Financial information
    /^cc/i, /^card/i, /^cvv/i, /^cvc/i, /^ccv/i, /^securitycode/i,
    /credit.*number/i, /card.*number/i,
    /^exp/i, /expir(y|ation)/i, /^csc/i,
    
    // Personal identifiable information specifically in hidden fields
    /^ssn$/i, /^social.*security/i, /^(tax|taxpayer).*id/i, /^passport/i,
    
    // Banking specific
    /^account.*number/i, /^routing/i, /^swift/i, /^iban/i,
    
    // Personal information in hidden fields is suspicious
    /^full.*name$/i, /^first.*name$/i, /^last.*name$/i
  ];
  
  // Check name and ID against suspicious patterns
  if (suspiciousPatterns.some(pattern => pattern.test(name) || pattern.test(id))) {
    return true;
  }
  
  // Check for suspicious value patterns
  
  // Suspicious if a hidden field has a credit card format value already populated
  if (/^(?:\d[ -]*?){13,16}$/.test(value) || // Credit card number format
      /^\d{3,4}$/.test(value)) {            // CVV format
    return true;
  }
  
  // Suspicious if hidden input appears to store PII values
  if (/^[A-Z][a-z]+ [A-Z][a-z]+$/.test(value) || // Full name format
      /^\d{3}-\d{2}-\d{4}$/.test(value)) {      // SSN format
    return true;
  }
  
  return false;
}

/**
 * Calculate impact based on hidden input analysis
 */
function calculateHiddenInputImpact(analysis: {
  total: number;
  suspicious: number;
  legitimate: number;
  suspiciousRatio: number;
}): number {
  // If no hidden inputs, slightly negative impact (good sign)
  if (analysis.total === 0) return -0.2;
  
  // If many hidden inputs but none suspicious (like PayPal), strong negative impact (good sign)
  if (analysis.total >= 10 && analysis.suspicious === 0) return -0.4;
  
  // If a few hidden inputs with none suspicious, slight negative impact
  if (analysis.total < 10 && analysis.suspicious === 0) return -0.2;
  
  // High suspicious ratio is concerning
  if (analysis.suspiciousRatio >= 0.5) return 0.8;
  if (analysis.suspiciousRatio >= 0.25) return 0.5;
  if (analysis.suspiciousRatio > 0) return 0.3;
  
  // Balanced mix with low suspicious ratio
  return 0.1;
}

/**
 * Helper function to check if an element is overlapping any form elements
 */
function isOverlappingForms(element: Element): boolean {
  const elementRect = element.getBoundingClientRect();
  const forms = document.querySelectorAll('form, input, button[type="submit"]');
  
  for (const form of Array.from(forms)) {
    const formRect = form.getBoundingClientRect();
    const overlaps = !(
      elementRect.right < formRect.left || 
      elementRect.left > formRect.right || 
      elementRect.bottom < formRect.top || 
      elementRect.top > formRect.bottom
    );
    
    if (overlaps) return true;
  }
  
  return false;
}

/**
 * Helper function to check if an element is part of a modal dialog pattern
 */
function isPartOfModalDialog(element: Element): boolean {
  let el: Element | null = element;
  while (el) {
    if (
      el.getAttribute('role') === 'dialog' ||
      el.getAttribute('aria-modal') === 'true' ||
      el.classList.contains('modal') ||
      el.classList.contains('dialog') ||
      el.classList.contains('overlay') ||
      el.getAttribute('id')?.includes('modal') ||
      el.getAttribute('id')?.includes('dialog')
    ) {
      return true;
    }
    el = el.parentElement;
  }
  return false;
}

/**
 * Helper function to check if an element is part of a carousel
 */
function isPartOfCarousel(element: Element): boolean {
  let el: Element | null = element;
  while (el) {
    if (
      el.classList.contains('carousel') ||
      el.classList.contains('slider') ||
      el.classList.contains('swiper') ||
      el.getAttribute('id')?.includes('carousel') ||
      el.getAttribute('id')?.includes('slider') ||
      el.getAttribute('role') === 'slider'
    ) {
      return true;
    }
    el = el.parentElement;
  }
  return false;
}

/**
 * Helper function to check if an element is part of a dropdown menu
 */
function isPartOfDropdown(element: Element): boolean {
  let el: Element | null = element;
  while (el) {
    if (
      el.classList.contains('dropdown') ||
      el.classList.contains('menu') ||
      el.getAttribute('role') === 'menu' ||
      el.getAttribute('aria-haspopup') === 'true'
    ) {
      return true;
    }
    el = el.parentElement;
  }
  return false;
}

/**
 * Helper function to determine if two elements are part of the same UI component
 */
function arePartOfSameComponent(element1: Element, element2: Element): boolean {
  // Check if they share a common parent within 3 levels
  let parent1: Element | null = element1;
  for (let i = 0; i < 3 && parent1; i++) {
    let parent2: Element | null = element2;
    for (let j = 0; j < 3 && parent2; j++) {
      if (parent1 === parent2) return true;
      parent2 = parent2.parentElement;
    }
    parent1 = parent1.parentElement;
  }
  
  // Check if they are siblings with similar attributes
  if (element1.parentElement && element1.parentElement === element2.parentElement) {
    // Check if they have similar names, classes, or data attributes
    const e1Classes = element1.className || '';
    const e2Classes = element2.className || '';
    const e1Id = element1.id || '';
    const e2Id = element2.id || '';
    
    // Check for naming patterns that indicate relationship
    if ((e1Id && e2Id) && (
        e1Id.includes(e2Id) || 
        e2Id.includes(e1Id) ||
        // Common patterns like input-visible and input-hidden
        e1Id.replace(/(visible|hidden|show|hide)$/, '') === 
        e2Id.replace(/(visible|hidden|show|hide)$/, '')
    )) {
      return true;
    }
    
    // Check for common class patterns
    if (e1Classes && e2Classes && (
        e1Classes.includes(e2Classes) || 
        e2Classes.includes(e1Classes) ||
        // Check for common frameworks class patterns
        e1Classes.match(/active|inactive|visible|hidden/) && 
        e2Classes.match(/active|inactive|visible|hidden/)
    )) {
      return true;
    }
  }
  
  return false;
}

/**
 * Calculate impact score based on number of suspicious transparent overlays
 */
function calculateOverlayImpact(count: number): number {
  if (count === 0) return -0.1;
  if (count === 1) return 0.5; 
  if (count >= 2) return 0.8;
  return 0;
}
