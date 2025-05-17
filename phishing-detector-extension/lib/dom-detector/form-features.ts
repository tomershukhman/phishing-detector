// Form features extraction for DOM detector
import type { DomFeature } from "./types"
import { domLogger as logger } from "../logger"
import { detectLoginForm } from "./utils"
import { SUSPICIOUS_KEYWORDS } from "./constants"
import { hasTrustedReputation, isLikelyLegitimateForm } from "./site-reputation"

// Extract form-related features
export function extractFormFeatures(features: DomFeature[]): void {
  const forms = document.forms;
  const passwordFields = document.querySelectorAll('input[type="password"]');
  
  // 1. Authentication form detection
  // This replaces both formCount and loginFormDetected with a more specific categorization
  const formAnalysis = analyzeFormPurpose();
  
  features.push({
    name: "hasAuthenticationForm",
    value: formAnalysis.hasAuthenticationForm,
    weight: 0.75,
    impact: formAnalysis.hasAuthenticationForm ? 0.5 : -0.2
  });
  
  // 2. External form submission (remains important as a standalone feature)
  const externalFormSubmission = Array.from(forms).some(form => {
    const action = form.getAttribute('action') || '';
    
    // If action is empty, check if there are any event handlers that might submit to external domains
    if (!action) {
      const hasExternalSubmitScript = form.hasAttribute('onsubmit') && 
        (form.getAttribute('onsubmit') || '').toLowerCase().includes('http');
      if (hasExternalSubmitScript) return true;
    }
    
    // Handle both http and https protocols
    if (action.startsWith('http')) {
      try {
        // Use URL parsing to properly handle subdomains and different TLDs
        const actionUrl = new URL(action);
        const currentDomain = window.location.hostname;
        
        // Extract the base domain to compare (e.g., example.com from sub.example.com)
        const getBaseDomain = (hostname) => {
          const parts = hostname.split('.');
          if (parts.length > 2) {
            // This handles cases like sub.example.com -> example.com
            return parts.slice(-2).join('.');
          }
          return hostname;
        };
        
        const actionBaseDomain = getBaseDomain(actionUrl.hostname);
        const currentBaseDomain = getBaseDomain(currentDomain);
        
        // Return true if domains don't match (indicating external submission)
        return actionBaseDomain !== currentBaseDomain;
      } catch (e) {
        // If URL parsing fails, fall back to the original implementation
        return !action.includes(window.location.hostname);
      }
    }
    
    return false;
  });
  
  features.push({
    name: "externalFormSubmission",
    value: externalFormSubmission,
    weight: 0.9,
    impact: externalFormSubmission ? 0.8 : -0.1
  });
  
  // 3. Data collection categorization
  // This replaces the overlapping sensitiveInputFieldCount and suspiciousInputFields
  // with more distinctive categorization
  const dataCollection = analyzeDataCollection();
  
  // 3a. Financial data collection (highest risk category)
  features.push({
    name: "collectsFinancialData",
    value: dataCollection.financial,
    weight: 0.95,
    impact: dataCollection.financial ? 0.9 : -0.1
  });
  
  // 3b. Identity data collection (high risk category)
  features.push({
    name: "collectsIdentityData",
    value: dataCollection.identity,
    weight: 0.8,
    impact: dataCollection.identity ? 0.7 : -0.1
  });
  
  // 3c. Personal data collection (medium risk)
  // We differentiate between basic login forms (email+password) and actual personal data collection
  // A form with just email and password fields isn't considered personal data collection
  // but forms with address, name, phone, etc. are flagged
  features.push({
    name: "collectsPersonalData",
    value: dataCollection.personal,
    weight: 0.6,
    impact: dataCollection.personal ? 0.5 : -0.1
  });
  
  // 4. Form implementation suspicious patterns
  // This replaces suspiciousFormAttributes with more specific checks
  const implementationIssues = detectSuspiciousImplementation();
  
  features.push({
    name: "hasSuspiciousFormImplementation",
    value: implementationIssues > 0,
    weight: 0.7,
    impact: implementationIssues > 0 ? 0.6 : -0.2
  });
  
  // 8. Check for high density of personal information fields
  const personalInfoDensity = analyzePersonalInfoDensity();
  
  features.push({
    name: "personalInfoDensity",
    value: personalInfoDensity,
    weight: 0.8,
    impact: personalInfoDensity > 0.8 ? 0.65 : -0.01
  });
  
  // 9. Check for excessive inline styling (often used in phishing pages)
  const inlineStyleRate = [...document.querySelectorAll('*')]
    .filter(el => el.hasAttribute("style")).length / document.getElementsByTagName("*").length;
  const excessiveInlineStyling = inlineStyleRate > 0.5;
  
  features.push({
    name: "excessiveInlineStyling",
    value: excessiveInlineStyling,
    weight: 0.8,
    impact: excessiveInlineStyling ? 0.8 : -0.01
  });
  
  // 10. Check for password inputs that are outside of forms or hidden
  // Phishing sites often place password inputs outside of proper forms
  // or hide real inputs while displaying fake ones
  const orphanPasswordInputs = [...document.querySelectorAll('input[type="password"]')]
    .filter(p => !p.closest("form") || getComputedStyle(p).display === "none");
  const hasSuspiciousPasswordInput = orphanPasswordInputs.length > 0;
  
  features.push({
    name: "hasSuspiciousPasswordInput",
    value: hasSuspiciousPasswordInput,
    weight: 0.8,
    impact: hasSuspiciousPasswordInput ? 0.8 : -0.01
  });
  
  // 11. Check for fake input elements (divs/spans styled to look like inputs)
  // Phishing sites often create fake input fields with divs/spans that look like inputs
  const fakeInputs = [...document.querySelectorAll("div, span")]
    .filter(el => {
      const text = (el as HTMLElement).textContent?.toLowerCase() || '';
      const hasBorder = getComputedStyle(el).borderStyle !== "none";
      const isClickable = el.hasAttribute('onclick') || 
                          (el as HTMLElement).tabIndex >= 0 || 
                          el.getAttribute('role') === 'textbox' ||
                          el.getAttribute('contenteditable') === 'true';
      return hasBorder && isClickable && (text.includes("password") || text.includes("email"));
  });
  const hasFakeInputs = fakeInputs.length > 0;
  
  features.push({
    name: "hasFakeInputs",
    value: hasFakeInputs,
    weight: 0.8,
    impact: hasFakeInputs ? 0.8 : -0.01
  });
  
  // 12. Check for suspicious full-screen overlays
  // Phishing sites often use overlays to simulate the entire page
  const overlays = [...document.querySelectorAll("*")]
    .filter(el => {
      const style = getComputedStyle(el);
      return style.position === "fixed" &&
        parseInt(style.zIndex || "0") > 1000 &&
        (el as HTMLElement).offsetWidth > window.innerWidth * 0.8 &&
        (el as HTMLElement).offsetHeight > window.innerHeight * 0.8;
    });
  const hasSuspiciousOverlay = overlays.length > 0;
  
  features.push({
    name: "hasSuspiciousOverlay",
    value: hasSuspiciousOverlay,
    weight: 0.6,
    impact: hasSuspiciousOverlay ? 0.7 : -0.01
  });
  
  // 13. Check for pages that have forms but no scripts
  // Legitimate login pages almost always have scripts, while phishing copies often don't
  const noScripts = document.querySelectorAll("script").length === 0;
  const hasForms = document.forms.length > 0;
  const suspiciousNoScriptForm = noScripts && hasForms;
  
  features.push({
    name: "suspiciousNoScriptForm",
    value: suspiciousNoScriptForm,
    weight: 0.8,
    impact: suspiciousNoScriptForm ? 0.8 : -0.01
  });
  
  // 14. Check for excessive use of base64 encoded images
  // Phishing sites often embed images as base64 to avoid external references
  const base64Images = [...document.querySelectorAll("img")]
    .filter(img => img.src.startsWith("data:image/"));
  const excessiveBase64Images = base64Images.length > 3;
  
  features.push({
    name: "excessiveBase64Images",
    value: excessiveBase64Images,
    weight: 0.8,
    impact: excessiveBase64Images ? 0.8 : -0.01
  });
}

// Helper function to detect sensitive input fields that might be used for phishing
function detectSensitiveInputFields(): number {
  let count = 0;
  const allInputs = document.querySelectorAll('input');
  
  // Keywords that suggest sensitive input fields
  const sensitiveKeywords = [
    // Credit card related
    'credit', 'card', 'cc', 'cvv', 'cvc', 'ccv', 'security code', 'card number', 'expiry', 'expiration',
    // Identity related
    'ssn', 'social security', 'national id', 'passport', 'license', 'id number', 'tax id',
    // Banking related
    'bank account', 'routing', 'swift', 'iban', 'pin', 'atm', 'account number',
    // Personal data
    'birthdate', 'date of birth', 'mother maiden', 'maiden name',
    // Basic personal info
    'email', 'e-mail', 'phone', 'mobile', 'cell', 'telephone', 'address', 'street', 'city', 'state',
    'zip', 'postal', 'country', 'full name', 'first name', 'last name', 'surname', 'dob'
  ];
  
  const sensitiveTypes = ['tel', 'number', 'email'];
  const inputPatterns = {
    creditCard: /^(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})$/,
    ssn: /^(?!000|666)[0-8][0-9]{2}(?!00)[0-9]{2}(?!0000)[0-9]{4}$/,
    date: /^(?:0[1-9]|1[0-2])\/(?:0[1-9]|[12][0-9]|3[01])\/(?:19|20)\d{2}$/,
    email: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
    phone: /^[\d\s\(\)\-\+\.]{10,15}$/
  };
  
  // Check for inputs with patterns matching credit card format
  const numberInputsWithPattern = document.querySelectorAll('input[pattern]');
  for (const input of Array.from(numberInputsWithPattern)) {
    const pattern = input.getAttribute('pattern');
    if (pattern && (
        pattern.includes('\\d{13,16}') || // Common pattern for credit cards
        pattern.includes('\\d{3,4}') ||   // Common pattern for CVV
        pattern.includes('[0-9]{13,16}') || // Alternative pattern for credit cards
        pattern.includes('[0-9]{3,4}')     // Alternative pattern for CVV
    )) {
      count++;
    }
  }
  
  // Check all inputs for attributes and placeholder values
  for (const input of Array.from(allInputs)) {
    const type = input.getAttribute('type') || '';
    const name = (input.getAttribute('name') || '').toLowerCase();
    const id = (input.getAttribute('id') || '').toLowerCase();
    const placeholder = (input.getAttribute('placeholder') || '').toLowerCase();
    const className = (input.getAttribute('class') || '').toLowerCase();
    const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
    
    // Check for specific input types that often collect personal information
    if (type === 'email' || type === 'tel') {
      count++;
      continue;
    }
    
    // Check for credit card specific autocomplete values
    if (autocomplete.includes('cc-') || 
        autocomplete === 'cc-number' || 
        autocomplete === 'cc-exp' || 
        autocomplete === 'cc-csc') {
      count++;
      continue;
    }
    
    // Check for personal information autocomplete values
    if (autocomplete.includes('email') || 
        autocomplete.includes('phone') || 
        autocomplete.includes('tel') ||
        autocomplete.includes('name') ||
        autocomplete.includes('address') ||
        autocomplete.includes('postal')) {
      count++;
      continue;
    }
    
    // Check attributes against sensitive keywords
    const inputText = `${name} ${id} ${placeholder} ${className}`;
    if (sensitiveKeywords.some(keyword => inputText.includes(keyword))) {
      count++;
      continue;
    }
    
    // Check for typical credit card field sizes
    if (type === 'tel' || type === 'number' || type === 'text') {
      const maxLength = input.getAttribute('maxlength');
      if (maxLength) {
        // Credit card number is typically 16 digits
        if (maxLength === '16' || maxLength === '19') {
          count++;
          continue;
        }
        // CVV is typically 3-4 digits
        if (maxLength === '3' || maxLength === '4') {
          count++;
          continue;
        }
      }
    }
    
    // Check for data input formats (MM/YY or MM/YYYY)
    if (placeholder && (
        placeholder.includes('MM/YY') || 
        placeholder.includes('MM/YYYY') ||
        placeholder.includes('mm/yy') ||
        placeholder.includes('mm/yyyy')
    )) {
      count++;
      continue;
    }
  }
  
  return count;
}

// Helper function to analyze the density of personal information fields
function analyzePersonalInfoDensity(): number {
  const allInputs = document.querySelectorAll('input');
  if (allInputs.length === 0) return 0;
  
  // Define categories of personal information
  const categories = {
    identity: ['name', 'firstname', 'lastname', 'surname', 'full name', 'fullname'],
    contact: ['email', 'phone', 'mobile', 'telephone', 'cell'],
    address: ['address', 'street', 'city', 'state', 'zip', 'postal', 'country'],
    financial: ['credit', 'card', 'cvv', 'cvc', 'expiry', 'expiration', 'bank', 'account'],
    government: ['ssn', 'social security', 'tax', 'passport', 'license', 'id number'],
    personal: ['birth', 'dob', 'age', 'gender', 'sex', 'nationality', 'mother maiden']
  };
  
  // Track which categories are found in the form
  const foundCategories = {};
  let categoryCount = 0;
  
  // Check each input for category matches
  for (const input of Array.from(allInputs)) {
    const type = (input.getAttribute('type') || '').toLowerCase();
    const name = (input.getAttribute('name') || '').toLowerCase();
    const id = (input.getAttribute('id') || '').toLowerCase();
    const placeholder = (input.getAttribute('placeholder') || '').toLowerCase();
    const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
    
    const inputText = `${name} ${id} ${placeholder} ${autocomplete}`;
    
    // Check each category
    for (const [category, keywords] of Object.entries(categories)) {
      if (!foundCategories[category] && keywords.some(keyword => inputText.includes(keyword))) {
        foundCategories[category] = true;
        categoryCount++;
        break; // Once a category is found, no need to check further keywords
      }
    }
    
    // Special case checks for specific input types
    if (!foundCategories['contact'] && (type === 'email' || type === 'tel')) {
      foundCategories['contact'] = true;
      categoryCount++;
    }
    
    if (!foundCategories['financial'] && autocomplete.includes('cc-')) {
      foundCategories['financial'] = true;
      categoryCount++;
    }
  }
  
  // Calculate a density score (0-1)
  // Higher score when more categories of personal information are being collected
  return Math.min(categoryCount / 6, 1.0); // 6 is the total number of categories
}

// Helper function to detect suspicious input fields
function detectSuspiciousInputFields(): number {
  let count = 0;
  const allInputs = document.querySelectorAll('input');
  
  // Check for common input types that collect personal info
  const emailInputs = document.querySelectorAll('input[type="email"]');
  const telInputs = document.querySelectorAll('input[type="tel"]');
  
  // Count the presence of these input types directly
  // We weight this less than in the sensitive function, as legitimate sites use these too
  if (emailInputs.length > 0) count++;
  if (telInputs.length > 0) count++;
  
  for (const input of Array.from(allInputs)) {
    const type = (input.getAttribute('type') || '').toLowerCase();
    const name = (input.getAttribute('name') || '').toLowerCase();
    const id = (input.getAttribute('id') || '').toLowerCase();
    const placeholder = (input.getAttribute('placeholder') || '').toLowerCase();
    
    // Check for hidden inputs that might collect data surreptitiously
    // Be more precise with these checks since many legitimate sites use hidden fields
    if (type === 'hidden') {
      // Hidden fields with these sensitive patterns are concerning
      // but only when they seem to be collecting sensitive data rather than configuration
      const isSuspiciousHiddenField = (
        // User credentials in hidden fields is highly suspicious
        name.includes('password') || 
        name.includes('passwd') || 
        name.includes('userpass') ||
        id.includes('password') || 
        id.includes('passwd') ||
        
        // Credit card data in hidden fields is highly suspicious
        name.includes('cardnumber') || 
        name.includes('ccnumber') || 
        name.includes('securitycode') || 
        name.includes('cvv') ||
        id.includes('cardnumber') || 
        id.includes('ccnumber')
      );
      
      if (isSuspiciousHiddenField) {
        count++;
        continue;
      }
    }
    
    // Check for fields with suspicious keywords
    const inputText = `${name} ${id} ${placeholder}`;
    if (SUSPICIOUS_KEYWORDS.some(keyword => inputText.includes(keyword))) {
      count++;
      continue;
    }
    
    // Check for inputs that might be disguised (e.g., password fields not marked as such)
    if (type === 'text' && (
        name.includes('pass') ||
        id.includes('pass') ||
        placeholder.includes('pass') ||
        name.includes('pwd') ||
        id.includes('pwd') ||
        placeholder.includes('pwd')
    )) {
      count++;
      continue;
    }
    
    // Check for fields that might be collecting personal data 
    // but aren't properly labeled for autocomplete
    if (type === 'text' && (
        inputText.includes('address') ||
        inputText.includes('phone') ||
        inputText.includes('mobile') ||
        inputText.includes('birth') ||
        inputText.includes('zip') ||
        inputText.includes('postal') ||
        inputText.includes('email') ||
        inputText.includes('name') ||
        inputText.includes('surname') ||
        inputText.includes('first') ||
        inputText.includes('last')
    ) && !input.hasAttribute('autocomplete')) {
      count++;
      continue;
    }
    
    // Check text fields with patterns matching email or phone formats
    if (type === 'text') {
      // Common email pattern attribute
      const pattern = input.getAttribute('pattern');
      if (pattern && (
          pattern.includes('@') || 
          pattern.includes('[a-zA-Z0-9._%+-]+@') ||
          pattern.includes('\\d{3}[-\\.\\s]\\d{3}[-\\.\\s]\\d{4}') // Phone pattern
      )) {
        count++;
        continue;
      }
      
      // Check for placeholder that suggests email/phone input
      if (placeholder && (
          placeholder.includes('@') ||
          placeholder.includes('email') ||
          placeholder.includes('phone') ||
          placeholder.includes('mobile') ||
          placeholder.match(/\d{3}[.\-\s]?\d{3}[.\-\s]?\d{4}/) // Phone format in placeholder
      )) {
        count++;
        continue;
      }
    }
  }
  
  return count;
}

// Analyzes the purpose of forms on the page
function analyzeFormPurpose() {
  const forms = document.forms;
  const passwordFields = document.querySelectorAll('input[type="password"]');
  
  // Determine if the page has an authentication form
  const hasAuthenticationForm = passwordFields.length > 0 || detectLoginForm();
  
  // Analyze each form to determine its purpose
  let hasTransactionForm = false;
  let hasSubscriptionForm = false;
  
  for (const form of Array.from(forms)) {
    const formContent = form.innerHTML.toLowerCase();
    const formText = form.textContent?.toLowerCase() || '';
    
    // Check for transaction forms
    if (
      formText.includes('payment') || 
      formText.includes('checkout') || 
      formText.includes('purchase') ||
      formText.includes('order') ||
      formText.includes('buy') ||
      form.querySelector('input[name*="card"], input[id*="card"], input[placeholder*="card"]')
    ) {
      hasTransactionForm = true;
    }
    
    // Check for subscription/membership forms
    if (
      formText.includes('subscribe') || 
      formText.includes('sign up') || 
      formText.includes('join') ||
      formText.includes('register') ||
      formText.includes('create account')
    ) {
      hasSubscriptionForm = true;
    }
  }
  
  return {
    hasAuthenticationForm,
    hasTransactionForm,
    hasSubscriptionForm
  };
}

// Analyzes what types of data are being collected
function analyzeDataCollection() {
  const allInputs = document.querySelectorAll('input');
  
  // Categories of data being collected
  const dataTypes = {
    financial: false,  // Credit cards, bank accounts, etc.
    identity: false,   // Government IDs, SSNs, etc.
    personal: false,   // Names, addresses, emails, phone numbers
    credentials: false // Usernames, passwords
  };
  
  // Financial data indicators - highly specific words that indicate actual financial data collection
  const financialKeywords = [
    'credit card', 'creditcard', 'cc number', 'ccnumber', 'cvv', 'cvc', 'ccv', 'security code', 
    'card number', 'cardnumber', 'expiry', 'expiration date', 'bank account', 'routing', 
    'swift', 'iban', 'account number'
  ];
  
  // Words like "pin", "atm", "credit", "card" alone are too general and can cause false positives
  // "payment" removed from the financial keywords list as it's too general
  // and might appear in contexts unrelated to financial data collection
  
  // Identity data indicators
  const identityKeywords = [
    'ssn', 'social security', 'national id', 'passport', 'license', 
    'id number', 'tax id', 'identification', 'government'
  ];
  
  // Personal data indicators - refined list
  const personalKeywords = [
    'fullname', 'firstname', 'lastname', 'surname', 
    'address', 'street', 'city', 'state', 'zip', 'postal', 'country',
    'phone', 'mobile', 'cell', 'telephone', 
    'birthdate', 'date of birth', 'dob', 
    'gender', 'age', 'nationality'
  ];
  
  // Simple contact info (like standalone email) is normal for login forms
  // so we'll treat it separately to avoid false positives
  const contactKeywords = [
    'email'
  ];
  
  // Credential indicators
  const credentialKeywords = [
    'password', 'pwd', 'pass', 'username', 'user', 'login', 'account'
  ];
  
  // Check specific input types
  if (document.querySelector('input[type="password"]')) {
    dataTypes.credentials = true;
  }
  
  // Email inputs are expected on login forms, so only mark as personal
  // if there are multiple personal data fields
  const emailInputs = document.querySelectorAll('input[type="email"]');
  const hasEmailInput = emailInputs.length > 0;
  
  if (hasEmailInput) {
    // We don't automatically set personal=true for just email inputs
    // as they are common in basic login forms
  }
  
  if (document.querySelector('input[type="tel"]')) {
    dataTypes.personal = true;
  }
  
  // Check autocomplete attributes
  const ccInputs = document.querySelector('input[autocomplete^="cc-"]');
  if (ccInputs) {
    dataTypes.financial = true;
  }
  
  // Look for specific financial patterns in inputs
  let hasFinancialInputs = false;
  
  // Check for credit card related input patterns
  const possibleCCInputs = document.querySelectorAll('input[maxlength="15"], input[maxlength="16"], input[maxlength="19"]');
  
  // Only consider it financial data if there are multiple related fields
  // like expiry date or CVV together with the possible CC field
  if (possibleCCInputs.length > 0) {
    const possibleCVVInputs = document.querySelectorAll('input[maxlength="3"], input[maxlength="4"]');
    const expiryInputs = Array.from(document.querySelectorAll('input[placeholder*="MM/YY"], input[placeholder*="mm/yy"], input[placeholder*="MM/YYYY"], input[placeholder*="mm/yyyy"]'));
    
    // Need multiple credit card fields to confirm it's collecting financial data
    if ((possibleCVVInputs.length > 0 && possibleCCInputs.length > 0) || 
        (expiryInputs.length > 0 && possibleCCInputs.length > 0)) {
      hasFinancialInputs = true;
    }
    
    // Also check for attributes that clearly indicate this is a credit card form
    const ccAttributes = document.querySelectorAll('input[autocomplete="cc-number"], input[autocomplete="cc-csc"], input[autocomplete="cc-exp"]');
    if (ccAttributes.length > 0) {
      hasFinancialInputs = true;
    }
  }
  
  // Check all inputs for data type indicators
  for (const input of Array.from(allInputs)) {
    const type = (input.getAttribute('type') || '').toLowerCase();
    const name = (input.getAttribute('name') || '').toLowerCase();
    const id = (input.getAttribute('id') || '').toLowerCase();
    const placeholder = (input.getAttribute('placeholder') || '').toLowerCase();
    const className = (input.getAttribute('class') || '').toLowerCase();
    const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
    const inputText = `${name} ${id} ${placeholder} ${className}`;
    
    // Check for financial data indicators
    if (!dataTypes.financial) {
      // Only set financial to true if there are explicit financial keywords
      // in the actual input fields (not just in page content)
      const indicatesFinancialData = financialKeywords.some(keyword => {
        // Use exact word boundary match to avoid false positives
        const pattern = new RegExp(`\\b${keyword.replace(/\s+/g, '[\\s-_]+')}\\b`, 'i');
        return pattern.test(name) || 
               pattern.test(id) || 
               pattern.test(placeholder);
      });
      
      if (indicatesFinancialData || 
          type === 'creditcard' || 
          name.includes('creditcard') || 
          autocomplete.startsWith('cc-')) {
        
        // Additional check: only mark as financial if multiple financial fields are found
        // or if this is explicitly a credit card field
        if (hasFinancialInputs || 
            type === 'creditcard' || 
            autocomplete.startsWith('cc-')) {
          dataTypes.financial = true;
        }
      }
    }
    
    // Check for identity data indicators
    if (!dataTypes.identity) {
      // More precise matching for identity data keywords
      if (identityKeywords.some(keyword => {
        // Use more precise matching with word boundaries
        const pattern = new RegExp(`\\b${keyword.replace(/\s+/g, '[\\s-_]+')}\\b`, 'i');
        return pattern.test(name) || 
               pattern.test(id) || 
               pattern.test(placeholder);
      })) {
        // For identity data, require at least 2 matching fields to avoid false positives
        // on forms that might have legitimate "id" or similar fields
        const identityCount = Array.from(allInputs).filter(input => {
          const iName = (input.getAttribute('name') || '').toLowerCase();
          const iId = (input.getAttribute('id') || '').toLowerCase();
          const iPlaceholder = (input.getAttribute('placeholder') || '').toLowerCase();
          
          return identityKeywords.some(keyword => {
            const pattern = new RegExp(`\\b${keyword.replace(/\s+/g, '[\\s-_]+')}\\b`, 'i');
            return pattern.test(iName) || pattern.test(iId) || pattern.test(iPlaceholder);
          });
        }).length;
        
        if (identityCount >= 2) {
          dataTypes.identity = true;
        }
      }
    }
    
    // Check for personal data indicators
    if (!dataTypes.personal) {
      // More precise matching for personal data keywords
      if (personalKeywords.some(keyword => {
        // Use more precise matching with word boundaries
        const pattern = new RegExp(`\\b${keyword}\\b`, 'i');
        return pattern.test(name) || 
               pattern.test(id) || 
               pattern.test(placeholder);
      })) {
        dataTypes.personal = true;
      }
    }
    
    // Check for contact keywords separately
    if (contactKeywords.some(keyword => {
      const pattern = new RegExp(`\\b${keyword}\\b`, 'i');
      return pattern.test(name) || 
             pattern.test(id) || 
             pattern.test(placeholder);
    })) {
      // Just having contact info like email doesn't automatically
      // mean personal data collection - only if combined with other personal data
      if (dataTypes.personal) {
        // If we already found other personal data, this confirms it
        dataTypes.personal = true;
      }
    }
    
    // Check for credential indicators
    if (!dataTypes.credentials && credentialKeywords.some(keyword => inputText.includes(keyword))) {
      dataTypes.credentials = true;
    }
    
    // Check for credit card number patterns
    if (!dataTypes.financial && type === 'text') {
      const maxLength = input.getAttribute('maxlength');
      if (maxLength === '16' || maxLength === '19') {
        // Only mark as financial if we have additional evidence
        if (hasFinancialInputs) {
          dataTypes.financial = true;
        }
      }
    }
  }
  
  // Special case for login forms that only collect email + password
  // These shouldn't be classified as collecting personal data
  if (hasEmailInput && document.querySelector('input[type="password"]')) {
    // Count the number of visible input fields to determine if this is just a login form
    // or something that collects more personal data
    const visibleInputs = Array.from(allInputs).filter(input => {
      const type = input.getAttribute('type') || '';
      return type !== 'hidden' && type !== 'submit' && type !== 'button' && type !== 'checkbox';
    });
    
    // If there are just 2-3 fields (likely email, password, and maybe username/remember me)
    // and we haven't detected other personal data, this is probably just a login form
    if (visibleInputs.length <= 3) {
      // Don't mark basic login forms as collecting personal data
      dataTypes.personal = false;
      
      // Check form text content for clues about its purpose
      const forms = document.forms;
      for (const form of Array.from(forms)) {
        const formText = form.textContent?.toLowerCase() || '';
        // If the form mentions personal information collection specifically, 
        // then it might still be collecting personal data
        if (formText.includes('personal information') || 
            formText.includes('personal details') ||
            formText.includes('register') ||
            formText.includes('sign up') ||
            formText.includes('create account')) {
          // If these phrases are found in form text but not near login elements,
          // this might be a registration form rather than a basic login
          dataTypes.personal = true;
        }
      }
    }
  }
  
  // Improved login form detection - check if there are visible form labels
  // that indicate this is just a standard login form
  function isStandardLoginForm() {
    // Look for typical login form indicators
    const loginLabels = document.querySelectorAll('label, .field-label, .form-label');
    const loginTexts = ['log in', 'login', 'sign in', 'signin', 'username', 'email', 'password'];
    
    let loginLabelCount = 0;
    let personalLabelCount = 0;
    
    for (const label of Array.from(loginLabels)) {
      const labelText = label.textContent?.toLowerCase() || '';
      
      // Count login-related labels
      if (loginTexts.some(text => labelText.includes(text))) {
        loginLabelCount++;
      }
      
      // Count personal-data-related labels (which aren't typical for login forms)
      if (personalKeywords.some(keyword => labelText.includes(keyword))) {
        personalLabelCount++;
      }
    }
    
    // If we have more login labels than personal data labels, 
    // and there are no more than 3 visible input fields,
    // this is likely just a standard login form
    return loginLabelCount > 0 && loginLabelCount > personalLabelCount;
  }
  
  // Check if this is a standard login form with just email/username and password
  if (hasEmailInput && document.querySelector('input[type="password"]') && isStandardLoginForm()) {
    dataTypes.personal = false;
  }
  
  // If this is a known legitimate website, we can adjust thresholds
  // to reduce false positives for login forms that might appear to collect financial/personal data
  if (hasTrustedReputation()) {
    // For legitimate sites, login forms should still detect credentials
    // but not necessarily trigger financial/personal data collection warnings
    if (dataTypes.credentials && !hasFinancialInputs) {
      dataTypes.financial = false;
      
      // Check if this is just a login form on a trusted site
      const visibleInputs = Array.from(allInputs).filter(input => {
        const type = input.getAttribute('type') || '';
        return type !== 'hidden' && type !== 'submit' && type !== 'button';
      });
      
      if (visibleInputs.length <= 3) {
        // Basic login form on a trusted site
        dataTypes.personal = false;
      }
    }
  }
  
  // Also check each form individually to see if it appears legitimate
  const forms = document.forms;
  for (const form of Array.from(forms)) {
    if (isLikelyLegitimateForm(form) && dataTypes.credentials) {
      // If this is a legitimate-looking login form, reduce the likelihood of false positives
      if (!hasFinancialInputs) {
        dataTypes.financial = false;
      }
    }
  }
  
  return dataTypes;
}

// Detects suspicious form implementation techniques
function detectSuspiciousImplementation() {
  let suspiciousPatterns = 0;
  const forms = document.forms;
  
  for (const form of Array.from(forms)) {
    // 1. Check for blank or suspicious form actions
    const actionAttr = (form.getAttribute('action') || '').toLowerCase();
    if (!actionAttr || actionAttr === '#' || actionAttr === 'javascript:void(0)') {
      suspiciousPatterns++;
    }
    
    // 2. Check for obfuscated form handling
    if (form.hasAttribute('onsubmit')) {
      const onSubmit = form.getAttribute('onsubmit') || '';
      if (onSubmit.includes('eval(') || onSubmit.includes('encode') || onSubmit.includes('escape')) {
        suspiciousPatterns += 2; // Higher weight for obfuscation
      }
    }
    
    // 3. Check for hidden fields with suspicious purposes
    const hiddenFields = form.querySelectorAll('input[type="hidden"]');
    for (const field of Array.from(hiddenFields)) {
      const name = (field.getAttribute('name') || '').toLowerCase();
      const value = (field.getAttribute('value') || '').toLowerCase();
      
      // Hidden fields trying to capture sensitive data
      if (name.includes('email') || name.includes('user') || name.includes('pass')) {
        suspiciousPatterns++;
      }
      
      // Hidden fields with suspicious values
      if (value.includes('http') || value.includes('redirect') || value.includes('://')) {
        suspiciousPatterns++;
      }
    }
    
    // 4. Check for disguised fields
    const textFields = form.querySelectorAll('input[type="text"]');
    for (const field of Array.from(textFields)) {
      const name = (field.getAttribute('name') || '').toLowerCase();
      const id = (field.getAttribute('id') || '').toLowerCase();
      
      // Text fields pretending to be password fields
      if (name.includes('pass') || id.includes('pass') || name.includes('pwd') || id.includes('pwd')) {
        suspiciousPatterns += 2; // Major suspicious pattern
      }
    }
  }
  
  return suspiciousPatterns;
}
