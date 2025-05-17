// Constants for DOM detector

// List of suspicious keywords that might indicate phishing
export const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'password', 'secure', 'account', 'banking',
  'update', 'confirm', 'verification', 'authenticate', 'credential',
  'personal', 'information', 'contact', 'details', 'identity', 'verify identity',
  'required', 'mandatory', 'validate', 'subscription', 'billing'
];

// List of common brand names that are often impersonated
export const COMMON_PHISHING_TARGETS = [
  'paypal', 'apple', 'amazon', 'microsoft', 'google', 'facebook', 'netflix',
  'bank', 'ebay', 'instagram', 'coinbase', 'chase', 'wellsfargo', 'citi',
  'amex', 'mastercard', 'visa', 'discover', 'dropbox', 'linkedin', 'twitter',
  'yahoo', 'outlook', 'gmail', 'icloud', 'steam', 'spotify', 'snapchat'
];

// Comprehensive list of suspicious words for fraud text detection
export const SUSPICIOUS_WORDS = [
  // Urgency terms
  'urgent', 'immediately', 'quick', 'hurry', 'limited time', 'expires', 'act now', 'deadline',
  // Security terms
  'verify', 'confirm', 'validate', 'secure', 'protect', 'alert', 'warning',
  // Account terms
  'account', 'password', 'login', 'credentials', 'profile', 'suspended', 'disabled', 'blocked', 'sign in',
  // Financial terms
  'pay', 'bank', 'debit', 'transfer', 'transaction', 'money', 'financial','revenue', 'profit', 'investment',
  // Reward terms
  'free', 'prize', 'winner', 'reward', 'gift', 'bonus', 'discount', 'offer',
  // Crypto terms
  'crypto', 'bitcoin', 'eth','btc', 'wallet', 'blockchain', 'token', 'mining', 'coin',
  // Threat terms
  'suspicious', 'unauthorized', 'unusual', 'risk', 'compromised', 'threat', 'breach', 'violation',
  // Action terms
  'click', 'download', 'submit', 'provide'
];

// Configuration settings that could be updated without hardcoding
export const CONFIG = {
  // Reputation scores needed to consider a site trustworthy
  reputation: {
    trustThreshold: 0.7,              // Score above which a site is considered trusted
    highReputationThreshold: 0.85,    // Score above which a site is considered highly trusted
    suspiciousThreshold: 0.3          // Score below which a site is considered suspicious
  },
  
  // Detection settings
  detection: {
    // Thresholds for form analysis
    minVisibleFieldsForDataCollection: 3, // More than this number of fields suggests data collection
    maxVisibleFieldsForLogin: 3,          // Login forms typically have fewer fields
    
    // Weights for different signals
    externalFormSubmissionWeight: 0.9,    // Weight for forms that submit to external domains
    financialDataCollectionWeight: 0.95,  // Weight for forms that collect financial data
    personalDataCollectionWeight: 0.6,    // Weight for forms that collect personal data
    
    // Feature impact values
    financialDataPositiveImpact: 0.9,     // Impact if financial data collection is detected
    financialDataNegativeImpact: -0.1,    // Impact if financial data collection is not detected
    personalDataPositiveImpact: 0.5,      // Impact if personal data collection is detected
    personalDataNegativeImpact: -0.1      // Impact if personal data collection is not detected
  }
};
