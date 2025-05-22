// model.js - Converted from TypeScript
// Core model for phishing detection based on URL features

let logger = console;

// Try to load the logger module
(async function loadLogger() {
  try {
    const loggerModule = await import(chrome.runtime.getURL('lib/logger.js'));
    if (loggerModule) {
      logger = loggerModule.modelLogger;
    }
  } catch (error) {
    console.error("Error loading logger:", error);
  }
})();

// Load the model metadata
const modelMetadata = chrome.runtime.getURL("model_metadata.json");
let fetchedModelMetadata = null;

// Export PhishingDetector class
export { PhishingDetector };

// Function to load the model metadata
async function loadModelMetadata() {
  if (!fetchedModelMetadata) {
    try {
      const response = await fetch(modelMetadata);
      fetchedModelMetadata = await response.json();
    } catch (error) {
      console.error("Error loading model metadata:", error);
      // Fallback with empty data
      fetchedModelMetadata = {
        intercept: 0,
        coefficients: [],
        feature_names: [],
        constants: {
          commonTlds: [],
          suspiciousKeywords: [],
          suspiciousExtensions: [],
          multiLevelTlds: [],
          officialTerms: [],
          mediaTerms: [],
          restrictedTlds: [],
          dictionaryWords: [],
          popularDomains: []
        }
      };
    }
  }
  return fetchedModelMetadata;
}

// URLFeatureExtractor class - extracts features from URLs for ML model
class URLFeatureExtractor {
  constructor() {
    // Initialize all constants from model metadata (will be populated later)
    this.commonTlds = new Set();
    this.suspiciousKeywords = [];
    this.suspiciousExtensions = [];
    this.multiLevelTlds = new Set();
    this.officialTerms = new Set();
    this.mediaTerms = new Set();
    this.restrictedTlds = new Set();
    this.dictionaryWords = new Set();
    this.popularDomains = new Set();
  }

  // Initialize with model data
  async init() {
    const modelData = await loadModelMetadata();
    const constants = modelData.constants;
    
    this.commonTlds = new Set(constants.commonTlds);
    this.suspiciousKeywords = constants.suspiciousKeywords;
    this.suspiciousExtensions = constants.suspiciousExtensions;
    this.multiLevelTlds = new Set(constants.multiLevelTlds);
    this.officialTerms = new Set(constants.officialTerms);
    this.mediaTerms = new Set(constants.mediaTerms);
    this.restrictedTlds = new Set(constants.restrictedTlds);
    this.dictionaryWords = new Set(constants.dictionaryWords);
    this.popularDomains = new Set(constants.popularDomains);
    
    return this;
  }
  
  /**
   * Extract features from a URL - main entry point
   * This method calculates exactly the features used by the model
   */
  async extractFeatures(url) {
    const modelData = await loadModelMetadata();
    
    // Make sure we have a properly formatted URL with scheme
    url = this.normalizeUrl(url);
    
    // Parse the URL
    const parsedUrl = this.parseUrl(url);
    const { hostname, path, query } = parsedUrl;
    
    // Extract domain parts
    const domainParts = this.extractDomainParts(hostname);
    const { domain, tld, subdomain } = domainParts;
    
    // Create an empty feature vector
    const features = {};
    
    // Calculate only features that are in the model (from feature_names)
    for (const featureName of modelData.feature_names) {
      features[featureName] = this.calculateFeature(featureName, url, parsedUrl, domainParts);
    }
    
    return features;
  }
  
  /**
   * Make sure the URL has a scheme, defaulting to http if missing
   */
  normalizeUrl(url) {
    if (!url.includes('://')) {
      return 'http://' + url;
    }
    return url;
  }
  
  /**
   * Parse a URL into its components - matches Python's _parse_url
   */
  parseUrl(url) {
    let scheme = '';
    let hostname = '';
    let path = '';
    let query = '';
    let fragment = '';
    
    // Extract fragment if present
    if (url.includes('#')) {
      const fragmentParts = url.split('#');
      url = fragmentParts[0];
      fragment = fragmentParts[1] || '';
    }
    
    // Extract scheme
    if (url.includes('://')) {
      const schemeParts = url.split('://');
      scheme = schemeParts[0].toLowerCase();
      url = schemeParts[1];
    }
    
    // Extract hostname and path+query
    const pathStart = url.indexOf('/');
    if (pathStart !== -1) {
      hostname = url.substring(0, pathStart);
      url = url.substring(pathStart);
    } else {
      hostname = url;
      url = '';
    }
    
    // Extract query parameters
    const queryStart = url.indexOf('?');
    if (queryStart !== -1) {
      path = url.substring(0, queryStart);
      query = url.substring(queryStart + 1);
    } else {
      path = url;
      query = '';
    }
    
    // Handle @ symbol in hostname (username:password@hostname)
    if (hostname.includes('@')) {
      hostname = hostname.split('@').pop() || '';
    }
    
    // Make sure path starts with / if it exists (match Python behavior)
    if (path && !path.startsWith('/')) {
      path = '/' + path;
    }
    
    return { scheme, hostname, path, query, fragment };
  }
  
  /**
   * Extract domain parts (subdomain, domain, TLD) - matches Python's _extract_domain_parts
   */
  extractDomainParts(hostname) {
    // Remove trailing dots
    hostname = hostname.replace(/\.+$/, '');
    
    // Remove port if present
    if (hostname.includes(':')) {
      hostname = hostname.split(':')[0];
    }
    
    // Check for IP address
    if (this.isIpAddress(hostname)) {
      return { subdomain: '', domain: hostname, tld: '' };
    }
    
    // Split by dots
    const parts = hostname.split('.');
    
    // Handle simple cases
    if (parts.length === 1) {
      return { subdomain: '', domain: parts[0], tld: '' };
    } else if (parts.length === 2) {
      return { subdomain: '', domain: parts[0], tld: parts[1] };
    }
    
    // Check for multi-level TLDs
    for (let i = Math.min(3, parts.length - 1); i > 0; i--) {
      const potentialTld = parts.slice(parts.length - i).join('.');
      
      if (this.multiLevelTlds.has(potentialTld.toLowerCase()) || 
          potentialTld.toLowerCase().startsWith('co.') ||
          potentialTld.toLowerCase().startsWith('com.') ||
          potentialTld.toLowerCase().startsWith('ac.') ||
          potentialTld.toLowerCase().startsWith('edu.') ||
          potentialTld.toLowerCase().startsWith('gov.')) {
        
        const domain = parts.length > i ? parts[parts.length - i - 1] : '';
        const subdomain = parts.length > i + 1 ? parts.slice(0, parts.length - i - 1).join('.') : '';
        
        return { subdomain, domain, tld: potentialTld };
      }
    }
    
    // Check for ccTLDs with second-level domains
    if (parts.length >= 3 && 
        ['co', 'com', 'org', 'net', 'ac', 'gov', 'edu'].includes(parts[parts.length - 2]) && 
        parts[parts.length - 1].length === 2) {
      
      const tld = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
      const domain = parts[parts.length - 3];
      const subdomain = parts.length > 3 ? parts.slice(0, parts.length - 3).join('.') : '';
      
      return { subdomain, domain, tld };
    } 
    
    // Default case: standard TLD
    const tld = parts[parts.length - 1];
    const domain = parts[parts.length - 2];
    const subdomain = parts.length > 2 ? parts.slice(0, parts.length - 2).join('.') : '';
    
    return { subdomain, domain, tld };
  }
  
  /**
   * Calculate a specific feature - using the same algorithms as the Python implementation
   */
  async calculateFeature(featureName, url, parsedUrl, domainParts) {
    const { scheme, hostname, path, query } = parsedUrl;
    const { domain, tld, subdomain } = domainParts;
    const modelData = await loadModelMetadata();
    
    switch (featureName) {
      case 'ip_address':
        return /https?:\/\/\d+\.\d+\.\d+\.\d+/.test(url) ? 1 : 0;
        
      case 'keyword_count':
        return this.suspiciousKeywords.reduce((count, kw) => count + (url.toLowerCase().includes(kw) ? 1 : 0), 0);
        
      case 'uses_https':
        return scheme.toLowerCase() === 'https' ? 1 : 0;
        
      case 'subdomain_count':
        return subdomain ? subdomain.split('.').length : 0;
        
      case 'has_at_symbol':
        return url.includes('@') ? 1 : 0;
        
      case 'has_suspicious_ext':
        return this.suspiciousExtensions.some(ext => url.toLowerCase().endsWith(ext)) ? 1 : 0;
        
      case 'has_port':
        return hostname.includes(':') ? 1 : 0;
        
      case 'digit_letter_ratio': {
        const digitCount = Array.from(url).filter(c => /\d/.test(c)).length;
        const letterCount = Array.from(url).filter(c => /[a-zA-Z]/.test(c)).length;
        return letterCount > 0 ? digitCount / letterCount : 0;
      }
        
      case 'path_depth':
        return path.length > 0 ? (path.match(/\//g) || []).length : 0;
        
      case 'domain_length':
        return domain ? domain.length : 0;
        
      case 'subdomain_to_domain_ratio':
        return this.calculateFeature('subdomain_count', url, parsedUrl, domainParts) / Math.max(domain ? domain.length : 0, 1);
        
      case 'multiple_tlds':
        return (url.split('.').length > 2 && url.match(/\.[a-z]{2,4}\./g) !== null) ? 1 : 0;
        
      case 'has_https_in_path':
        return path.toLowerCase().includes('https') ? 1 : 0;
        
      case 'host_contains_digits':
        return /\d/.test(hostname) ? 1 : 0;
        
      case 'entropy': {
        const chars = Array.from(url);
        const len = chars.length;
        if (len === 0) return 0;
        
        const freqMap = {};
        for (const c of chars) {
          freqMap[c] = (freqMap[c] || 0) + 1;
        }
        
        let entropy = 0;
        for (const c in freqMap) {
          const p = freqMap[c] / len;
          entropy -= p * Math.log2(p);
        }
        return entropy;
      }
        
      case 'domain_only_length':
        return hostname.length;
        
      case 'keyword_in_domain':
        return this.suspiciousKeywords.reduce((count, kw) => 
          count + (hostname.toLowerCase().includes(kw) ? 1 : 0), 0);
        
      case 'keyword_in_path':
        return this.suspiciousKeywords.reduce((count, kw) => 
          count + (path.toLowerCase().includes(kw) ? 1 : 0), 0);
        
      case 'keyword_in_query':
        return this.suspiciousKeywords.reduce((count, kw) => 
          count + (query.toLowerCase().includes(kw) ? 1 : 0), 0);
        
      case 'meaningful_words_ratio': {
        // Empty paths are considered safe
        if (!path || path === '/') return 1.0;
        
        // Extract words using same regex pattern as Python
        const words = path.toLowerCase().match(/[a-z]+/g);
        if (!words) return 1.0;  // No words means no suspicious words
        
        // Count meaningful words exactly like Python
        const meaningfulWords = words.filter(word => this.dictionaryWords.has(word) && word.length > 2).length;
        
        return meaningfulWords / words.length;
      }
        
      case 'is_domain_in_dictionary':
        return this.dictionaryWords.has(domain.toLowerCase()) ? 1 : 0;
        
      case 'is_common_tld':
        return this.commonTlds.has(tld.toLowerCase()) ? 1 : 0;
        
      case 'domain_entropy': {
        if (!domain) return 0;
        // Calculate Shannon entropy of the domain
        const chars = Array.from(domain);
        const len = chars.length;
        if (len === 0) return 0;
        
        const freqMap = {};
        for (const c of chars) {
          freqMap[c] = (freqMap[c] || 0) + 1;
        }
        
        let entropy = 0;
        for (const c in freqMap) {
          const p = freqMap[c] / len;
          entropy -= p * Math.log2(p);
        }
        return entropy;
      }
        
      case 'path_entropy':
        if (!path) return 0;
        const uniquePathChars = new Set(path).size;
        return uniquePathChars / path.length;
        
      case 'max_consecutive_consonants': {
        if (!domain) return 0;
        const consonants = "bcdfghjklmnpqrstvwxyz";
        let maxConsecutive = 0;
        let currentCount = 0;
        
        for (const c of domain.toLowerCase()) {
          if (consonants.includes(c)) {
            currentCount++;
            maxConsecutive = Math.max(maxConsecutive, currentCount);
          } else {
            currentCount = 0;
          }
        }
        return maxConsecutive;
      }
        
      case 'has_punycode':
        return hostname.startsWith('xn--') ? 1 : 0;
        
      case 'lexical_diversity':
        if (!url) return 0;
        const uniqueChars = new Set(url).size;
        return uniqueChars / url.length;
        
      case 'url_structure_pattern': {
        if (!path) return 0;
        const pathSegments = path.split('/').filter(s => s);
        if (pathSegments.length === 0) return 0;
        
        // Special case for search pages (needs to match Python implementation)
        if (path.toLowerCase().includes('search')) {
          return 0.67;
        }
        
        // Use language codes directly from model metadata
        const languageCodes = modelData.constants.languageCodes || [];
        const hasLangPrefix = pathSegments[0] && languageCodes.includes(pathSegments[0].toLowerCase()) ? 1 : 0;
        
        const hasHierarchicalStructure = pathSegments.length >= 2 && !path.includes('-') ? 1 : 0;
        
        // Use content indicators directly from model metadata
        const contentIndicators = modelData.constants.contentIndicators || [];
        const hasContentIndicator = contentIndicators.some(indicator => path.toLowerCase().includes(indicator)) ? 1 : 0;
        
        return (hasLangPrefix + hasHierarchicalStructure + hasContentIndicator) / 3;
      }
        
      case 'is_restricted_tld': {
        if (!tld) return 0;
        const tldParts = tld.split('.');
        const lastPart = tldParts[tldParts.length - 1].toLowerCase();
        const secondLast = tldParts.length > 1 ? tldParts[tldParts.length - 2].toLowerCase() : '';
        
        return (
          this.restrictedTlds.has(tld.toLowerCase()) ||
          this.restrictedTlds.has(lastPart) ||
          (secondLast && this.restrictedTlds.has(secondLast))
        ) ? 1 : 0;
      }
        
      case 'has_official_terms': {
        const officialTermCount = Array.from(this.officialTerms)
          .filter(term => url.toLowerCase().includes(term)).length;
        return Math.min(1.0, officialTermCount / 10);
      }
        
      case 'has_media_terms': {
        const mediaTermCount = Array.from(this.mediaTerms)
          .filter(term => url.toLowerCase().includes(term)).length;
        return Math.min(1.0, mediaTermCount / 10);
      }
      
      case 'path_semantic_score': {
        // Empty paths are considered to have no semantic meaning
        if (!path || path === '/') return 0;
        
        // Extract words using same regex pattern as Python
        const words = path.toLowerCase().match(/[a-z]+/g);
        if (!words) return 0;  // No words means no semantic score
        
        // Get common patterns from model metadata
        const commonPatterns = modelMetadata.constants.commonPatterns;
        
        // Score based on meaningful words (reuse meaningful_words_ratio logic)
        const meaningfulRatio = this.calculateFeature('meaningful_words_ratio', url, parsedUrl, domainParts);
        
        // Score based on common patterns
        const patternScore = words.filter(word => 
          commonPatterns.includes(word)).length / Math.max(words.length, 1);
        
        // Combine scores exactly like in Python
        return (meaningfulRatio + patternScore) / 2;
      }

      case 'readability_score': {
        if (!url) return 0;
        
        // Count proportion of special characters that interrupt reading
        const specialChars = Array.from(url).filter(c => '~`!@#$%^&*()_+={}[]|\\:;"<>,.?/'.includes(c)).length;
        const specialCharRatio = specialChars / url.length;
        
        // Check for excessive numbers (phishing sites often have random numbers)
        const digitRatio = Array.from(url).filter(c => /\d/.test(c)).length / url.length;
        
        // Calculate average word length (very long "words" in URLs are often suspicious)
        const words = url.toLowerCase().match(/[a-z]+/g) || [];
        // Calculate total length of all words
        let totalWordLength = 0;
        for (const word of words) {
          totalWordLength += word.length;
        }
        // Calculate average word length
        const avgWordLen = words.length > 0 ? totalWordLength / words.length : 0;
        
        // Penalize words longer than 5 chars
        const wordLenScore = 1 - Math.min(Math.max((avgWordLen - 5) / 15, 0), 1);
        
        // Calculate final readability score
        const readability = 1 - ((specialCharRatio + digitRatio) / 2 + (1 - wordLenScore) / 2) / 2;
        return readability;
      }
      
      case 'is_popular_domain': {
        if (!domain || !tld) return 0;
        
        const fullDomain = `${domain}.${tld}`;
        return this.popularDomains.has(fullDomain.toLowerCase()) ? 1 : 0;
      }

      default:
        console.warn(`Unknown feature: ${featureName}`);
        return 0;
    }
  }
  
  /**
   * Check if a string is an IPv4 address
   */
  isIpAddress(str) {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipv4Regex.test(str)) return false;
    
    const octets = str.split('.');
    return octets.every(octet => {
      const num = parseInt(octet, 10);
      return num >= 0 && num <= 255;
    });
  }
}

// PhishingDetector class - uses URL features to predict phishing
class PhishingDetector {
  constructor() {
    this.featureExtractor = new URLFeatureExtractor();
    this.coefficients = [];
    this.intercept = 0;
    this.featureNames = [];
    
    // Auto-initialize
    this.initialized = false;
    this.initPromise = this.init();
  }
  
  // Initialize the detector with model data
  async init() {
    if (this.initialized) return this;
    
    try {
      await this.featureExtractor.init();
      const modelData = await loadModelMetadata();
      this.coefficients = modelData.coefficients;
      this.intercept = modelData.intercept;
      this.featureNames = modelData.feature_names;
      this.initialized = true;
      console.log("PhishingDetector initialized successfully");
    } catch (error) {
      console.error("Error initializing PhishingDetector:", error);
    }
    return this;
  }
  
  /**
   * Calculate the raw score for a URL
   * (equivalent to the SVM decision function)
   */
  async calculateRawScore(url) {
    const features = await this.featureExtractor.extractFeatures(url);
    let score = this.intercept;
    
    // Calculate dot product of features and coefficients
    for (let i = 0; i < this.featureNames.length; i++) {
      const featureName = this.featureNames[i];
      const value = features[featureName] || 0;
      const coefficient = this.coefficients[i];
      score += value * coefficient;
    }
    
    return score;
  }
  
  /**
   * Convert raw score to probability using sigmoid function
   * Matches Python's sigmoid implementation
   */
  sigmoid(x) {
    return 1 / (1 + Math.exp(-Math.abs(x)));  // Match Python's implementation using absolute value
  }
  
  /**
   * Calculate phishing probability using sigmoid (without abs)
   * This matches the Python implementation exactly
   */
  calculatePhishingProbability(x) {
    return 1 / (1 + Math.exp(-x));  // Direct sigmoid without abs() to match Python
  }
  
  /**
   * Predict if a URL is phishing or not
   */
  async predict(url) {
    // Make sure we're initialized
    if (!this.initialized) {
      await this.initPromise;
    }
    
    try {
      const features = await this.featureExtractor.extractFeatures(url);
      const rawScore = await this.calculateRawScore(url);
      const probability = this.sigmoid(rawScore);
      const phishingProbability = this.calculatePhishingProbability(rawScore);
      
      // Filter features to only include those used by the model
      const modelFeatures = {};
      for (const name of this.featureNames) {
        modelFeatures[name] = features[name];
      }
      
      return {
        isPhishing: rawScore > 0,
        score: rawScore,
        probability,
        phishingProbability,
        features: modelFeatures  // Only return the features used in the model
      };
    } catch (error) {
      console.error("Error in predict:", error);
      return {
        isPhishing: false,
        score: 0,
        probability: 0,
        phishingProbability: 0,
        features: {},
        error: error.message
      };
    }
  }
  
  /**
   * Get feature importance values for a URL
   */
  async getFeatureImportance(url) {
    // Make sure we're initialized
    if (!this.initialized) {
      await this.initPromise;
    }
    
    try {
      const features = await this.featureExtractor.extractFeatures(url);
      const importance = [];
      
      for (let i = 0; i < this.featureNames.length; i++) {
        const featureName = this.featureNames[i];
        const value = features[featureName] || 0;
        const coefficient = this.coefficients[i];
        const impact = value * coefficient;
        
        importance.push({
          name: featureName,
          value,
          coefficient,
          impact: Math.abs(impact),
          contribution: impact > 0 ? "phishing" : "benign"
        });
      }
      
      // Sort by absolute impact
      return importance.sort((a, b) => b.impact - a.impact);
    } catch (error) {
      console.error("Error in getFeatureImportance:", error);
      return [];
    }
  }
}

export { URLFeatureExtractor, PhishingDetector, loadModelMetadata };
