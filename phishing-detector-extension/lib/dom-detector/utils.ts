// DOM detector utility functions

// Helper function to detect login forms
export function detectLoginForm(): boolean {
  // Look for password fields
  const passwordField = document.querySelector('input[type="password"]');
  if (!passwordField) return false;
  
  // Find the form containing this password field
  const form = passwordField.closest('form');
  if (!form) return true; // Password field without a proper form is suspicious
  
  // Check for username/email field
  const hasUserField = !!form.querySelector('input[type="text"], input[type="email"]');
  
  // Check for submit button
  const hasSubmitButton = !!form.querySelector('input[type="submit"], button[type="submit"], button');
  
  return hasUserField && hasSubmitButton;
}

// Helper to extract domain name from hostname
export function extractDomainName(hostname: string): string {
  if (!hostname) return '';
  
  const parts = hostname.toLowerCase().split('.');
  
  // Handle special cases for multi-part TLDs (like .co.uk)
  if (parts.length > 2) {
    // Check for country-specific second-level domains
    const potentialSLDs = ['co', 'com', 'org', 'net', 'ac', 'gov', 'edu'];
    if (parts.length > 2 && potentialSLDs.includes(parts[parts.length - 2])) {
      // For things like example.co.uk, return "example"
      return parts[parts.length - 3];
    }
    // For normal subdomains like support.example.com, return "example"
    return parts[parts.length - 2];
  } else if (parts.length === 2) {
    // For example.com, return "example"
    return parts[0];
  }
  
  // Fallback for unusual cases
  return hostname;
}
