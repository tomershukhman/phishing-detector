/**
 * Debug utilities for DOM detector
 * Use these functions to make DOM detector logs more visible in the console
 */
import { domLogger } from "../logger";

/**
 * Log a message with higher visibility in the console
 * This can help when debugging DOM detector issues
 */
export function logHighlighted(message: string, data?: any): void {
  // Use console.warn for higher visibility (no styling)
  console.warn(`[DOM DETECTOR] ${message}`, data);
  
  // Also log through the regular logger
  domLogger.log(message, data);
}

/**
 * Execute a DOM detector test and log the results
 */
export function runDiagnostic(): void {
  logHighlighted('Running DOM detector diagnostic', { timestamp: new Date().toISOString() });
  
  try {
    // Log DOM structure stats
    const forms = document.forms.length;
    const inputs = document.querySelectorAll('input').length;
    const links = document.querySelectorAll('a').length;
    const iframes = document.querySelectorAll('iframe').length;
    
    logHighlighted('DOM structure', { forms, inputs, links, iframes });
    
    // Check if logger is working
    domLogger.log('DOM logger test from diagnostic', { test: true });
    domLogger.warn('DOM logger warning test', { test: true });
    domLogger.error('DOM logger error test', { test: true });
    
    logHighlighted('Diagnostic completed successfully');
  } catch (error) {
    logHighlighted('Diagnostic failed', { error: error.message });
  }
}

/**
 * Ensure that all logs from the DOM detector are visible
 * This function modifies the console to highlight DOM detector logs
 */
export function enhanceDomLogging(): void {
  logHighlighted('Enhancing DOM detector logging');
  
  const originalConsole = {
    log: console.log,
    warn: console.warn,
    error: console.error,
    debug: console.debug
  };
  
  // Replace console.log to detect DOM detector logs
  console.log = function(...args) {
    if (args[0] && typeof args[0] === 'string' && args[0].includes('[PHISHING-DETECTOR-DOM]')) {
      // Use normal log without styling
      originalConsole.log(args[0], ...args.slice(1));
      
      // Try to forward to background
      try {
        if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime.sendMessage({
            action: "forwardLog",
            logData: {
              component: 'DOM',
              level: 'INFO',
              message: args[0],
              data: args.length > 1 ? args[1] : undefined,
              timestamp: new Date().toISOString()
            }
          });
        }
      } catch (e) {
        // Silent fail for logging
      }
    } else {
      originalConsole.log(...args);
    }
  };
  
  // Similar for error logs
  console.error = function(...args) {
    if (args[0] && typeof args[0] === 'string' && args[0].includes('[PHISHING-DETECTOR-DOM]')) {
      originalConsole.error(args[0], ...args.slice(1));
      
      // Try to forward
      try {
        if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime.sendMessage({
            action: "forwardLog",
            logData: {
              component: 'DOM',
              level: 'ERROR',
              message: args[0],
              data: args.length > 1 ? args[1] : undefined,
              timestamp: new Date().toISOString()
            }
          });
        }
      } catch (e) {
        // Silent fail
      }
    } else {
      originalConsole.error(...args);
    }
  };
  
  logHighlighted('DOM detector logging enhanced');
}
