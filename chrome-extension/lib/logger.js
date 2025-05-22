// logger.js - Centralized logger for phishing detector extension
// Provides consistent logging format across all components

// Create a logger instance
function createLogger(options) {
  const { component, minLevel = 1 } = options;
  
  // Common prefix format for all logs
  const prefix = `[PHISHING-DETECTOR-${component}]`;

  // Helper function to send logs to background if in a content script context
  const sendToBackground = (level, message, data) => {
    // Only attempt to forward logs from content scripts (DOM component)
    if (component === 'DOM' && typeof chrome !== 'undefined' && chrome.runtime) {
      try {
        chrome.runtime.sendMessage({
          action: "forwardLog",
          logData: {
            component,
            level,
            message,
            data: data ? JSON.stringify(data) : undefined,
            timestamp: new Date().toISOString()
          }
        });
      } catch (e) {
        // Silent catch - this is just for logging
      }
    }
  };

  // Log functions for each level
  return {
    debug: (message, data) => {
      if (minLevel <= 0) {
        const formattedMessage = `${prefix}[${new Date().toISOString()}] ${message}`;
        if (data) {
          console.debug(formattedMessage, data);
        } else {
          console.debug(formattedMessage);
        }
        sendToBackground('DEBUG', message, data);
      }
    },
    
    log: (message, data) => {
      if (minLevel <= 1) {
        const formattedMessage = `${prefix}[${new Date().toISOString()}] ${message}`;
        if (data) {
          console.log(formattedMessage, data);
        } else {
          console.log(formattedMessage);
        }
        sendToBackground('INFO', message, data);
      }
    },
    
    warn: (message, data) => {
      if (minLevel <= 2) {
        const formattedMessage = `${prefix}[${new Date().toISOString()}] ${message}`;
        if (data) {
          console.warn(formattedMessage, data);
        } else {
          console.warn(formattedMessage);
        }
        sendToBackground('WARN', message, data);
      }
    },
    
    error: (message, data) => {
      if (minLevel <= 3) {
        const formattedMessage = `${prefix}[${new Date().toISOString()}] ${message}`;
        if (data) {
          console.error(formattedMessage, data);
        } else {
          console.error(formattedMessage);
        }
        sendToBackground('ERROR', message, data);
      }
    },
  };
}

// Pre-configured loggers for different components
const domLogger = createLogger({ component: 'DOM' });
const backgroundLogger = createLogger({ component: 'BG' });
const popupLogger = createLogger({ component: 'POPUP' });
const contentLogger = createLogger({ component: 'CONTENT' });
const modelLogger = createLogger({ component: 'MODEL' });
const messageLogger = createLogger({ component: 'MSG' });

// Export the loggers as ES modules
export {
  createLogger,
  domLogger,
  backgroundLogger,
  popupLogger,
  contentLogger,
  modelLogger,
  messageLogger
};
