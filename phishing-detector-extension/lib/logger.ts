// Centralized logger for phishing detector extension
// Provides consistent logging format across all components

// Log levels
enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3
}

// Logger interface
interface LoggerOptions {
  component: string; // Component name (BG, CONTENT, DOM, MODEL, etc.)
  minLevel?: LogLevel; // Minimum log level to output
}

// Create a logger instance
const createLogger = (options: LoggerOptions) => {
  const { component, minLevel = LogLevel.INFO } = options;
  
  // Common prefix format for all logs
  const prefix = `[PHISHING-DETECTOR-${component}]`;

  // Enhanced logging with console styling to make logs more visible

  // Helper function to send logs to background if in a content script context
  const sendToBackground = (level: string, message: string, data?: any) => {
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
    debug: (message: string, data?: any) => {
      if (minLevel <= LogLevel.DEBUG) {
        const formattedMessage = `${prefix}[${new Date().toISOString()}] ${message}`;
        if (data) {
          console.debug(`%c${formattedMessage}`, data);
        } else {
          console.debug(`%c${formattedMessage}`,);
        }
        sendToBackground('DEBUG', message, data);
      }
    },
    
    log: (message: string, data?: any) => {
      if (minLevel <= LogLevel.INFO) {
        const formattedMessage = `${prefix}[${new Date().toISOString()}] ${message}`;
        if (data) {
          console.log(`%c${formattedMessage}`, data);
        } else {
          console.log(`%c${formattedMessage}`);
        }
        sendToBackground('INFO', message, data);
      }
    },
    
    warn: (message: string, data?: any) => {
      if (minLevel <= LogLevel.WARN) {
        const formattedMessage = `${prefix}[${new Date().toISOString()}] ${message}`;
        if (data) {
          console.warn(`%c${formattedMessage}`, data);
        } else {
          console.warn(`%c${formattedMessage}`);
        }
        sendToBackground('WARN', message, data);
      }
    },
    
    error: (message: string, data?: any) => {
      if (minLevel <= LogLevel.ERROR) {
        const formattedMessage = `${prefix}[${new Date().toISOString()}] ${message}`;
        if (data) {
          console.error(`%c${formattedMessage}`, data);
        } else {
          console.error(`%c${formattedMessage}`);
        }
        sendToBackground('ERROR', message, data);
      }
    },
  };
};

// Pre-configured loggers for different components
export const backgroundLogger = createLogger({ component: 'BG' });
export const messageLogger = createLogger({ component: 'MSG' });
export const contentLogger = createLogger({ component: 'CONTENT' });
export const domLogger = createLogger({ component: 'DOM' });
export const modelLogger = createLogger({ component: 'MODEL' });
export const popupLogger = createLogger({ component: 'POPUP', minLevel: LogLevel.DEBUG });

// Utility function to create custom loggers
export function createCustomLogger(component: string, minLevel: LogLevel = LogLevel.INFO) {
  return createLogger({ component, minLevel });
}

// Default export for backward compatibility
export default {
  createLogger,
  backgroundLogger,
  messageLogger,
  contentLogger,
  domLogger,
  modelLogger,
  popupLogger,
  LogLevel
};
