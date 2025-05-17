// Forward log messages from content scripts to background
import type { PlasmoMessaging } from "@plasmohq/messaging";
import { messageLogger, backgroundLogger } from "../../lib/logger";

// Handle forwarded logs from content scripts (especially DOM detector)
const handler: PlasmoMessaging.MessageHandler = async (req, res) => {
  const { logData } = req.body;
  
  if (!logData) {
    res.send({ success: false, error: "No log data provided" });
    return;
  }
  
  const { component, level, message, data, timestamp } = logData;
  
  // Use the timestamp from the original log but format the message as a forwarded log
  const domLogPrefix = `[FORWARDED-${component}][${timestamp}]`;
  let parsedData;
  
  try {
    parsedData = data ? JSON.parse(data) : undefined;
  } catch (e) {
    parsedData = { rawData: data, parseError: true };
  }
  
  // Log using background logger to ensure visibility in extension console
  switch (level) {
    case 'DEBUG':
      backgroundLogger.debug(`${domLogPrefix} ${message}`, parsedData);
      break;
    case 'INFO':
      backgroundLogger.log(`${domLogPrefix} ${message}`, parsedData);
      break;
    case 'WARN':
      backgroundLogger.warn(`${domLogPrefix} ${message}`, parsedData);
      break;
    case 'ERROR':
      backgroundLogger.error(`${domLogPrefix} ${message}`, parsedData);
      break;
    default:
      backgroundLogger.log(`${domLogPrefix} ${message}`, parsedData);
  }
  
  // Also log a record that we received this forwarded log
  messageLogger.log(`Received forwarded log from ${component}`, { 
    level, 
    messagePreview: message.substring(0, 50) + (message.length > 50 ? '...' : '')
  });
  
  res.send({ success: true });
};

export default handler;
