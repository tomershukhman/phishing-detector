// General performance and utility functions for the phishing detector extension
import { createCustomLogger } from "./logger";

// Create a performance logger
const perfLogger = createCustomLogger('PERF');

/**
 * Wrapper function that measures both execution time and heap memory usage
 * @param fn - The function to execute and measure
 * @param fnName - Optional name for the function being measured (for logging)
 * @returns Object containing the result, timing, and memory data
 */
export function measureHeapAndTime<T>(fn: () => T, fnName?: string): {
  result: T;
  duration: number;
  heapBefore: number;
  heapAfter: number;
  heapUsed: number;
} {
  const functionName = fnName || 'unknown function';
  
  perfLogger.log(`Starting performance measurement for: ${functionName}`);
  
  // Check if heap measurement is available
  const heapAvailable = isHeapMeasurementAvailable();
  if (!heapAvailable) {
    perfLogger.warn(`Heap measurement not available for: ${functionName}`);
  }
  
  // Get initial heap size (if available in Chrome)
  const heapBefore = (performance as any).memory?.usedJSHeapSize || 0;
  
  perfLogger.log(`Initial heap before ${functionName}`, { 
    heapBefore: `${(heapBefore / 1024 / 1024).toFixed(2)} MB`,
    heapBeforeBytes: heapBefore 
  });
  
  // Measure execution time
  const startTime = performance.now();
  let result: T;
  let executionError: Error | null = null;
  
  try {
    result = fn();
    perfLogger.log(`Function ${functionName} executed successfully`);
  } catch (error) {
    executionError = error as Error;
    perfLogger.error(`Function ${functionName} threw an error`, { error: error.message });
    throw error;
  } finally {
    const endTime = performance.now();
    
    // Get final heap size (if available in Chrome)
    const heapAfter = (performance as any).memory?.usedJSHeapSize || 0;
    
    const duration = Math.round(endTime - startTime);
    const heapUsed = heapAfter - heapBefore;
    
    // Log detailed performance metrics
    perfLogger.log(`Performance measurement completed for: ${functionName}`, {
      duration: `${duration}ms`,
      heapAfter: `${(heapAfter / 1024 / 1024).toFixed(2)} MB`,
      heapAfterBytes: heapAfter,
      heapChange: `${heapUsed > 0 ? '+' : ''}${(heapUsed / 1024).toFixed(2)} KB`,
      heapChangeBytes: heapUsed,
      success: !executionError
    });
    
    // Log summary in a highlighted format
    const heapChangeStr = heapUsed > 0 ? `+${(heapUsed / 1024).toFixed(2)} KB` : `${(heapUsed / 1024).toFixed(2)} KB`;
    perfLogger.log(`📊 PERFORMANCE SUMMARY - ${functionName}: ${duration}ms, heap: ${heapChangeStr}`);
    
    return {
      result: result!,
      duration,
      heapBefore,
      heapAfter,
      heapUsed
    };
  }
}

/**
 * Async version of measureHeapAndTime for Promise-returning functions
 * @param fn - The async function to execute and measure
 * @param fnName - Optional name for the function being measured (for logging)
 * @returns Promise that resolves to object containing the result, timing, and memory data
 */
export async function measureHeapAndTimeAsync<T>(fn: () => Promise<T>, fnName?: string): Promise<{
  result: T;
  duration: number;
  heapBefore: number;
  heapAfter: number;
  heapUsed: number;
}> {
  const functionName = fnName || 'unknown async function';
  
  perfLogger.log(`Starting async performance measurement for: ${functionName}`);
  
  // Check if heap measurement is available
  const heapAvailable = isHeapMeasurementAvailable();
  if (!heapAvailable) {
    perfLogger.warn(`Heap measurement not available for: ${functionName}`);
  }
  
  // Get initial heap size (if available in Chrome)
  const heapBefore = (performance as any).memory?.usedJSHeapSize || 0;
  
  perfLogger.log(`Initial heap before ${functionName}`, { 
    heapBefore: `${(heapBefore / 1024 / 1024).toFixed(2)} MB`,
    heapBeforeBytes: heapBefore 
  });
  
  // Measure execution time
  const startTime = performance.now();
  let result: T;
  let executionError: Error | null = null;
  
  try {
    perfLogger.log(`Executing async function: ${functionName}`);
    result = await fn();
    perfLogger.log(`Async function ${functionName} completed successfully`);
  } catch (error) {
    executionError = error as Error;
    perfLogger.error(`Async function ${functionName} threw an error`, { error: error.message });
    throw error;
  } finally {
    const endTime = performance.now();
    
    // Get final heap size (if available in Chrome)
    const heapAfter = (performance as any).memory?.usedJSHeapSize || 0;
    
    const duration = Math.round(endTime - startTime);
    const heapUsed = heapAfter - heapBefore;
    
    // Log detailed performance metrics
    perfLogger.log(`Async performance measurement completed for: ${functionName}`, {
      duration: `${duration}ms`,
      heapAfter: `${(heapAfter / 1024 / 1024).toFixed(2)} MB`,
      heapAfterBytes: heapAfter,
      heapChange: `${heapUsed > 0 ? '+' : ''}${(heapUsed / 1024).toFixed(2)} KB`,
      heapChangeBytes: heapUsed,
      success: !executionError
    });
    
    // Log summary in a highlighted format
    const heapChangeStr = heapUsed > 0 ? `+${(heapUsed / 1024).toFixed(2)} KB` : `${(heapUsed / 1024).toFixed(2)} KB`;
    perfLogger.log(`📊 ASYNC PERFORMANCE SUMMARY - ${functionName}: ${duration}ms, heap: ${heapChangeStr}`);
    
    return {
      result: result!,
      duration,
      heapBefore,
      heapAfter,
      heapUsed
    };
  }
}

/**
 * Simple time measurement wrapper
 * @param fn - The function to execute and measure
 * @param fnName - Optional name for the function being measured (for logging)
 * @returns Object containing the result and timing data
 */
export function measureTime<T>(fn: () => T, fnName?: string): {
  result: T;
  duration: number;
} {
  const functionName = fnName || 'unknown function';
  
  perfLogger.log(`Starting time measurement for: ${functionName}`);
  
  const startTime = performance.now();
  let result: T;
  let executionError: Error | null = null;
  
  try {
    result = fn();
    perfLogger.log(`Function ${functionName} executed successfully`);
  } catch (error) {
    executionError = error as Error;
    perfLogger.error(`Function ${functionName} threw an error`, { error: error.message });
    throw error;
  } finally {
    const endTime = performance.now();
    const duration = Math.round(endTime - startTime);
    
    perfLogger.log(`Time measurement completed for: ${functionName}`, {
      duration: `${duration}ms`,
      success: !executionError
    });
    
    perfLogger.log(`⏱️  TIME SUMMARY - ${functionName}: ${duration}ms`);
    
    return {
      result: result!,
      duration
    };
  }
}

/**
 * Check if heap memory measurement is available in the current environment
 * @returns true if performance.memory is available (Chrome), false otherwise
 */
export function isHeapMeasurementAvailable(): boolean {
  const available = !!(performance as any).memory;
  perfLogger.log(`Heap measurement availability check`, { available });
  return available;
}

/**
 * Get current heap usage information if available
 * @returns Object with heap information or null if not available
 */
export function getCurrentHeapUsage(): {
  usedJSHeapSize: number;
  totalJSHeapSize: number;
  jsHeapSizeLimit: number;
} | null {
  const memory = (performance as any).memory;
  if (!memory) {
    perfLogger.warn(`Heap usage requested but performance.memory not available`);
    return null;
  }
  
  const heapInfo = {
    usedJSHeapSize: memory.usedJSHeapSize,
    totalJSHeapSize: memory.totalJSHeapSize,
    jsHeapSizeLimit: memory.jsHeapSizeLimit
  };
  
  perfLogger.log(`Current heap usage`, {
    used: `${(heapInfo.usedJSHeapSize / 1024 / 1024).toFixed(2)} MB`,
    total: `${(heapInfo.totalJSHeapSize / 1024 / 1024).toFixed(2)} MB`,
    limit: `${(heapInfo.jsHeapSizeLimit / 1024 / 1024).toFixed(2)} MB`,
    usagePercent: `${((heapInfo.usedJSHeapSize / heapInfo.totalJSHeapSize) * 100).toFixed(1)}%`
  });
  
  return heapInfo;
}
