// General performance and utility functions for the phishing detector extension

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
  // Get initial heap size (if available in Chrome)
  const heapBefore = (performance as any).memory?.usedJSHeapSize || 0;
  
  // Measure execution time
  const startTime = performance.now();
  const result = fn();
  const endTime = performance.now();
  
  // Get final heap size (if available in Chrome)
  const heapAfter = (performance as any).memory?.usedJSHeapSize || 0;
  
  const duration = Math.round(endTime - startTime);
  const heapUsed = heapAfter - heapBefore;
  
  // Optional logging
  if (fnName) {
    console.log(`[Performance] ${fnName}: ${duration}ms, heap: ${heapUsed > 0 ? '+' : ''}${heapUsed} bytes`);
  }
  
  return {
    result,
    duration,
    heapBefore,
    heapAfter,
    heapUsed
  };
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
  // Get initial heap size (if available in Chrome)
  const heapBefore = (performance as any).memory?.usedJSHeapSize || 0;
  
  // Measure execution time
  const startTime = performance.now();
  const result = await fn();
  const endTime = performance.now();
  
  // Get final heap size (if available in Chrome)
  const heapAfter = (performance as any).memory?.usedJSHeapSize || 0;
  
  const duration = Math.round(endTime - startTime);
  const heapUsed = heapAfter - heapBefore;
  
  // Optional logging
  if (fnName) {
    console.log(`[Performance] ${fnName}: ${duration}ms, heap: ${heapUsed > 0 ? '+' : ''}${heapUsed} bytes`);
  }
  
  return {
    result,
    duration,
    heapBefore,
    heapAfter,
    heapUsed
  };
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
  const startTime = performance.now();
  const result = fn();
  const endTime = performance.now();
  
  const duration = Math.round(endTime - startTime);
  
  // Optional logging
  if (fnName) {
    console.log(`[Performance] ${fnName}: ${duration}ms`);
  }
  
  return {
    result,
    duration
  };
}

/**
 * Check if heap memory measurement is available in the current environment
 * @returns true if performance.memory is available (Chrome), false otherwise
 */
export function isHeapMeasurementAvailable(): boolean {
  return !!(performance as any).memory;
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
  if (!memory) return null;
  
  return {
    usedJSHeapSize: memory.usedJSHeapSize,
    totalJSHeapSize: memory.totalJSHeapSize,
    jsHeapSizeLimit: memory.jsHeapSizeLimit
  };
}
