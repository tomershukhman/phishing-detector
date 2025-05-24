// Example usage of the performance tracking functionality

import { analyzeForPhishing } from './combined-detector';

/**
 * Example showing how to use the performance-wrapped analysis function
 * This will automatically measure time and heap usage and send the data to the background script
 */
export async function exampleUsage() {
  const testUrl = "https://example.com";
  
  try {
    // This call will:
    // 1. Measure execution time and heap usage
    // 2. Run the phishing analysis
    // 3. Send performance data to background script with action 'TEST'
    // 4. Return the analysis result
    const result = await analyzeForPhishing(testUrl);
    
    console.log('Analysis completed:', {
      isPhishing: result.isPhishing,
      confidence: result.confidence,
      url: result.url
    });
    
    // The performance data is automatically sent to background script:
    // {
    //   action: 'TEST',
    //   data: {
    //     url: window.location.href,
    //     groupId: 28,
    //     isPhishing: result.isPhishing,
    //     responseTimeMs: measurementResult.duration,
    //     heapChangeBytes: measurementResult.heapUsed
    //   }
    // }
    
    return result;
  } catch (error) {
    console.error('Analysis failed:', error);
    throw error;
  }
}

/**
 * You can also use the original function directly if you don't need performance tracking
 */
export async function exampleDirectUsage() {
  const { analyzeForPhishing } = await import('./combined-detector');
  
  const testUrl = "https://example.com";
  const result = await analyzeForPhishing(testUrl);
  
  return result;
}
