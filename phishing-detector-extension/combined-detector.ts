// Combined phishing detector with URL and DOM analysis
import { PhishingDetector } from './model';
import type { FeatureVector } from './model';
import type { DomFeatures } from './dom-detector';
import { modelLogger as logger } from './lib/logger';

export interface PhishingAnalysisResult {
  isPhishing: boolean;
  urlDetectorResult: boolean;
  domDetectorResult?: boolean;
  confidence: number | null;  // Can be null if both URL and DOM results are not available
  url: string;
  urlFeatures: any;
  domFeatures?: DomFeatures;
  autoAnalyzed?: boolean;
  // Add calculation details for display
  calculationDetails?: {
    urlWeight: number;
    urlScore: number;
    urlContribution: number;
    domWeight?: number;
    domScore?: number;
    domContribution?: number;
  };
}

// Main function to analyze a URL for phishing
export async function analyzeForPhishing(url: string, domFeatures?: DomFeatures): Promise<PhishingAnalysisResult> {
  logger.log("ANALYZING URL FOR PHISHING", url);

  // 1. Analyze URL using ML model
  const detector = new PhishingDetector();
  const urlAnalysis = detector.predict(url);
  const urlResult = urlAnalysis.isPhishing;
  const probability = urlAnalysis.probability;
  const phishingProbability = urlAnalysis.phishingProbability;
  const features = urlAnalysis.features;

  // Get feature importance analysis
  const featureImportance = detector.getFeatureImportance(url);

  // Get top 5 contributing features
  const topFeatures = featureImportance
    .filter(f => f.contribution === "phishing")
    .slice(0, 5)
    .map(f => ({ name: f.name, value: f.value, impact: f.impact }));

  // Get keywords found in URL
  const suspiciousKeywords = ['login', 'signin', 'bank', 'account', 'update', 'verify', 'secure', 'password'];
  const suspiciousKeywordsFound = suspiciousKeywords.filter(kw => url.toLowerCase().includes(kw));

  // Create structured URL features for output
  const urlFeatures = {
    url,
    features: urlAnalysis.features,
    topContributingFeatures: topFeatures,
    suspiciousKeywordsFound,
    probability,
    phishingProbability,
    score: urlAnalysis.score
  };

  // URL score is directly from model probability (0-1 scale)
  const urlScore = phishingProbability || probability; // Use phishingProbability if available, otherwise use regular probability
  
  // Set weights - default to URL only if no DOM data
  let urlWeight = domFeatures ? 0.5 : 1.0;
  let domWeight = domFeatures ? 0.5 : 0.0;
  
  // Create calculation details object
  const calculationDetails: PhishingAnalysisResult["calculationDetails"] = {
    urlWeight,
    urlScore,
    urlContribution: urlScore * urlWeight
  };

  let domScore = 0;
  let finalScore = urlScore * urlWeight;
  let domResult = false;
  
  // If we have DOM features, incorporate them
  if (domFeatures) {
    // Check if we have error indicators instead of real features
    const hasErrorFeatures = domFeatures.features && domFeatures.features.some(f => 
      ["timeoutError", "communicationError", "invalidResponse", "exceptionError", 
       "analysisError", "criticalError", "fallbackMode", "unexpectedError"].includes(f.name)
    );
    
    // If we have error features, adjust the weights to rely more on URL analysis
    if (hasErrorFeatures) {
      logger.log("===== DOM ANALYSIS HAD ERRORS =====");
      // Reduce DOM weight significantly when we have errors
      calculationDetails.urlWeight = 0.9;
      calculationDetails.domWeight = 0.1;
      urlWeight = 0.9;
      domWeight = 0.1;
    } else {
      // Normal weighting when DOM analysis succeeded
      calculationDetails.domWeight = domWeight;
    }
    
    domScore = domFeatures.suspiciousScore;
    domResult = domScore >= 0.5;
    
    // Add DOM info to calculations
    calculationDetails.domScore = domScore;
    calculationDetails.domContribution = domScore * domWeight;
    
    // Combine the scores using weights
    finalScore = urlScore * urlWeight + domScore * domWeight;
    
    logger.log("===== DOM ANALYSIS RESULTS =====");
    logger.log("DOM Score:", { domScore });
    if (hasErrorFeatures) {
      logger.log("DOM Analysis had errors, relying more on URL analysis");
      logger.log("Adjusted weights", { urlWeight, domWeight });
    }
  }

  // Debug output
  logger.log("===== URL ANALYSIS RESULTS =====");
  logger.log("URL Score:", { urlScore });
  logger.log("===== COMBINED ANALYSIS =====");
  logger.log("Final Score:", { finalScore });

  // Check if both URL and DOM detectors have returned results
  const bothDetectorsComplete = urlResult !== undefined && domFeatures !== undefined;
  
  // Final result
  const result: PhishingAnalysisResult = {
    isPhishing: finalScore >= 0.5,  // 50% threshold
    urlDetectorResult: urlResult,
    domDetectorResult: domFeatures ? domResult : undefined,
    confidence: bothDetectorsComplete ? Math.round(finalScore * 100) : null, // Only set confidence when both URL and DOM results are available
    url,
    urlFeatures,
    domFeatures: domFeatures,
    autoAnalyzed: false,
    calculationDetails
  };

  return result;
}