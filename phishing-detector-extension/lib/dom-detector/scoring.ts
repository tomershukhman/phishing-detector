// Scoring utilities for DOM detector
import type { DomFeature } from "./types"
import { domLogger as logger } from "../logger"

// Calculate the final suspicious score from features
export function calculateSuspiciousScore(features: DomFeature[]): number {
  // Split into positive features (phishing indicators) and negative features (legitimate indicators)
  const phishingFeatures = features.filter(f => f.impact > 0);
  const legitimateFeatures = features.filter(f => f.impact < 0);
  
  // Calculate phishing score (positive indicators)
  let phishingScore = 0;
  let phishingWeightSum = 0;
  phishingFeatures.forEach(feature => {
    phishingScore += feature.impact * feature.weight;
    phishingWeightSum += feature.weight;
  });
  
  // Calculate legitimacy score (negative indicators, but take absolute value)
  let legitimacyScore = 0;
  let legitimacyWeightSum = 0;
  legitimateFeatures.forEach(feature => {
    // Use absolute value since negative impacts indicate legitimacy
    legitimacyScore += Math.abs(feature.impact) * feature.weight;
    legitimacyWeightSum += feature.weight;
  });
  
  // Get weighted sum of absolute impacts (to determine total signal strength)
  let totalWeightedImpact = 0;
  features.forEach(feature => {
    totalWeightedImpact += Math.abs(feature.impact) * feature.weight;
  });
  
  // Get total weight
  let totalWeight = 0;
  features.forEach(feature => {
    totalWeight += feature.weight;
  });
  
  // Calculate direct weighted average (this now accounts for positive and negative together)
  // Don't separate by type, just calculate the true weighted average of impacts
  // Give special treatment to invisible element features as they are very strong indicators
  let weightedAvgImpact = 0;
  if (totalWeight > 0) {
    let rawWeightedImpact = 0;
    
    // Check for presence of invisible element features which are high-confidence indicators
    const invisibleInputsFeature = features.find(f => f.name === "hasInvisibleInputFields");
    const hasInvisibleInputs = invisibleInputsFeature && invisibleInputsFeature.value === true;
    const transparentOverlaysFeature = features.find(f => f.name === "hasTransparentOverlays");
    const hasTransparentOverlays = transparentOverlaysFeature && transparentOverlaysFeature.value === true;
    
    // If we have strong invisible element signals that are highly specific to phishing,
    // boost the overall score but be careful not to trigger on legitimate sites
    const hasSuspiciousInvisibleCredentials = features.find(f => f.name === "hasSuspiciousInvisibleCredentialInputs")?.value === true;
    const hasOverlappingInputTraps = features.find(f => f.name === "hasOverlappingInputTraps")?.value === true;
    const hasSuspiciousOverlays = features.find(f => f.name === "hasSuspiciousTransparentOverlays")?.value === true;
    
    if (hasSuspiciousInvisibleCredentials || hasOverlappingInputTraps || hasSuspiciousOverlays) {
      // Apply a targeted boost to the weighted impact calculation
      features.forEach(feature => {
        // Apply extra weight only to the highly-specific invisible features
        if (
          feature.name === "hasSuspiciousInvisibleCredentialInputs" || 
          feature.name === "hasOverlappingInputTraps" || 
          feature.name === "hasSuspiciousTransparentOverlays"
        ) {
          // Higher boost for more reliable indicators
          const boost = feature.name === "hasOverlappingInputTraps" ? 1.8 : 1.5; // Overlapping inputs are strongest signal
          rawWeightedImpact += feature.impact * feature.weight * boost;
        } else {
          rawWeightedImpact += feature.impact * feature.weight;
        }
      });
    } else {
      // Standard calculation without invisible elements
      features.forEach(feature => {
        rawWeightedImpact += feature.impact * feature.weight;
      });
    }
    
    weightedAvgImpact = rawWeightedImpact / totalWeight;
  }
  
  // weightedAvgImpact is now between -1 and 1, transform to 0-1 range
  // Apply a sigmoid-like function to better separate clear cases
  // This will push strong legitimacy signals closer to 0 and strong phishing signals closer to 1
  
  // Start with basic transformation from [-1,1] to [0,1]
  let basicScore = (weightedAvgImpact + 1) / 2;
  
  // Get information about feature counts and their total impacts
  const legitimateRatio = legitimateFeatures.length / features.length;
  const phishingRatio = phishingFeatures.length / features.length;
  
  // Calculate the total impact strength of each type of feature
  let phishingImpactSum = 0;
  let legitimateImpactSum = 0;
  
  phishingFeatures.forEach(f => phishingImpactSum += f.impact * f.weight);
  legitimateFeatures.forEach(f => legitimateImpactSum += Math.abs(f.impact) * f.weight);
  
  // Find the ratio of total impact (not just count)
  const totalImpactSum = phishingImpactSum + legitimateImpactSum;
  const phishingImpactRatio = totalImpactSum > 0 ? phishingImpactSum / totalImpactSum : 0;
  const legitimateImpactRatio = totalImpactSum > 0 ? legitimateImpactSum / totalImpactSum : 0;
  
  // Calculate average impact per feature category
  const avgPhishingImpact = phishingFeatures.length > 0 ? 
    phishingImpactSum / phishingFeatures.length : 0;
  const avgLegitimateImpact = legitimateFeatures.length > 0 ? 
    legitimateImpactSum / legitimateFeatures.length : 0;
  
  let finalScore = basicScore;
  
  // Adjust the thresholds to be more sensitive to phishing signals while maintaining accurate benign scoring
  if (legitimateRatio > 0.7 && basicScore < 0.5) {
    // Heavy pull toward 0 for sites with many legitimate features
    const pullFactor = Math.pow(legitimateRatio, 2);
    finalScore = basicScore * (1 - pullFactor * 0.5);
  } 
  // Enhanced phishing detection - use multiple conditions to catch different phishing patterns
  else if (
    // Condition 1: Significant number of phishing features and basic score above threshold
    (phishingRatio > 0.4 && basicScore > 0.5) || 
    // Condition 2: Strong phishing impact ratio regardless of feature count
    (phishingImpactRatio > 0.35 && basicScore > 0.5) ||
    // Condition 3: Few but very strong phishing indicators (high average impact)
    (phishingFeatures.length > 0 && avgPhishingImpact > 0.6 && basicScore > 0.45) ||
    // Condition 4: Extreme imbalance where phishing impact overwhelms legitimate impact
    (phishingImpactSum > legitimateImpactSum * 1.5 && basicScore > 0.45)
  ) {
    // Enhanced pull toward 1 for sites with significant phishing features
    // Use the stronger of the two ratios for more aggressive phishing detection
    const pullFactor = Math.pow(Math.max(phishingRatio, phishingImpactRatio), 2);
    // More aggressive adjustment for stronger phishing signals
    const adjustmentStrength = 0.7;
    finalScore = basicScore + (1 - basicScore) * pullFactor * adjustmentStrength;
  }
  
  // Log for debugging
  logger.debug("DOM detector scoring calculations:", {
    phishingFeaturesCount: phishingFeatures.length,
    legitimateFeaturesCount: legitimateFeatures.length,
    weightedAvgImpact,
    basicScore,
    legitimateRatio,
    phishingRatio,
    phishingImpactRatio,
    legitimateImpactRatio,
    avgPhishingImpact,
    avgLegitimateImpact,
    finalScore
  });
  
  // Ensure the score is within 0-1 bounds
  return Math.max(0, Math.min(1, finalScore));
}
