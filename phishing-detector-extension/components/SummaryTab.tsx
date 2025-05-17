import React, { useEffect, useState } from "react";
import type { PhishingAnalysisResult } from "../combined-detector";
import { createMessageListener } from "../lib/messaging-utils";

interface SuspiciousWordsData {
  url: string;
  fraudTextScore: number;
  calculatedImpact?: number; // Made optional for backward compatibility
  categoryOccurrences: Record<string, number>;
  wordsByCategory: Record<string, Record<string, number>>;
  allDetectedWords: Record<string, number>;
}

interface SummaryTabProps {
  features: PhishingAnalysisResult;
  result: string | null;
  confidence: number | null;
  getRiskLevel: (score: number) => string;
  setActiveTab: (tab: 'summary' | 'url' | 'dom' | 'debug') => void;
  urlProbability: number | null;
  domProbability: number | null;
}

const SummaryTab: React.FC<SummaryTabProps> = ({
  features,
  result,
  confidence,
  getRiskLevel,
  setActiveTab,
  urlProbability: externalUrlProbability,
  domProbability
}) => {
  const [suspiciousWordsData, setSuspiciousWordsData] = useState<SuspiciousWordsData | null>(null);
  const [dataFetchStatus, setDataFetchStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');

  // Use the actual probability score from our model
  const urlProbability = externalUrlProbability !== null ?
    externalUrlProbability :
    (features.urlFeatures.phishingProbability || features.urlFeatures.probability || 0);

  // Get calculation details from the detector result if available
  const calcDetails = features.calculationDetails || {
    urlWeight: 1.0,
    urlScore: urlProbability,
    urlContribution: urlProbability,
    domWeight: domProbability ? 0.5 : undefined,
    domScore: domProbability || undefined,
    domContribution: domProbability ? domProbability * 0.5 : undefined
  };

  // Fetch and synchronize with suspicious words data
  useEffect(() => {
    // Skip if we've already fetched the data successfully
    if (dataFetchStatus === 'success' && suspiciousWordsData) {
      return;
    }

    let isMounted = true;
    setDataFetchStatus('loading');

    // Function to get stored data from the active tab
    const getStoredDataFromActiveTab = async () => {
      if (!isMounted) return;

      try {
        // Get the active tab
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tabs.length === 0 || !isMounted) return;

        // Execute a script in the tab to retrieve the stored data
        const results = await chrome.scripting.executeScript({
          target: { tabId: tabs[0].id as number },
          func: () => {
            // Only request a refresh if we're specifically asking for data in SummaryTab
            if (!localStorage.getItem('phishing_detector_suspicious_words_sent')) {
              localStorage.setItem('phishing_detector_suspicious_words_refresh_requested', 'true');
            }

            const storedData = localStorage.getItem('phishing_detector_suspicious_words');
            return storedData ? JSON.parse(storedData) : null;
          }
        });

        // Check if we got valid data and update the state
        const data = results[0]?.result;
        if (data && isMounted) {
          // Only log once with minimal info
          console.debug("[SummaryTab] Retrieved suspicious words data");
          setSuspiciousWordsData(data);
          setDataFetchStatus('success');
        } else if (isMounted) {
          setDataFetchStatus('error');
        }
      } catch (error) {
        if (isMounted) {
          console.error("[SummaryTab] Error retrieving suspicious words data:", error);
          setDataFetchStatus('error');
        }
      }
    };

    // Listen for messages from content script using the centralized utility
    const handleMessage = (message: any, sender: any, sendResponse: (response?: any) => void) => {
      if (!isMounted) return false;

      if (message.type === "SUSPICIOUS_WORDS_DATA" || message.type === "SUSPICIOUS_WORDS_DATA_UPDATED") {
        // Log minimally to avoid console flooding
        console.debug(`[SummaryTab] Received ${message.type}`);
        setSuspiciousWordsData(message.data);
        setDataFetchStatus('success');

        // Let the sender know we processed the message
        sendResponse({ received: true });
        return true;
      }

      return false; // Let other handlers process this message
    };

    // Set up a timeout for data fallback
    const timeoutId = setTimeout(() => {
      if (dataFetchStatus === 'loading' && isMounted) {
        console.debug("[SummaryTab] Data fetch timeout, using feature data directly");
        setDataFetchStatus('error');
      }
    }, 2000);

    // Get initial data when tab opens
    getStoredDataFromActiveTab();

    // Add listener for messages from content script using our utility
    const messageListener = createMessageListener(handleMessage);

    // Clean up listener and timeout on unmount
    return () => {
      isMounted = false;
      clearTimeout(timeoutId);
      chrome.runtime.onMessage.removeListener(messageListener);
    };
  }, [dataFetchStatus, suspiciousWordsData]); // Run only when fetch status changes

  // Check if we have updated calculatedImpact from suspicious words data
  // This ensures we're showing the most accurate information in the summary tab
  const domFeatures = features?.domFeatures?.features || [];
  const updatedDomFeatures = [...domFeatures];

  // Update fraudTextScore feature with latest calculatedImpact if available
  if (suspiciousWordsData?.calculatedImpact && suspiciousWordsData.calculatedImpact !== 0) {
    const fraudTextFeatureIndex = updatedDomFeatures.findIndex(f => f.name === 'fraudTextScore');
    if (fraudTextFeatureIndex >= 0) {
      const updatedFeature = { ...updatedDomFeatures[fraudTextFeatureIndex] };
      updatedFeature.impact = suspiciousWordsData.calculatedImpact;
      updatedDomFeatures[fraudTextFeatureIndex] = updatedFeature;
    }
  }

  // Determine URL risk level
  const urlRiskLevel = getRiskLevel(urlProbability);

  const getColorForRiskLevel = (level: string) => {
    switch (level) {
      case 'high': return '#ff5555';
      case 'low': return '#ffaa55';
      case 'safe': return '#55aa55';
      default: return '#888888';
    }
  };

  const urlColor = getColorForRiskLevel(urlRiskLevel);
  const resultColor = result === 'phishing' ? '#ff5555' : (result === 'safe' ? '#55aa55' : '#888888');

  return (
    <div className="summary-tab">
      <h3>Analysis Summary</h3>

      <div className="result-box" style={{ backgroundColor: resultColor }}>
        <div className="result-title">
          {result === 'phishing' ? 'PHISHING' :
            (result === 'safe' ? 'SAFE' : 'ANALYSIS ERROR')}
        </div>
        <div className="result-confidence">
          {features?.confidence !== null ? `Confidence: ${features?.confidence || confidence || 0}%` : 
          'Confidence: Waiting for complete analysis...'}
        </div>
      </div>

      <div className="analysis-components">
        <h4>Analysis Components</h4>

        <div className="component-box">
          <div className="component-header">
            <div className="component-title">URL Analysis</div>
            <div className="component-indicator" style={{ backgroundColor: urlColor }}></div>
          </div>
          <div className="component-details">
            <div><strong>Risk Level:</strong> <span style={{ color: urlColor }}>{urlRiskLevel.toUpperCase()}</span></div>
            <div><strong>Score:</strong> {(urlProbability * 100).toFixed(2)}%</div>
            <div><strong>Weight:</strong> {(calcDetails.urlWeight * 100).toFixed(0)}%</div>
            <div><strong>Contribution:</strong> {(calcDetails.urlContribution * 100).toFixed(2)}%</div>
          </div>
        </div>

        {domProbability !== null && calcDetails.domWeight !== undefined && (
          <div className="component-box">
            <div className="component-header">
              <div className="component-title">DOM Analysis</div>
              <div className="component-indicator" style={{
                backgroundColor: domProbability >= 0.5 ? 'var(--danger-color)' : 'var(--safe-color)'
              }}></div>
            </div>
            <div className="component-details">
              <div>
                <strong>Risk Level:</strong>
                <span style={{
                  color: domProbability >= 0.5 ? 'var(--danger-color)' : 'var(--safe-color)'
                }}>
                  {getRiskLevel(domProbability).toUpperCase()}
                </span>
              </div>
              <div><strong>Score:</strong> {(domProbability * 100).toFixed(2)}%</div>
              <div><strong>Weight:</strong> {(calcDetails.domWeight * 100).toFixed(0)}%</div>
              <div><strong>Contribution:</strong> {(calcDetails.domContribution * 100).toFixed(2)}%</div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default SummaryTab;
