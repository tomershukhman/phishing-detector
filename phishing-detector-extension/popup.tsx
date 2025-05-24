import React, { useEffect, useState, useRef } from "react"
import type { PhishingAnalysisResult } from "./combined-detector"
import { analyzeForPhishing } from "./combined-detector"
import "./popup.css"
import { getCurrentTabId, getCurrentTabUrl, getTabAnalysisData, analyzeUrlManually } from "./lib/messaging"
import { createMessageListener } from "./lib/messaging-utils"
import { requestSuspiciousWordsRefresh } from "./lib/suspicious-words-utils"

// Components
import Header from "./components/Header"
import ActionBar from "./components/ActionBar"
import SummaryTab from "./components/SummaryTab"

// Interface for suspicious words data
interface SuspiciousWordsData {
  url: string;
  fraudTextScore: number;
  calculatedImpact?: number;
  categoryOccurrences: Record<string, number>;
  wordsByCategory: Record<string, Record<string, number>>;
  allDetectedWords: Record<string, number>;
}

// Interface for background analysis data
interface BackgroundAnalysisData {
  url: string;
  result: PhishingAnalysisResult;
  timestamp: number;
  analysisElapsedTime?: number;
  totalElapsedTime?: number;
}

// Helper to get human-readable feature names
function getFeatureDisplayName(feature: string): string {
  const nameMap: Record<string, string> = {
    // URL feature names can be added here
  };

  return nameMap[feature] || feature;
}

// Helper for feature categories
function getFeatureCategory(feature: string): string {
  return "URL-related";
}

function IndexPopup() {
  const [url, setUrl] = useState("");
  const [tabId, setTabId] = useState<number | undefined>(undefined);
  const [result, setResult] = useState<string | null>(null);
  const [confidence, setConfidence] = useState<number | null>(null);
  const [features, setFeatures] = useState<PhishingAnalysisResult | null>(null);
  const [isLoading, setIsLoading] = useState(true); // Start as loading
  const [debugInfo, setDebugInfo] = useState<string[]>([]);
  const [urlProbability, setUrlProbability] = useState<number | null>(null);
  const [domProbability, setDomProbability] = useState<number | null>(null);
  const [analysisTimestamp, setAnalysisTimestamp] = useState<number>(0);
  const [suspiciousWordsData, setSuspiciousWordsData] = useState<SuspiciousWordsData | null>(null);
  const [dataInitialized, setDataInitialized] = useState<boolean>(false);
  const popupMountedRef = useRef<boolean>(false);
  // Add states for analysis timing
  const [analysisStartTime, setAnalysisStartTime] = useState<number>(0);
  const [analysisElapsedTime, setAnalysisElapsedTime] = useState<number | null>(null);

  useEffect(() => {
    popupMountedRef.current = true;

    // Get current tab information
    Promise.all([getCurrentTabUrl(), getCurrentTabId()]).then(([currentUrl, currentTabId]) => {
      if (!popupMountedRef.current) return;

      setUrl(currentUrl);
      setTabId(currentTabId);

      // Clear debug info and start fresh
      setDebugInfo([]);
      addDebugMessage(`Popup opened for URL: ${currentUrl}`);

      // Check if this tab has already been analyzed
      if (currentTabId) {
        // Set start time when beginning to check for analysis
        setAnalysisStartTime(Date.now());
        checkAndLoadTabAnalysis(currentUrl, currentTabId);

        // Also fetch suspicious words data immediately to ensure it's available for all tabs
        fetchSuspiciousWordsData(currentTabId);
      } else {
        setIsLoading(false);
        addDebugMessage("Unable to determine current tab ID");
      }
    });

    return () => {
      popupMountedRef.current = false;
    };
  }, []);

  // Function to fetch suspicious words data from the active tab
  const fetchSuspiciousWordsData = async (currentTabId: number) => {
    if (!popupMountedRef.current) return;

    try {
      addDebugMessage("Fetching suspicious words data...");

      // Execute a script in the tab to retrieve the stored data
      const results = await chrome.scripting.executeScript({
        target: { tabId: currentTabId },
        func: () => {
          // Request a refresh using the utility if available 
          if (typeof requestSuspiciousWordsRefresh === 'function') {
            requestSuspiciousWordsRefresh();
          } else {
            // Legacy fallback method
            localStorage.setItem('phishing_detector_suspicious_words_refresh_requested', 'true');
          }

          const storedData = localStorage.getItem('phishing_detector_suspicious_words');
          return storedData ? JSON.parse(storedData) : null;
        }
      });

      // Check if we got valid data and update the state
      const data = results[0]?.result;
      if (data && popupMountedRef.current) {
        addDebugMessage("Retrieved suspicious words data successfully");
        setSuspiciousWordsData(data);

        // If we have features but no suspicious words data with calculatedImpact,
        // try to get the latest impact from the DOM directly
        if (features?.domFeatures && (!data.calculatedImpact || data.calculatedImpact === 0)) {
          addDebugMessage("Missing calculatedImpact in suspicious words data, retrieving from DOM");
          refreshSuspiciousWordsData(currentTabId);
        }
      } else {
        addDebugMessage("No suspicious words data available");
      }
    } catch (error) {
      if (popupMountedRef.current) {
        console.error("Error retrieving suspicious words data:", error);
        addDebugMessage(`Error retrieving suspicious words data: ${error.message}`);
      }
    }
  };

  // Function to force a refresh of suspicious words data by executing a script in the page
  const refreshSuspiciousWordsData = async (tabId: number) => {
    if (!popupMountedRef.current) return;

    try {
      addDebugMessage("Refreshing suspicious words data from page...");
      await chrome.scripting.executeScript({
        target: { tabId },
        func: () => {
          // Request a refresh using the centralized utility
          if (typeof requestSuspiciousWordsRefresh === 'function') {
            // If the function is already available in the page context
            requestSuspiciousWordsRefresh();
          } else {
            // Legacy fallback method
            localStorage.setItem('phishing_detector_suspicious_words_refresh_requested', 'true');
          }

          // Request the page to recalculate and resend the suspicious words data
          const fraudTextFeature = document.querySelector('meta[name="phishing-detector-feature-fraudTextScore"]');
          if (fraudTextFeature) {
            const storedData = localStorage.getItem('phishing_detector_suspicious_words');
            if (storedData) {
              const data = JSON.parse(storedData);
              // Update calculatedImpact from the DOM feature if available
              const impact = fraudTextFeature.getAttribute('content');
              if (impact) {
                data.calculatedImpact = parseFloat(impact);
                localStorage.setItem('phishing_detector_suspicious_words', JSON.stringify(data));

                // Notify the extension that data has been updated
                chrome.runtime.sendMessage({
                  type: "SUSPICIOUS_WORDS_DATA_UPDATED",
                  data
                });
              }
            }
          }
        }
      });
      addDebugMessage("Suspicious words data refresh requested");
    } catch (error) {
      if (popupMountedRef.current) {
        console.error("Error refreshing suspicious words data:", error);
        addDebugMessage(`Error refreshing suspicious words data: ${error.message}`);
      }
    }
  };

  // Set up listener for suspicious words data messages
  useEffect(() => {
    if (!dataInitialized) {
      const handleMessage = (message: any, sender: any, sendResponse: (response?: any) => void) => {
        if (!popupMountedRef.current) return false;

        if (message.type === "SUSPICIOUS_WORDS_DATA" || message.type === "SUSPICIOUS_WORDS_DATA_UPDATED") {
          // Only log at debug level to avoid console flooding
          console.debug(`Received ${message.type}`);

          // Check if the data is actually different before updating
          const hasNewImpact = message.data.calculatedImpact !== suspiciousWordsData?.calculatedImpact;

          if (hasNewImpact) {
            addDebugMessage(`Received ${message.type} with updated impact: ${message.data.calculatedImpact}`);
            setSuspiciousWordsData(message.data);

            // If we have features, update the fraudTextScore feature with the new calculatedImpact
            if (features?.domFeatures && message.data.calculatedImpact) {
              updateFraudTextScoreImpact(message.data.calculatedImpact);
            }
          }

          // Acknowledge receipt of the message
          sendResponse({ received: true });
          return true;
        }

        return false; // Let other handlers process this message
      };

      // Add listener for messages from content script using our utility
      const messageListener = createMessageListener(handleMessage);
      setDataInitialized(true);

      // Clean up listener on unmount
      return () => {
        chrome.runtime.onMessage.removeListener(messageListener);
      };
    }
  }, [dataInitialized, features]);

  // Function to update the fraudTextScore feature's impact in the features state
  const updateFraudTextScoreImpact = (calculatedImpact: number) => {
    if (!popupMountedRef.current || !features?.domFeatures) return;

    addDebugMessage(`Updating fraudTextScore impact to ${calculatedImpact}`);

    // Create a deep copy of features
    const updatedFeatures = JSON.parse(JSON.stringify(features));

    // Find and update the fraudTextScore feature
    const fraudTextFeatureIndex = updatedFeatures.domFeatures.features.findIndex(
      (f: any) => f.name === 'fraudTextScore'
    );

    if (fraudTextFeatureIndex >= 0) {
      updatedFeatures.domFeatures.features[fraudTextFeatureIndex].impact = calculatedImpact;
      setFeatures(updatedFeatures);
      addDebugMessage("Updated features with new fraudTextScore impact");
    }
  };

  // Check for existing analysis and load it
  const checkAndLoadTabAnalysis = async (currentUrl: string, currentTabId: number) => {
    if (!popupMountedRef.current) return;

    try {
      addDebugMessage("Checking for analysis data...");

      // First check with the background script for stored analysis data
      const bgResponse = await getTabAnalysisData(currentTabId);

      if (bgResponse && bgResponse.success && bgResponse.data) {
        addDebugMessage("Found analysis data from background");

        // Cast to the interface to fix typing
        const analysisData = bgResponse.data as BackgroundAnalysisData;

        // If there's a timestamp in background data, use it
        if (analysisData.timestamp) {
          setAnalysisTimestamp(analysisData.timestamp);
          addDebugMessage(`Analysis was performed at: ${new Date(analysisData.timestamp).toLocaleString()}`);
        }

        // Use the existing analysis result
        if (analysisData.result) {
          processAnalysisResult(analysisData.result, true);

          // Calculate elapsed time if we have a timestamp
          if (analysisData.totalElapsedTime) {
            setAnalysisElapsedTime(analysisData.totalElapsedTime);
            addDebugMessage(`Analysis took ${analysisData.totalElapsedTime}ms to complete since page load`);
          } else if (analysisData.analysisElapsedTime) {
            setAnalysisElapsedTime(analysisData.analysisElapsedTime);
            addDebugMessage(`Analysis took ${analysisData.analysisElapsedTime}ms to complete (analysis process only)`);
          } else {
            setAnalysisElapsedTime(null);
          }

          addDebugMessage("Loaded pre-analyzed result from background");
        } else {
          // Fallback to running a new analysis
          handleCheck();
        }
      } else {
        // As a fallback, check directly with the content script
        addDebugMessage("No data in background, checking content script status...");

        try {
          // Send a message to the content script to check if analysis was done
          const contentResponse = await new Promise<any>((resolve, reject) => {
            chrome.tabs.sendMessage(currentTabId, {
              action: "getAnalysisStatus"
            }, response => {
              // Handle no response or error
              if (chrome.runtime.lastError) {
                reject(chrome.runtime.lastError);
                return;
              }
              resolve(response);
            });
          });

          // If content script reports analysis was done
          if (contentResponse && contentResponse.analyzed) {
            addDebugMessage("Page was analyzed according to content script");
            handleCheck(); // Re-run analysis to get the data
          } else {
            // No analysis data, run the check now
            addDebugMessage("No analysis found, running fresh check");
            handleCheck();
          }
        } catch (error) {
          addDebugMessage(`Content script check failed: ${error.message}`);
          // If we can't communicate with the content script, run a fresh analysis
          handleCheck();
        }
      }
    } catch (error) {
      if (popupMountedRef.current) {
        console.error("Error checking tab analysis:", error);
        addDebugMessage(`Error checking tab analysis: ${error.message}`);

        // Run a new analysis as fallback
        handleCheck();
      }
    }
  };

  const addDebugMessage = (message: string) => {
    setDebugInfo(prevInfo => [...prevInfo, `[${new Date().toLocaleTimeString()}] ${message}`]);
    console.debug(`[Popup] ${message}`);
  };

  const processAnalysisResult = (analysisResult: PhishingAnalysisResult, isAutoAnalyzed: boolean = false) => {
    if (!popupMountedRef.current) return;

    addDebugMessage(`Processing analysis result: ${analysisResult.isPhishing ? 'phishing' : 'safe'} (${analysisResult.confidence}% confidence)`);

    // Calculate elapsed time if we don't have it yet and we have a start time
    if (analysisStartTime > 0 && analysisElapsedTime === null) {
      const elapsed = Date.now() - analysisStartTime;
      setAnalysisElapsedTime(elapsed);
      addDebugMessage(`Analysis completed in ${elapsed}ms`);
    }

    // Update state with the analysis result
    setResult(analysisResult.isPhishing ? 'phishing' : 'safe');
    setConfidence(analysisResult.confidence);
    setFeatures(analysisResult);
    setIsLoading(false);

    // Extract URL and DOM probabilities for display
    const urlProb = analysisResult.urlFeatures.phishingProbability || analysisResult.urlFeatures.probability;
    setUrlProbability(urlProb);

    if (analysisResult.domFeatures) {
      setDomProbability(analysisResult.domFeatures.suspiciousScore);
      addDebugMessage(`DOM Score: ${analysisResult.domFeatures.suspiciousScore}`);
    }

    // If we have suspicious words data already, update the feature with its calculated impact
    if (suspiciousWordsData?.calculatedImpact && analysisResult.domFeatures) {
      addDebugMessage(`Updating feature with pre-loaded suspicious words impact: ${suspiciousWordsData.calculatedImpact}`);

      // Create a deep copy
      const updatedAnalysisResult = JSON.parse(JSON.stringify(analysisResult));

      // Find and update the fraudTextScore feature if it exists
      const fraudTextFeatureIndex = updatedAnalysisResult.domFeatures.features.findIndex(
        (f: any) => f.name === 'fraudTextScore'
      );

      if (fraudTextFeatureIndex >= 0) {
        updatedAnalysisResult.domFeatures.features[fraudTextFeatureIndex].impact = suspiciousWordsData.calculatedImpact;
        setFeatures(updatedAnalysisResult);
      }
    }
  };

  const handleCheck = async () => {
    if (!popupMountedRef.current) return;

    setIsLoading(true);
    addDebugMessage("Running manual check...");

    // Reset timing values and start the timer
    setAnalysisStartTime(Date.now());
    setAnalysisElapsedTime(null);

    try {
      // Use the messaging service to request an analysis
      const response = await analyzeUrlManually(url, tabId);

      if (response && response.success && response.result) {
        addDebugMessage("Analysis successful");
        setAnalysisTimestamp(Date.now());

        // If the response includes elapsedTime, use that instead of calculating our own
        if (response.totalElapsedTime) {
          setAnalysisElapsedTime(response.totalElapsedTime);
          addDebugMessage(`Analysis took ${response.totalElapsedTime}ms since page load`);
        } else if (response.analysisElapsedTime) {
          setAnalysisElapsedTime(response.analysisElapsedTime);
          addDebugMessage(`Analysis took ${response.analysisElapsedTime}ms (analysis process only)`);
        }

        processAnalysisResult(response.result);
      } else {
        // Fallback to direct analysis if messaging failed
        addDebugMessage("Messaging failed, falling back to direct analysis");
        const result = await analyzeForPhishing(url);
        setAnalysisTimestamp(Date.now());
        processAnalysisResult(result);
      }
    } catch (error) {
      if (popupMountedRef.current) {
        console.error("Analysis error:", error);
        addDebugMessage(`Analysis error: ${error.message}`);
        setIsLoading(false);
        setResult("error");
      }
    }
  };

  const handleExport = () => {
    if (!features) return;

    try {
      // Prepare data for export
      const exportData = {
        url,
        timestamp: new Date().toISOString(),
        result,
        confidence,
        features,
        analysisTime: {
          totalTimeFromPageLoad: analysisElapsedTime,
          analysisProcessTime: null // We don't have access to the analysis-only time here
        }
      };

      // Create a blob and download it
      const blobUrl = URL.createObjectURL(new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' }));
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = `phishing-analysis-${new Date().toISOString()}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(blobUrl);

      addDebugMessage("Analysis data exported");
    } catch (error) {
      console.error("Export error:", error);
      addDebugMessage(`Export error: ${error.message}`);
    }
  };

  const getRiskLevel = (score: number) => {
    if (score >= 0.5) return 'high';
    if (score >= 0.3) return 'low';
    return 'safe';
  };



  // Helper function to format elapsed time for display
  const formatElapsedTime = (ms: number | null): string => {
    if (ms === null) return "Unknown";

    if (ms < 1000) {
      return `${ms}ms`;
    } else {
      const seconds = (ms / 1000).toFixed(2);
      return `${seconds}s`;
    }
  };

  return (
    <div className="phishing-detector">
      <Header url={url} />
      <ActionBar
        onCheck={handleCheck}
        onExport={features ? handleExport : undefined}
        isLoading={isLoading}
        isAutoAnalyzed={features?.autoAnalyzed || false}
        analysisTimestamp={analysisTimestamp}
      />

      <div className="tab-content">
        {isLoading ? (
          <div className="loading-container">
            <div className="loading-spinner"></div>
            <div className="loading-text">Analyzing for phishing...</div>
          </div>
        ) : features ? (
          <>
            <SummaryTab
              features={features}
              result={result}
              confidence={confidence}
              getRiskLevel={getRiskLevel}
              setActiveTab={(tab) => {
                // No tab navigation in simplified UI
              }}
              urlProbability={urlProbability}
              domProbability={domProbability}
            />
            {analysisElapsedTime !== null && (
              <div className="analysis-timing">
                Analysis completed in {formatElapsedTime(analysisElapsedTime)} from page load
              </div>
            )}
          </>
        ) : (
          <div className="no-analysis">
            <p>No analysis data available. Click "Check Now" to analyze this page.</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default IndexPopup;
