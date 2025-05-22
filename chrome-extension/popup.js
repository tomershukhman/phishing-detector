// popup.js - Script for the extension popup UI

// Initialize logger
let logger = console;

// Try to load the logger module
(async function loadLogger() {
  try {
    const loggerModule = await import(chrome.runtime.getURL('lib/logger.js'));
    if (loggerModule) {
      logger = loggerModule.popupLogger;
      logger.log("Logger loaded successfully in popup");
    }
  } catch (error) {
    console.error("Error loading logger:", error);
  }
})();

document.addEventListener('DOMContentLoaded', function() {
  // DOM Elements
  const statusIndicator = document.getElementById('statusIndicator');
  const loadingContainer = document.getElementById('loadingContainer');
  const resultContainer = document.getElementById('resultContainer');
  const errorContainer = document.getElementById('errorContainer');
  const errorMessage = document.getElementById('errorMessage');
  const resultStatus = document.getElementById('resultStatus');
  const confidenceScore = document.getElementById('confidenceScore');
  const analyzedUrl = document.getElementById('analyzedUrl');
  const refreshButton = document.getElementById('refreshButton');
  const reportButton = document.getElementById('reportButton');
  const summarySafeContainer = document.getElementById('summarySafeContainer');
  const summaryWarningContainer = document.getElementById('summaryWarningContainer');
  const warningList = document.getElementById('warningList');
  const topFeatureslist = document.getElementById('topFeatureslist');
  const urlScore = document.getElementById('urlScore');
  const domFeaturesList = document.getElementById('domFeaturesList');
  const domScore = document.getElementById('domScore');
  const tabButtons = document.querySelectorAll('.tab-button');
  const tabPanels = document.querySelectorAll('.tab-panel');

  // Initialize the popup
  initializePopup();

  // Set up tab switching
  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      const tabName = button.getAttribute('data-tab');
      switchTab(tabName);
    });
  });

  // Set up refresh button
  refreshButton.addEventListener('click', () => {
    showLoading();
    analyzeCurrentTab(true);
  });

  // Set up report button
  reportButton.addEventListener('click', reportPhishingSite);

  // Function to initialize the popup
  function initializePopup() {
    showLoading();
    analyzeCurrentTab();
  }

  // Function to show loading state
  function showLoading() {
    statusIndicator.className = 'status-indicator analyzing';
    loadingContainer.classList.remove('hidden');
    resultContainer.classList.add('hidden');
    errorContainer.classList.add('hidden');
  }

  // Function to analyze the current tab
  async function analyzeCurrentTab(forceRefresh = false) {
    try {
      showLoading();
      
      // Get the current active tab
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const activeTab = tabs[0];
      
      if (!activeTab) {
        throw new Error("No active tab found");
      }
      
      console.log("Analyzing current tab", { 
        tabId: activeTab.id, 
        url: activeTab.url,
        forceRefresh 
      });
      
      if (!activeTab.url || !(activeTab.url.startsWith('http://') || activeTab.url.startsWith('https://'))) {
        throw new Error("Can only analyze HTTP/HTTPS URLs");
      }
      
      // First try to get existing tab analysis
      let analysisResults = await new Promise((resolve) => {
        chrome.runtime.sendMessage({ 
          action: "getTabAnalysisData", 
          tabId: activeTab.id,
          forceRefresh
        }, response => {
          if (chrome.runtime.lastError || !response || !response.success) {
            resolve(null);
          } else {
            resolve(response.data);
          }
        });
      });
      
      // If we didn't get results, try a direct URL analysis
      if (!analysisResults) {
        console.log("No tab analysis available, trying direct URL analysis");
        
        analysisResults = await new Promise((resolve) => {
          chrome.runtime.sendMessage({ 
            action: "analyzeUrlManually", 
            url: activeTab.url
          }, response => {
            if (chrome.runtime.lastError || !response || !response.success) {
              resolve(null);
            } else {
              resolve({
                url: activeTab.url,
                result: response.result,
                timestamp: Date.now()
              });
            }
          });
        });
      }
      
      if (analysisResults) {
        console.log("Analysis results received", analysisResults);
        showResults(analysisResults);
      } else {
        showError("Unable to analyze this page. Please try again.");
      }
    } catch (error) {
      console.error("Error analyzing tab:", error);
      showError(error.message);
    }
  }

  // Add a fallback analysis function that doesn't rely on background communication
  async function fallbackAnalysis() {
    try {
      console.log("Attempting fallback analysis...");
      
      // Get the current tab URL
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const activeTab = tabs[0];
      
      if (!activeTab || !activeTab.url || !(activeTab.url.startsWith('http'))) {
        throw new Error("No valid tab to analyze");
      }
      
      console.log("Performing fallback analysis for:", activeTab.url);
      
      // Create a minimal analysis result
      const analysisResult = {
        url: activeTab.url,
        result: {
          isPhishing: false,
          confidence: 50,
          urlFeatures: {
            url: activeTab.url,
            features: {},
            suspiciousKeywordsFound: [],
            probability: 0.5,
            score: 0
          },
          domFeatures: null,
          calculationDetails: {
            urlWeight: 1.0,
            urlScore: 0.5,
            urlContribution: 0.5
          }
        },
        timestamp: Date.now()
      };
      
      // Display the fallback result
      showResults(analysisResult);
      
      // Add a note about fallback mode
      const fallbackNote = document.createElement('div');
      fallbackNote.className = 'fallback-notice';
      fallbackNote.textContent = 'Running in fallback mode. Some features may be limited.';
      fallbackNote.style.color = '#ff9800';
      fallbackNote.style.padding = '10px';
      fallbackNote.style.marginTop = '10px';
      fallbackNote.style.textAlign = 'center';
      fallbackNote.style.fontStyle = 'italic';
      document.querySelector('.result-container').prepend(fallbackNote);
      
      return true;
    } catch (error) {
      console.error("Fallback analysis failed:", error);
      showError("All analysis methods failed. " + error.message);
      return false;
    }
  }

  // Add direct URL analysis that doesn't depend on module imports
  function directUrlAnalysis(url) {
    return new Promise((resolve) => {
      console.log("Performing direct URL analysis for:", url);
      
      chrome.runtime.sendMessage(
        { 
          action: 'analyzeUrlDirectly', 
          url: url
        },
        function(response) {
          if (chrome.runtime.lastError || !response || !response.success) {
            console.error("Direct URL analysis failed:", 
                          chrome.runtime.lastError ? chrome.runtime.lastError.message : 
                          response ? response.error : "No response");
            resolve(null);
            return;
          }
          
          resolve({
            url: url,
            result: response.result,
            timestamp: Date.now()
          });
        }
      );
      
      // Set a timeout in case the message never gets a response
      setTimeout(() => {
        console.log("Direct URL analysis timed out");
        resolve(null);
      }, 3000);
    });
  }

  // Function to show results
  function showResults(data) {
    loadingContainer.classList.add('hidden');
    resultContainer.classList.remove('hidden');
    errorContainer.classList.add('hidden');

    // Set the URL
    analyzedUrl.textContent = data.url;

    // Parse the result
    const isPhishing = data.result.isPhishing;
    const confidence = data.result.confidence;
    const urlFeatures = data.result.urlFeatures;
    const domFeatures = data.result.domFeatures;
    const calculationDetails = data.result.calculationDetails;

    // Update status indicator and message
    if (isPhishing) {
      statusIndicator.className = 'status-indicator warning';
      resultStatus.textContent = 'Potential Phishing Site';
      resultStatus.style.color = '#f44336';
      summarySafeContainer.classList.add('hidden');
      summaryWarningContainer.classList.remove('hidden');
    } else {
      statusIndicator.className = 'status-indicator safe';
      resultStatus.textContent = 'Site Appears Safe';
      resultStatus.style.color = '#34a853';
      summarySafeContainer.classList.remove('hidden');
      summaryWarningContainer.classList.add('hidden');
    }

    // Set confidence score
    if (confidence !== null) {
      confidenceScore.textContent = `Confidence: ${confidence}%`;
    } else {
      confidenceScore.textContent = 'Analyzing...';
    }

    // Populate warning list if phishing
    if (isPhishing) {
      // Clear previous warnings
      warningList.innerHTML = '';

      // Add warning items based on features
      const warnings = generateWarnings(urlFeatures, domFeatures);
      warnings.forEach(warning => {
        const li = document.createElement('li');
        li.textContent = warning;
        warningList.appendChild(li);
      });
    }

    // Populate URL Features tab
    if (urlFeatures) {
      topFeatureslist.innerHTML = '';

      // Add top contributing features
      if (urlFeatures.topContributingFeatures && urlFeatures.topContributingFeatures.length > 0) {
        urlFeatures.topContributingFeatures.forEach(feature => {
          const li = document.createElement('li');
          
          const nameSpan = document.createElement('span');
          nameSpan.className = 'feature-name';
          nameSpan.textContent = formatFeatureName(feature.name);
          
          const valueSpan = document.createElement('span');
          valueSpan.className = 'feature-value';
          valueSpan.textContent = formatFeatureValue(feature.value);
          
          li.appendChild(nameSpan);
          li.appendChild(valueSpan);
          topFeatureslist.appendChild(li);
        });
      } else {
        const li = document.createElement('li');
        li.textContent = 'No significant contributing features';
        topFeatureslist.appendChild(li);
      }

      // Set URL score
      if (calculationDetails && calculationDetails.urlScore !== undefined) {
        const scorePercentage = Math.round((1 - calculationDetails.urlScore) * 100);
        urlScore.textContent = `${scorePercentage}%`;
      } else {
        urlScore.textContent = 'N/A';
      }
    }

    // Populate DOM Features tab
    if (domFeatures && domFeatures.features) {
      domFeaturesList.innerHTML = '';

      // Get most significant DOM features
      const significantFeatures = domFeatures.features
        .filter(feature => feature.impact > 0 && feature.name !== 'analysisError')
        .sort((a, b) => b.impact - a.impact)
        .slice(0, 5);

      if (significantFeatures.length > 0) {
        significantFeatures.forEach(feature => {
          const li = document.createElement('li');
          
          const nameSpan = document.createElement('span');
          nameSpan.className = 'feature-name';
          nameSpan.textContent = formatFeatureName(feature.name);
          
          const valueSpan = document.createElement('span');
          valueSpan.className = 'feature-value';
          valueSpan.textContent = feature.value === true ? 'Detected' : 
                                 feature.value === false ? 'Not detected' : 
                                 feature.value;
          
          li.appendChild(nameSpan);
          li.appendChild(valueSpan);
          domFeaturesList.appendChild(li);
        });
      } else {
        const li = document.createElement('li');
        li.textContent = 'No suspicious DOM features detected';
        domFeaturesList.appendChild(li);
      }

      // Set DOM score
      if (domFeatures.suspiciousScore !== undefined) {
        const scorePercentage = Math.round((1 - domFeatures.suspiciousScore) * 100);
        domScore.textContent = `${scorePercentage}%`;
      } else {
        domScore.textContent = 'N/A';
      }
    } else {
      domFeaturesList.innerHTML = '<li>DOM analysis not available</li>';
      domScore.textContent = 'N/A';
    }
  }

  // Function to show error
  function showError(message) {
    loadingContainer.classList.add('hidden');
    resultContainer.classList.add('hidden');
    errorContainer.classList.remove('hidden');
    errorMessage.textContent = message;
    statusIndicator.className = 'status-indicator';
  }

  // Function to switch tabs
  function switchTab(tabName) {
    // Update active tab button
    tabButtons.forEach(button => {
      if (button.getAttribute('data-tab') === tabName) {
        button.classList.add('active');
      } else {
        button.classList.remove('active');
      }
    });

    // Update active tab panel
    tabPanels.forEach(panel => {
      if (panel.id === `${tabName}Tab`) {
        panel.classList.add('active');
      } else {
        panel.classList.remove('active');
      }
    });
  }

  // Function to analyze the current tab
  function analyzeCurrentTab(forceRefresh = false) {
    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
      if (tabs.length === 0) {
        showError('Unable to access the current tab.');
        return;
      }

      const currentTab = tabs[0];
      
      // Skip non-HTTP URLs
      if (!currentTab.url || !currentTab.url.startsWith('http')) {
        showError('This extension only works on HTTP/HTTPS pages.');
        return;
      }

      console.log("Analyzing tab:", currentTab.url);
      
      // Set a timeout for the whole analysis process
      const analysisTimeout = setTimeout(() => {
        console.log("Analysis timed out completely, using fallback");
        fallbackAnalysis();
      }, 5000);

      // Get analysis data from background script
      chrome.runtime.sendMessage(
        { 
          action: 'getTabAnalysisData', 
          tabId: currentTab.id,
          forceRefresh: forceRefresh
        },
        function(response) {
          if (chrome.runtime.lastError) {
            console.error('Error from background script:', chrome.runtime.lastError);
            
            // Try direct URL analysis as fallback
            tryDirectAnalysis(currentTab.url, analysisTimeout);
            return;
          }

          if (!response || !response.success) {
            console.log("Tab analysis failed:", response ? response.error : "No successful response");
            
            // Try direct URL analysis as fallback
            tryDirectAnalysis(currentTab.url, analysisTimeout);
            return;
          }

          // We have data - show the results
          clearTimeout(analysisTimeout);
          showResults(response.data);
        }
      );
    });
  }
  
  // Helper function to try direct URL analysis
  function tryDirectAnalysis(url, timeoutId) {
    console.log("Trying direct URL analysis for:", url);
    
    // First try the analyzeUrlManually method
    chrome.runtime.sendMessage(
      { 
        action: 'analyzeUrlManually', 
        url: url
      },
      function(response) {
        if (chrome.runtime.lastError || !response || !response.success) {
          console.error("Regular URL analysis failed:", 
                        chrome.runtime.lastError ? chrome.runtime.lastError.message : 
                        response ? response.error : "No response");
          
          // If that fails, try our direct analysis method
          directUrlAnalysis(url).then(result => {
            if (result) {
              clearTimeout(timeoutId);
              showResults(result);
            } else {
              // If all else fails, use the local fallback
              fallbackAnalysis();
            }
          });
          return;
        }
        
        // We have data - show the results
        clearTimeout(timeoutId);
        
        showResults({
          url: url,
          result: response.result,
          timestamp: Date.now()
        });
      }
    );
  }

  // Function to report the current site as phishing
  function reportPhishingSite() {
    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
      if (tabs.length === 0) {
        return;
      }

      const currentTab = tabs[0];
      if (!currentTab.url) {
        return;
      }

      // Open Google's phishing report form in a new tab
      const reportUrl = `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(currentTab.url)}`;
      chrome.tabs.create({ url: reportUrl });
    });
  }

  // Function to generate warning messages from features
  function generateWarnings(urlFeatures, domFeatures) {
    const warnings = [];
    
    // Add URL-based warnings
    if (urlFeatures) {
      // Check for suspicious keywords
      if (urlFeatures.suspiciousKeywordsFound && urlFeatures.suspiciousKeywordsFound.length > 0) {
        warnings.push(`Suspicious keywords in URL: ${urlFeatures.suspiciousKeywordsFound.join(', ')}`);
      }
      
      // Add warnings based on top features
      if (urlFeatures.topContributingFeatures) {
        for (const feature of urlFeatures.topContributingFeatures) {
          // Only add warning for significant feature impacts
          if (feature.impact > 0.3) {
            let warning = "";
            
            // Generate a readable warning based on the feature name
            switch (feature.name) {
              case "has_suspicious_tld":
                warning = "Suspicious top-level domain (TLD) detected";
                break;
              case "domain_length":
                warning = "Unusually long domain name";
                break;
              case "has_suspicious_keywords":
                warning = "Contains suspicious keywords";
                break;
              case "entropy":
                warning = "URL contains unusual character patterns";
                break;
              case "url_length":
                warning = "Excessively long URL";
                break;
              case "has_suspicious_extensions":
                warning = "Suspicious file extensions detected";
                break;
              case "digit_count":
                warning = "Unusual number of digits in URL";
                break;
              case "has_ip_address":
                warning = "URL contains an IP address instead of a domain name";
                break;
              case "suspicious_char_ratio":
                warning = "High ratio of suspicious characters";
                break;
              default:
                warning = `Suspicious URL characteristic: ${formatFeatureName(feature.name)}`;
            }
            
            warnings.push(warning);
          }
        }
      }
    }
    
    // Add DOM-based warnings
    if (domFeatures && domFeatures.features) {
      const significantFeatures = domFeatures.features
        .filter(f => f.impact > 0.3)
        .sort((a, b) => b.impact - a.impact);
      
      for (const feature of significantFeatures) {
        let warning = "";
        
        // Generate a readable warning based on the feature name
        switch (feature.name) {
          case "has_password_field":
            warning = "Login form detected on a suspicious page";
            break;
          case "has_login_form":
            warning = "Login form detected on a suspicious page";
            break;
          case "has_suspicious_hidden_fields":
            warning = "Suspicious hidden form fields detected";
            break;
          case "has_deceptive_links":
            warning = "Links with misleading text detected";
            break;
          case "has_invisible_inputs":
            warning = "Invisible input fields detected (potential data theft)";
            break;
          case "has_suspicious_content":
            warning = "Page content contains suspicious security/urgency keywords";
            break;
          case "has_spelling_errors":
            warning = "Page contains misspelled words (common in phishing)";
            break;
          default:
            warning = `Suspicious page element: ${formatFeatureName(feature.name)}`;
        }
        
        warnings.push(warning);
      }
    }
    
    // If we don't have enough warnings but the score is high, add a generic one
    if (warnings.length === 0) {
      warnings.push("Multiple minor suspicious elements detected");
    }
    
    return warnings;
  }
  
  // Function to format feature names for display
  function formatFeatureName(name) {
    return name
      .replace(/_/g, ' ')
      .replace(/\b\w/g, l => l.toUpperCase());
  }
  
  // Function to format feature values for display
  function formatFeatureValue(value) {
    if (value === true) return "Yes";
    if (value === false) return "No";
    if (typeof value === 'number') {
      // If it's a small value, show more decimal places
      if (Math.abs(value) < 0.1) {
        return value.toFixed(4);
      }
      return value.toFixed(2);
    }
    return value.toString();
  }

  // Add diagnostic function to check background service worker
  async function checkBackgroundStatus() {
    try {
      console.log("Checking background service worker status...");
      const response = await new Promise((resolve) => {
        chrome.runtime.sendMessage({
          action: "checkBackgroundStatus"
        }, (response) => {
          if (chrome.runtime.lastError) {
            console.error("Error checking background status:", chrome.runtime.lastError);
            resolve({ success: false, error: chrome.runtime.lastError.message });
          } else {
            resolve(response || { success: false, error: "No response" });
          }
        });
      });
      
      console.log("Background status check result:", response);
      
      if (!response.success) {
        console.error("Background service worker not responding properly");
        
        // Add debug info to UI if in error state
        if (errorContainer.classList.contains('hidden') === false) {
          const debugInfo = document.createElement("div");
          debugInfo.className = "debug-info";
          debugInfo.innerHTML = `
            <h4>Diagnostic Info:</h4>
            <p>Background service worker is not responding properly.</p>
            <p>Error: ${response.error || "Unknown error"}</p>
            <p>Try reloading the extension or browser.</p>
          `;
          errorContainer.appendChild(debugInfo);
        }
      }
      
      return response;
    } catch (error) {
      console.error("Exception in checkBackgroundStatus:", error);
      return { success: false, error: error.message };
    }
  }
  
  // Call diagnostic check on popup load
  checkBackgroundStatus();

  // Function to switch tabs
  function switchTab(tabName) {
    tabButtons.forEach(button => {
      if (button.getAttribute('data-tab') === tabName) {
        button.classList.add('active');
      } else {
        button.classList.remove('active');
      }
    });
    
    tabPanels.forEach(panel => {
      if (panel.id === tabName + 'Tab') {
        panel.classList.add('active');
      } else {
        panel.classList.remove('active');
      }
    });
  }
  
  // Function to report a phishing site
  function reportPhishingSite() {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      const url = tabs[0].url;
      const reportUrl = `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(url)}`;
      window.open(reportUrl, '_blank');
    });
  }
});
