/**
 * Sentinel AI - Explainable Cyber Trust Assistant
 * Background Service Worker (Manifest V3)
 */

// Initialize extension on install
chrome.runtime.onInstalled.addListener(() => {
  console.log('Sentinel AI: Explainable Cyber Trust Assistant installed.');
  
  // Set default settings
  chrome.storage.local.set({
    backendUrl: 'http://localhost:8000',
    localAnalysisMode: true
  });
});

// Listener for message passing between popup, content scripts, and background
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Sentinel AI background script received request:', request);

  if (request.action === 'analyzeUrlRemote') {
    // Phase 2/5 Integration: Contacting the FastAPI backend with DOM telemetry
    fetchRemoteAnalysis(request.url, request.domTelemetry)
      .then(result => sendResponse({ success: true, data: result }))
      .catch(err => sendResponse({ success: false, error: err.message }));
    
    return true; // Keeps the message channel open for async response
  }
  
  if (request.action === 'getContentDetails') {
    // Direct content extraction request proxy
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, { action: 'scanDOM' }, (response) => {
          if (chrome.runtime.lastError) {
            sendResponse({ success: false, error: chrome.runtime.lastError.message });
          } else {
            sendResponse({ success: true, data: response });
          }
        });
      } else {
        sendResponse({ success: false, error: 'No active tab found' });
      }
    });
    return true;
  }
});

/**
 * Fetches analysis from the FastAPI server.
 * Used during Phase 2+ to connect backend checks.
 * @param {string} url The page URL to analyze.
 * @param {object} domTelemetry Telemetry from the webpage content script.
 */
async function fetchRemoteAnalysis(url, domTelemetry) {
  // Read configured backend URL
  const settings = await chrome.storage.local.get('backendUrl');
  const backendBase = settings.backendUrl || 'http://localhost:8000';
  
  const response = await fetch(`${backendBase}/api/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ 
      url: url,
      dom_telemetry: domTelemetry
    })
  });

  if (!response.ok) {
    throw new Error(`Backend request failed with status: ${response.status}`);
  }
  
  return await response.json();
}
