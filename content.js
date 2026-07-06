/**
 * Sentinel AI - Explainable Cyber Trust Assistant
 * Content Script (DOM Risk Inspector)
 */

console.log('Sentinel AI: DOM Inspector activated on this page.');

// Listen for scanning signals from popup or background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scanDOM') {
    const domTelemetry = performDOMInspection();
    sendResponse(domTelemetry);
  }
  return true; // Keep channel open
});

/**
 * Scans the webpage DOM for security risks.
 * @returns {object} Telemetry reports on forms, iframes, and scripts.
 */
function performDOMInspection() {
  const result = {
    hasPasswordForms: false,
    insecurePasswordForm: false,
    hiddenIframesCount: 0,
    metaRedirectFound: false,
    formsCount: 0,
    scriptsCount: 0,
    detectedBrandImpersonation: false
  };

  try {
    // 1. Audit Forms
    const forms = document.querySelectorAll('form');
    result.formsCount = forms.length;
    
    forms.forEach(form => {
      const passwordInputs = form.querySelectorAll('input[type="password"]');
      if (passwordInputs.length > 0) {
        result.hasPasswordForms = true;
        
        // Check if a password form submits over insecure HTTP
        const action = form.getAttribute('action') || '';
        const currentProtocol = window.location.protocol;
        
        if (currentProtocol === 'http:' || (action.startsWith('http:') && !action.startsWith('https:'))) {
          result.insecurePasswordForm = true;
        }
      }
    });

    // 2. Audit Hidden Iframes
    const iframes = document.querySelectorAll('iframe');
    iframes.forEach(iframe => {
      const style = window.getComputedStyle(iframe);
      const isHidden = 
        style.display === 'none' || 
        style.visibility === 'hidden' || 
        style.opacity === '0' ||
        iframe.width === '0' || 
        iframe.height === '0' ||
        parseInt(style.width) === 0 || 
        parseInt(style.height) === 0;
        
      if (isHidden) {
        result.hiddenIframesCount++;
      }
    });

    // 3. Check for Meta Redirects
    const metaRedirect = document.querySelector('meta[http-equiv="refresh"]');
    if (metaRedirect) {
      result.metaRedirectFound = true;
    }

    // 4. Audit script count
    const scripts = document.querySelectorAll('script');
    result.scriptsCount = scripts.length;

    // 5. Basic brand impersonation checks (look for signs of login pages claiming to be Google, Microsoft, Facebook in title vs URL)
    const title = (document.title || '').toLowerCase();
    const hostname = window.location.hostname.toLowerCase();
    
    const brands = ['google', 'microsoft', 'facebook', 'netflix', 'paypal', 'apple', 'amazon', 'chase', 'bankofamerica'];
    brands.forEach(brand => {
      if (title.includes(brand) && !hostname.includes(brand)) {
        result.detectedBrandImpersonation = true;
      }
    });

  } catch (error) {
    console.error('Sentinel AI DOM analysis error:', error);
  }

  return result;
}
