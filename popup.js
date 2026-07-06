/**
 * Sentinel AI - Explainable Cyber Trust Assistant
 * Popup Logic Controller (Phase 1 Client-Side MVP)
 */

document.addEventListener('DOMContentLoaded', () => {
  initAnalysis();
  
  // Setup rescan button listener
  const rescanBtn = document.getElementById('rescan-btn');
  if (rescanBtn) {
    rescanBtn.addEventListener('click', () => {
      // Trigger a rotation animation on the icon
      const svgIcon = rescanBtn.querySelector('svg');
      if (svgIcon) {
        svgIcon.style.transition = 'transform 0.6s ease';
        svgIcon.style.transform = 'rotate(360deg)';
        setTimeout(() => { svgIcon.style.transform = 'rotate(0deg)'; }, 600);
      }
      initAnalysis();
    });
  }
});

/**
 * Initializes the website security scan.
 */
function initAnalysis() {
  showLoading();
  
  // Query the current active tab
  if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0]) {
        const activeTab = tabs[0];
        const urlStr = activeTab.url;

        // Skip background check for browser internal pages
        if (urlStr.startsWith('chrome://') || urlStr.startsWith('chrome-extension://') || urlStr.startsWith('about:')) {
          displaySystemPage(urlStr);
          return;
        }

        // Query the content script for DOM details first (Phase 5)
        chrome.tabs.sendMessage(activeTab.id, { action: 'scanDOM' }, (domTelemetry) => {
          // If content script fails (e.g., restricted page), we handle it gracefully.
          const telemetry = (domTelemetry && !chrome.runtime.lastError) ? domTelemetry : null;

          // Attempt remote analysis using the background service worker
          chrome.runtime.sendMessage(
            { action: 'analyzeUrlRemote', url: urlStr, domTelemetry: telemetry },
            (response) => {
              if (response && response.success && response.data) {
                console.log('Sentinel AI: Remote analysis successful', response.data);
                
                const backendStatus = document.getElementById('backend-status');
                if (backendStatus) backendStatus.innerText = 'Server AI Connected';
                
                const result = response.data;
                const isHttps = result.details ? result.details.ssl_verified : result.url.startsWith('https:');
                
                // Update quick stat badges from backend details
                if (result.details) {
                  const ageLabel = result.details.domain_age_days !== -1 
                    ? `Age: ${result.details.domain_age_days}d` 
                    : 'Age: N/A';
                  const ageBadge = document.getElementById('badge-age');
                  if (ageBadge) ageBadge.querySelector('.stat-label').innerText = ageLabel;
                  
                  const mlLabel = `ML: ${result.details.ml_prediction}`;
                  const mlBadge = document.getElementById('badge-ml');
                  if (mlBadge) mlBadge.querySelector('.stat-label').innerText = mlLabel;
                }
                
                updateUI(activeTab.title, result.domain, result.trust_score, isHttps, result.factors);
              } else {
                console.log('Sentinel AI: Local fallback mode triggered', response?.error);
                
                const backendStatus = document.getElementById('backend-status');
                if (backendStatus) backendStatus.innerText = 'Local Heuristic Mode';
                
                analyzeUrlLocal(urlStr, activeTab.title || 'Webpage');
              }
            }
          );
        });
      } else {
        showError('Unable to access tab information.');
      }
    });
  } else {
    // Development/Fallback Mode (if loaded outside extension context)
    const mockUrl = window.location.href;
    analyzeUrlLocal(mockUrl, document.title || 'Local Test Page');
  }
}

/**
 * Shows the loading shimmer states in the UI.
 */
function showLoading() {
  document.getElementById('site-name').innerText = 'Scanning...';
  document.getElementById('site-url').innerText = 'Querying tab information...';
  document.getElementById('score-num').innerText = '--';
  document.getElementById('status-val').innerText = 'Analyzing';
  
  const factorsList = document.getElementById('factors-list');
  factorsList.innerHTML = `
    <div class="loading-shimmer">
      <div class="shimmer-line"></div>
      <div class="shimmer-line short"></div>
      <div class="shimmer-line"></div>
    </div>
  `;
  
  // Reset score ring
  const scoreRing = document.getElementById('score-ring');
  if (scoreRing) {
    scoreRing.style.strokeDashoffset = '251.2';
  }
  
  const container = document.body;
  container.className = ''; // Remove status themes
}

/**
 * Displays an error state.
 */
function showError(message) {
  document.getElementById('site-name').innerText = 'Error';
  document.getElementById('site-url').innerText = message;
  document.getElementById('factors-list').innerHTML = `
    <div class="factor-card" style="border-left: 4px solid var(--color-danger)">
      <div class="factor-info">
        <span class="factor-name">Scan Failed</span>
        <span class="factor-desc">${message}</span>
      </div>
    </div>
  `;
}

/**
 * Analyzes the URL using client-side heuristics.
 * @param {string} urlStr The tab URL.
 * @param {string} pageTitle The tab title.
 */
function analyzeUrlLocal(urlStr, pageTitle) {
  try {
    // Filter chrome://, about:blank, etc.
    if (urlStr.startsWith('chrome://') || urlStr.startsWith('chrome-extension://') || urlStr.startsWith('about:')) {
      displaySystemPage(urlStr);
      return;
    }

    const url = new URL(urlStr);
    const domain = url.hostname;
    
    // Check HTTPS
    const isHttps = url.protocol === 'https:';
    
    // List of suspicious TLDs
    const suspiciousTlds = ['.zip', '.mov', '.tk', '.ml', '.ga', '.cf', '.gq', '.country', '.stream', '.men', '.work', '.click', '.top'];
    const currentTld = domain.substring(domain.lastIndexOf('.')).toLowerCase();
    const hasSuspiciousTld = suspiciousTlds.some(tld => domain.endsWith(tld));

    // Check for IP Address host
    const ipPattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    const isIpHost = ipPattern.test(domain);

    // Check URL length
    const isLongUrl = urlStr.length > 75;

    // Check for excessive subdomains (e.g. login.secure.bank.domain.com has 5 parts)
    const subdomainParts = domain.split('.');
    // For standard domains, www.google.com has 3 parts.
    // domains like google.co.uk has 4 parts but .co.uk is a public suffix.
    // A basic check: subdomains > 3 indicates complexity.
    const isExcessiveSubdomains = subdomainParts.length > 3;

    // Check for special characters in URL
    const hasAtSymbol = urlStr.includes('@');
    
    // Check for excessive hyphens in domain (common in typosquatting)
    const hyphenCount = (domain.match(/-/g) || []).length;
    const hasExcessiveHyphens = hyphenCount >= 3;

    // Calculate basic Trust Score (starts at 100)
    let score = 100;
    const factors = [];

    // Factor evaluations
    if (isHttps) {
      factors.push({
        status: 'safe',
        name: 'Secure Connection (HTTPS)',
        desc: 'The website uses SSL/TLS encryption for data transmission.'
      });
    } else {
      score -= 35;
      factors.push({
        status: 'danger',
        name: 'Insecure Connection (HTTP)',
        desc: 'Data transferred to this site is not encrypted. High risk of interception.'
      });
    }

    if (isIpHost) {
      score -= 20;
      factors.push({
        status: 'danger',
        name: 'IP Address as Hostname',
        desc: 'The website uses an IP address directly instead of a domain name, commonly seen in phishing scams.'
      });
    } else {
      factors.push({
        status: 'safe',
        name: 'Valid Domain Hostname',
        desc: 'The site resolves to a named domain hierarchy.'
      });
    }

    if (hasSuspiciousTld) {
      score -= 15;
      factors.push({
        status: 'warning',
        name: 'Suspicious Domain Extension',
        desc: `Uses TLD (${currentTld}) often associated with low cost, temporary, or malicious websites.`
      });
    }

    if (isLongUrl) {
      score -= 10;
      factors.push({
        status: 'warning',
        name: 'Unusually Long URL',
        desc: `The URL length (${urlStr.length} chars) is long, a tactic used to hide the true destination domain.`
      });
    }

    if (isExcessiveSubdomains) {
      score -= 10;
      factors.push({
        status: 'warning',
        name: 'Multiple Subdomain Levels',
        desc: 'Deep subdomain layering discovered, which can be used to mimic trust brands.'
      });
    }

    if (hasAtSymbol) {
      score -= 15;
      factors.push({
        status: 'danger',
        name: 'Suspicious Symbol (@)',
        desc: 'Contains "@" in the URL, which forces browsers to ignore previous text and load the domain that follows.'
      });
    }

    if (hasExcessiveHyphens) {
      score -= 10;
      factors.push({
        status: 'warning',
        name: 'Excessive Hyphens in Domain',
        desc: 'Domain contains multiple hyphens, typically used in typosquatting to mimic real brand names.'
      });
    }

    // If no negative factors, add a positive factor
    if (score === 100) {
      factors.push({
        status: 'safe',
        name: 'Clean URL Structure',
        desc: 'Basic client-side heuristics did not find any suspicious patterns in this URL.'
      });
    }

    // Ensure score bounds
    score = Math.max(0, Math.min(100, score));

    // Update UI elements
    updateUI(pageTitle, domain, score, isHttps, factors);

  } catch (error) {
    showError('Invalid URL format: ' + error.message);
  }
}

/**
 * Displays special instructions for system-reserved chrome pages.
 */
function displaySystemPage(urlStr) {
  const container = document.body;
  container.className = 'safe-theme theme-applied';
  
  document.getElementById('site-name').innerText = 'Browser System Page';
  document.getElementById('site-url').innerText = urlStr.substring(0, 45) + '...';
  
  // Set score to 100
  document.getElementById('score-num').innerText = '100';
  document.getElementById('status-val').innerText = 'System Safe';
  
  const scoreRing = document.getElementById('score-ring');
  if (scoreRing) {
    scoreRing.style.strokeDashoffset = '0'; // Fully complete ring
  }
  
  const protocolBadge = document.getElementById('protocol-badge');
  protocolBadge.className = 'protocol-badge https';
  protocolBadge.innerText = 'SYSTEM';

  // Badges update
  document.getElementById('badge-ssl').querySelector('.stat-label').innerText = 'SSL: Trusted';
  document.getElementById('badge-age').querySelector('.stat-label').innerText = 'Age: N/A';
  document.getElementById('badge-ml').querySelector('.stat-label').innerText = 'ML: Safe';

  document.getElementById('factors-list').innerHTML = `
    <div class="factor-card">
      <span class="factor-status-icon">🛡️</span>
      <div class="factor-info">
        <span class="factor-name">Protected Environment</span>
        <span class="factor-desc">This is an internal web-browser address. Network traffic and external scripts do not run here.</span>
      </div>
    </div>
  `;
}

/**
 * Updates all elements in the popup interface based on analysis results.
 */
function updateUI(title, domain, score, isHttps, factors) {
  // Update name and domain
  document.getElementById('site-name').innerText = title || domain;
  document.getElementById('site-url').innerText = domain;

  // Update Protocol Badge
  const protocolBadge = document.getElementById('protocol-badge');
  if (isHttps) {
    protocolBadge.className = 'protocol-badge https';
    protocolBadge.innerText = 'HTTPS';
    document.getElementById('badge-ssl').querySelector('.stat-label').innerText = 'SSL: SECURE';
  } else {
    protocolBadge.className = 'protocol-badge http';
    protocolBadge.innerText = 'HTTP';
    document.getElementById('badge-ssl').querySelector('.stat-label').innerText = 'SSL: INSECURE';
  }

  // Update Score
  document.getElementById('score-num').innerText = score;
  
  // Calculate and animate circular ring
  const scoreRing = document.getElementById('score-ring');
  if (scoreRing) {
    const circumference = 251.2; // 2 * pi * r (r=40)
    const offset = circumference - (score / 100) * circumference;
    scoreRing.style.strokeDashoffset = offset;
  }

  // Determine Risk Class & Text
  let themeClass = '';
  let riskText = '';
  
  if (score >= 80) {
    themeClass = 'safe-theme';
    riskText = 'Safe';
  } else if (score >= 50) {
    themeClass = 'warning-theme';
    riskText = 'Suspicious';
  } else {
    themeClass = 'danger-theme';
    riskText = 'Dangerous';
  }

  // Apply theme class to body
  const container = document.body;
  container.className = `${themeClass} theme-applied`;
  document.getElementById('status-val').innerText = riskText;

  // Update placeholder stats (these will be enriched in later phases)
  document.getElementById('badge-age').querySelector('.stat-label').innerText = 'Age: Real-time';
  document.getElementById('badge-ml').querySelector('.stat-label').innerText = `ML: ${score >= 50 ? 'Safe' : 'Risk'}`;

  // Populate Factors list
  const factorsList = document.getElementById('factors-list');
  factorsList.innerHTML = ''; // Clear loading shimmers
  
  factors.forEach(factor => {
    const card = document.createElement('div');
    card.className = 'factor-card';
    
    // Choose emoji or icon based on status
    let statusIcon = 'ℹ️';
    if (factor.status === 'safe') {
      statusIcon = '✅';
      card.style.borderLeft = '3px solid var(--color-safe)';
    } else if (factor.status === 'warning') {
      statusIcon = '⚠️';
      card.style.borderLeft = '3px solid var(--color-warning)';
    } else if (factor.status === 'danger') {
      statusIcon = '🚨';
      card.style.borderLeft = '3px solid var(--color-danger)';
    }

    card.innerHTML = `
      <span class="factor-status-icon">${statusIcon}</span>
      <div class="factor-info">
        <span class="factor-name">${escapeHtml(factor.name)}</span>
        <span class="factor-desc">${escapeHtml(factor.desc)}</span>
      </div>
    `;
    factorsList.appendChild(card);
  });
}

/**
 * Escapes HTML characters to prevent XSS.
 */
function escapeHtml(str) {
  return str.replace(/[&<>'"]/g, 
    tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[tag] || tag)
  );
}
