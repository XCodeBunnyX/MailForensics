// ============================================================
// GmailGuard — Main Application Controller
// Problem Statement: SIH26106
// AI-Powered Email Threat Detection, GeoLocation, and Forensic Intelligence Platform
// ============================================================

class GmailGuardApp {
  constructor() {
    this.currentPage = 'dashboard';
    this.currentResult = null;
    this.sessionInvestigations = [];
    this.charts = {};
    this.clockInterval = null;
    this.healthInterval = null;
    this.backendConnected = false;
    this.backendInfo = null;
    this.activeFile = null;
    this.activeResultTab = 'overview';
    this.isAnalyzing = false;

    // Gmail & Gemini state
    this.gmailConnected = false;
    this.gmailUser = null;
    this.gmailMessages = [];
    this.gmailLoading = false;
    this.analysisState = {}; // Per-email: emailId -> { status: 'idle'|'analyzing'|'completed'|'error', threatScore, verdict, geminiAssessment, error, timestamp }
    this.analysisResults = {}; // Per-email: emailId -> full normalized forensic report
    this.activeGmailFilter = 'all';
    this.activeGmailSearch = '';
    this.gmailCurrentPage = 1;
    this.gmailPageSize = 8;
    this.geminiOverview = null;
  }

  init() {
    this.renderSidebar();
    this.renderMainArea();
    this.renderTopbar();
    this.startClock();
    this.setupToastContainer();

    // Check backend health immediately and periodically
    this.checkBackendHealth();
    this.healthInterval = setInterval(() => this.checkBackendHealth(), 15000);

    // Check for Google OAuth callback redirect parameters
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('gmail') === 'connected') {
      this.showToast('Google OAuth: Gmail connected successfully!', 'success', '📧');
      window.history.replaceState({}, document.title, window.location.pathname);
      this.gmailConnected = true;
      this.loadGmailStatus().then(() => this.loadGmailMessages());
      this.navigateTo('gmail-inbox');
      return;
    } else if (urlParams.get('gmail') === 'error') {
      const reason = urlParams.get('reason') || 'Consent declined';
      const rawDetails = urlParams.get('details');
      const details = rawDetails ? decodeURIComponent(rawDetails) : '';
      let errorMsg = `Google OAuth failed: ${reason}`;
      if (reason === 'access_denied') {
        errorMsg = 'Google OAuth: Access denied. Make sure your Gmail address is added under Test Users in Google Cloud Console OAuth consent screen.';
      } else if (reason === 'missing_code') {
        errorMsg = 'Google OAuth: Authorization code was missing from callback redirect. Please retry.';
      } else if (reason === 'exchange_failed') {
        errorMsg = details
          ? `Google OAuth: Token exchange failed (${details}). Verify your OAuth client settings.`
          : 'Google OAuth: Token exchange failed. Please verify your redirect URI in Google Cloud Console and retry.';
      }
      this.showToast(errorMsg, 'error', '⚠️');
      window.history.replaceState({}, document.title, window.location.pathname);
      this.navigateTo('gmail-inbox');
      return;
    }

    // Initial navigation
    this.navigateTo('dashboard');
  }

  // ─── Backend Connectivity & Health ──────────────────────────
  async checkBackendHealth() {
    try {
      const data = await window.GmailGuardAPI.checkHealth();
      const wasConnected = this.backendConnected;
      this.backendConnected = true;
      this.backendInfo = data;
      this.updateBackendStatus(true, data);
      if (!wasConnected) {
        console.info('GmailGuard: FastAPI Forensics Engine Connected', data);
      }
      return true;
    } catch (err) {
      this.backendConnected = false;
      this.updateBackendStatus(false, null);
      return false;
    }
  }

  updateBackendStatus(isLive, data) {
    const pill = document.getElementById('backend-status-pill');
    if (pill) {
      pill.className = `backend-status-badge ${isLive ? 'live' : 'fallback'}`;
      pill.innerHTML = `
        <div class="pulse-dot" style="--pulse-color:${isLive ? 'var(--low)' : 'var(--critical)'}"></div>
        <span>${isLive ? `🟢 FastAPI Engine Live (${data?.version || 'v2.6'})` : '🔴 Backend Offline (Port 8000)'}</span>
      `;
    }
    const sideInd = document.getElementById('sidebar-engine-status');
    if (sideInd) {
      sideInd.textContent = isLive ? 'FASTAPI ENGINE ACTIVE' : 'BACKEND OFFLINE';
      sideInd.style.color = isLive ? 'var(--low)' : 'var(--critical)';
    }
  }

  showBackendDiagnostics() {
    if (this.backendConnected) {
      const mods = this.backendInfo?.modules || ['Linear SVM Classifier', 'IPinfo Geolocation', 'PhishTank Feed', 'SPF/DKIM/DMARC Evaluator'];
      this.showToast(`Connected to FastAPI Backend at ${window.GmailGuardAPI.baseUrl || 'http://127.0.0.1:8000'}. Modules: ${mods.join(', ')}.`, 'success', '⚡');
    } else {
      this.showToast(`FastAPI Backend at ${window.GmailGuardAPI.baseUrl || 'http://127.0.0.1:8000'} is offline. Start the backend: uvicorn api:app --port 8000`, 'error', '⚠️');
    }
  }

  // ─── Clock & Notifications ─────────────────────────────────
  startClock() {
    const update = () => {
      const el = document.getElementById('topbar-clock');
      if (el) el.textContent = new Date().toLocaleTimeString('en-IN', { hour12: false });
    };
    update();
    this.clockInterval = setInterval(update, 1000);
  }

  setupToastContainer() {
    let container = document.getElementById('toast-container');
    if (!container) {
      container = document.createElement('div');
      container.className = 'toast-container';
      container.id = 'toast-container';
      document.body.appendChild(container);
    }
  }

  showToast(message, type = 'info', icon = 'ℹ️') {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast toast-${type} animate-in`;
    toast.innerHTML = `
      <span class="toast-icon">${icon}</span>
      <span class="toast-msg">${message}</span>
    `;
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      toast.style.transition = '0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  // ─── Layout & Navigation ────────────────────────────────────
  renderSidebar() {
    const nav = [
      { id: 'dashboard', icon: '⬡', label: 'Dashboard' },
      { id: 'gmail-inbox', icon: '📧', label: 'Gmail Inbox', badge: this.gmailConnected ? 'Live' : null },
      { id: 'analyze', icon: '🔍', label: 'Analyze Email' },
      { id: 'investigation', icon: '🎯', label: 'Investigation', badge: this.currentResult ? 'Active' : null },
      { id: 'infrastructure', icon: '🌍', label: 'Infrastructure & Geo' },
      { id: 'threat-intel', icon: '🌐', label: 'Threat Intel & IOCs' },
      { id: 'forensics', icon: '🔬', label: 'Forensic Evidence' },
      { id: 'gemini-security', icon: '🤖', label: 'Gemini Security' },
      { id: 'reports', icon: '📋', label: 'Reports' },
    ];

    document.getElementById('sidebar').innerHTML = `
      <div class="sidebar-logo">
        <div class="logo-icon">⬡</div>
        <div>
          <div class="logo-text">GmailGuard</div>
          <div class="logo-tagline">See Beyond the Inbox</div>
        </div>
      </div>
      <div class="sidebar-section">Operations</div>
      ${[nav[0], nav[1], nav[2]].map(n => this._navItem(n)).join('')}
      <div class="sidebar-section">Forensic Analysis</div>
      ${[nav[3], nav[4], nav[5], nav[6]].map(n => this._navItem(n)).join('')}
      <div class="sidebar-section">AI Security</div>
      ${[nav[7]].map(n => this._navItem(n)).join('')}
      <div class="sidebar-section">Intelligence</div>
      ${[nav[8]].map(n => this._navItem(n)).join('')}
      <div class="sidebar-footer">
        <div class="threat-level-indicator">
          <div class="threat-level-header">🛡️ Engine Status</div>
          <div class="threat-level-value font-mono" id="sidebar-engine-status" style="font-size:11px;">
            ${this.backendConnected ? 'FASTAPI ENGINE ACTIVE' : 'CONNECTING...'}
          </div>
        </div>
        <div style="margin-top:12px;font-size:11px;color:var(--text-muted);text-align:center;line-height:1.4">
          SIH 2026 — Problem SIH26106<br>
          AICTE & National Cybersecurity<br>
          <span class="font-mono text-cyan" style="font-size:10px">v2.6.0 SOC Architecture</span>
        </div>
      </div>
    `;

    document.querySelectorAll('.nav-item').forEach(el => {
      el.addEventListener('click', () => this.navigateTo(el.dataset.page));
    });
  }

  _navItem(n) {
    return `<div class="nav-item${n.id === this.currentPage ? ' active' : ''}" data-page="${n.id}">
      <span class="nav-icon">${n.icon}</span>
      <span>${n.label}</span>
      ${n.badge ? `<span class="nav-badge">${n.badge}</span>` : ''}
    </div>`;
  }

  renderMainArea() {
    const main = document.getElementById('main-content');
    main.innerHTML = `
      <div id="topbar" class="topbar"></div>
      <div id="page-content" class="page-content"></div>
    `;
  }

  renderTopbar() {
    const titles = {
      dashboard: ['Operations Dashboard', 'Real-Time SOC Telemetry & Session Investigations'],
      'gmail-inbox': ['Gmail Inbox & Live Mailbox Stream', 'Official Gmail API OAuth 2.0 Integration & On-Demand Forensics'],
      analyze: ['Analyze Email', 'RFC 5322 Ingestion, File Parsing & Engine Pipeline'],
      investigation: ['Investigation / Analysis Result', 'Comprehensive Multi-Vector Threat Assessment'],
      infrastructure: ['Infrastructure & Geolocation', 'Candidate Relays, Transit Observables & Clock Skew'],
      'threat-intel': ['Threat Intelligence & IOCs', 'Domain Reputation, PhishTank Feeds & Extracted Artifacts'],
      forensics: ['Forensic Evidence & Correlation', 'Authentication Verification, Static Attachments & Evidence Correlation'],
      'gemini-security': ['Gemini AI Security Intelligence', 'Contextual Intent Reasoning, Plain-Language Analysis & SOC Recommendations'],
      reports: ['Forensic Reports', 'Audit-Ready Digital Forensic Investigation Summaries']
    };
    const [title, sub] = titles[this.currentPage] || ['GmailGuard', ''];
    const topbar = document.getElementById('topbar');
    if (!topbar) return;

    topbar.innerHTML = `
      <div class="topbar-left">
        <div class="topbar-title">${title}</div>
        <div class="topbar-subtitle">${sub}</div>
      </div>
      <div class="topbar-right">
        <div class="backend-status-badge ${this.backendConnected ? 'live' : 'fallback'}" id="backend-status-pill" title="Click for Backend Diagnostics" onclick="app.showBackendDiagnostics()" style="cursor:pointer">
          <div class="pulse-dot" style="--pulse-color:${this.backendConnected ? 'var(--low)' : 'var(--critical)'}"></div>
          <span>${this.backendConnected ? '🟢 FastAPI Engine Live' : '🔴 Backend Offline'}</span>
        </div>
        <div class="topbar-time font-mono" id="topbar-clock"></div>
        <div class="topbar-status"><div class="pulse-dot" style="--pulse-color:var(--low)"></div>SOC Systems Online</div>
        <div class="topbar-avatar" title="Forensic Analyst">🛡️</div>
      </div>
    `;
    this.startClock();
  }

  navigateTo(page) {
    this.currentPage = page;
    this.renderSidebar();
    this.renderTopbar();

    const content = document.getElementById('page-content');
    if (!content) return;
    content.innerHTML = '';
    content.style.animation = 'none';
    requestAnimationFrame(() => {
      content.style.animation = 'fadeInUp 0.25s ease-out both';
    });

    const pages = {
      dashboard: () => this.renderDashboard(),
      'gmail-inbox': () => this.renderGmailInbox(),
      analyze: () => this.renderAnalyze(),
      investigation: () => this.renderInvestigation(),
      infrastructure: () => this.renderInfrastructure(),
      'threat-intel': () => this.renderThreatIntel(),
      forensics: () => this.renderForensics(),
      'gemini-security': () => this.renderGeminiSecurity(),
      reports: () => this.renderReports(),
    };

    if (pages[page]) {
      pages[page]();
    } else {
      this.renderDashboard();
    }
  }

  // ─── A. DASHBOARD ──────────────────────────────────────────
  renderDashboard() {
    const content = document.getElementById('page-content');
    const cases = this.sessionInvestigations;
    const totalCount = cases.length;

    // Strict no-fabrication rule: derive exclusively from session data
    const criticalCount = cases.filter(c => c.severity === 'critical' || c.threatScore >= 80).length;
    const highCount = cases.filter(c => (c.severity === 'high' || (c.threatScore >= 60 && c.threatScore < 80))).length;
    const suspiciousCount = cases.filter(c => (c.severity === 'medium' || (c.threatScore >= 35 && c.threatScore < 60))).length;
    const cleanCount = cases.filter(c => (c.severity === 'low' || c.threatScore < 35)).length;

    // Collect unique observable IPs across session cases
    const observableIps = new Set();
    const allIocs = new Set();
    cases.forEach(c => {
      (c.geolocation || []).forEach(g => g.ip && observableIps.add(g.ip));
      (c.candidateRelays || []).forEach(r => r.ip && observableIps.add(r.ip));
      (c.iocs || []).forEach(i => i.value && allIocs.add(i.value));
    });

    content.innerHTML = `
      <!-- Telemetry Stats Grid -->
      <div class="stats-grid mb-24">
        <div class="stat-card animate-in" style="--accent-color:var(--cyan)">
          <div class="stat-icon">📁</div>
          <div class="stat-value">${totalCount}</div>
          <div class="stat-label">Emails Analyzed</div>
          <div class="stat-change" style="color:var(--text-muted)">Session Investigations</div>
        </div>
        <div class="stat-card animate-in animate-in-delay-1" style="--accent-color:var(--critical)">
          <div class="stat-icon">🚨</div>
          <div class="stat-value text-critical">${criticalCount + highCount}</div>
          <div class="stat-label">High-Risk Detections</div>
          <div class="stat-change text-critical">${criticalCount} Critical • ${highCount} High</div>
        </div>
        <div class="stat-card animate-in animate-in-delay-2" style="--accent-color:var(--medium)">
          <div class="stat-icon">⚠️</div>
          <div class="stat-value text-medium">${suspiciousCount}</div>
          <div class="stat-label">Suspicious Evaluations</div>
          <div class="stat-change text-medium">Require Analyst Review</div>
        </div>
        <div class="stat-card animate-in animate-in-delay-3" style="--accent-color:var(--purple)">
          <div class="stat-icon">🌐</div>
          <div class="stat-value" style="color:var(--purple)">${observableIps.size}</div>
          <div class="stat-label">Suspicious Infrastructure</div>
          <div class="stat-change" style="color:var(--text-muted)">Observable Transit Nodes</div>
        </div>
        <div class="stat-card animate-in animate-in-delay-4" style="--accent-color:var(--cyan)">
          <div class="stat-icon">🚩</div>
          <div class="stat-value text-cyan">${allIocs.size}</div>
          <div class="stat-label">Important IOCs</div>
          <div class="stat-change text-low">IPs, URLs & Hashes</div>
        </div>
      </div>

      ${totalCount === 0 ? `
        <!-- Ready State when no session investigations exist -->
        <div class="card mb-24 animate-in">
          <div class="card-body" style="padding:32px;text-align:center">
            <div style="font-size:48px;margin-bottom:12px">🛡️</div>
            <div style="font-size:18px;font-weight:700;color:var(--text-primary);margin-bottom:8px">
              SOC Investigation Pipeline Ready
            </div>
            <div style="font-size:13px;color:var(--text-secondary);max-width:600px;margin:0 auto 20px;line-height:1.5">
              No email investigations have been recorded in the current session. Submit a suspicious email via <strong style="color:var(--cyan)">Analyze Email</strong> or run a sample investigation below to observe full telemetry from the FastAPI backend.
            </div>
            <div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap">
              <button class="btn btn-primary" onclick="app.navigateTo('analyze')">
                🔍 Ingest New Email (.eml / Text)
              </button>
              <button class="btn btn-secondary" onclick="app.runDemoInvestigation('phishing_bank')">
                🎣 Test Banking Phishing EML
              </button>
              <button class="btn btn-secondary" onclick="app.runDemoInvestigation('ceo_fraud')">
                👔 Test BEC Wire Transfer
              </button>
              <button class="btn btn-secondary" onclick="app.runDemoInvestigation('malware_dropper')">
                🦠 Test Malware Dropper
              </button>
            </div>
          </div>
        </div>
      ` : `
        <!-- Charts & Distribution Row -->
        <div class="grid-2 mb-24">
          <div class="card animate-in">
            <div class="card-header">
              <div class="card-title">📊 Threat Distribution (Session Cases: ${totalCount})</div>
            </div>
            <div class="card-body">
              <div class="chart-wrap" style="height:220px;display:flex;align-items:center;justify-content:center">
                <canvas id="dashboard-threat-donut"></canvas>
              </div>
            </div>
          </div>

          <div class="card animate-in animate-in-delay-1">
            <div class="card-header">
              <div class="card-title">🎯 Threat Score Distribution</div>
            </div>
            <div class="card-body">
              <div class="chart-wrap" style="height:220px;display:flex;align-items:center;justify-content:center">
                <canvas id="dashboard-score-bar"></canvas>
              </div>
            </div>
          </div>
        </div>

        <!-- Recent Analyses Table -->
        <div class="card animate-in animate-in-delay-2">
          <div class="card-header">
            <div class="card-title">📋 Recent Investigations (${cases.length})</div>
            <button class="btn btn-primary btn-sm" onclick="app.navigateTo('analyze')">+ Ingest Another Email</button>
          </div>
          <div class="data-table-wrap">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Case ID</th>
                  <th>Sender</th>
                  <th>Subject</th>
                  <th>Threat Assessment</th>
                  <th>Threat Score</th>
                  <th>Observable IPs</th>
                  <th>Extracted URLs</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                ${cases.map(c => {
                  const scoreColor = c.threatScore >= 80 ? 'critical' : c.threatScore >= 60 ? 'high' : c.threatScore >= 35 ? 'medium' : 'low';
                  return `
                    <tr style="cursor:pointer" onclick="app.openInvestigation('${c.caseId}')">
                      <td class="case-id-cell">${c.caseId}</td>
                      <td class="email-cell font-mono" title="${c.email?.from || 'Unknown'}">${c.email?.senderEmail || c.email?.from || 'Not available'}</td>
                      <td class="email-cell" title="${c.email?.subject || 'No Subject'}">${c.email?.subject || '(No Subject)'}</td>
                      <td><span class="badge badge-${c.severity || 'medium'}">${c.verdict || 'EVALUATED'}</span></td>
                      <td class="score-cell text-${scoreColor} font-mono">${c.threatScore}/100</td>
                      <td class="font-mono" style="font-size:11px">${c.geolocation?.length || 0} nodes</td>
                      <td class="font-mono" style="font-size:11px">${c.urls?.length || 0} URLs</td>
                      <td><button class="btn btn-secondary btn-sm" onclick="event.stopPropagation();app.openInvestigation('${c.caseId}')">Drill Down →</button></td>
                    </tr>
                  `;
                }).join('')}
              </tbody>
            </table>
          </div>
        </div>
      `}
    `;

    if (totalCount > 0) {
      setTimeout(() => this._initDashboardCharts(criticalCount, highCount, suspiciousCount, cleanCount, cases), 100);
    }
  }

  _initDashboardCharts(critical, high, suspicious, clean, cases) {
    if (typeof Chart === 'undefined') {
      console.warn('Chart.js not loaded — skipping dashboard charts.');
      return;
    }
    const donutEl = document.getElementById('dashboard-threat-donut');
    if (donutEl) {
      if (this.charts.donut) this.charts.donut.destroy();
      this.charts.donut = new Chart(donutEl, {
        type: 'doughnut',
        data: {
          labels: ['Critical Risk', 'High Risk', 'Suspicious', 'Clean / Safe'],
          datasets: [{
            data: [critical, high, suspicious, clean],
            backgroundColor: ['#ff2d55', '#ff6b35', '#ffd60a', '#34d399'],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { position: 'right', labels: { color: '#94a3b8', font: { family: 'Inter', size: 11 } } }
          },
          cutout: '70%'
        }
      });
    }

    const barEl = document.getElementById('dashboard-score-bar');
    if (barEl) {
      if (this.charts.bar) this.charts.bar.destroy();
      const labels = cases.map(c => c.caseId.slice(-8));
      const scores = cases.map(c => c.threatScore);
      const colors = scores.map(s => s >= 80 ? '#ff2d55' : s >= 60 ? '#ff6b35' : s >= 35 ? '#ffd60a' : '#34d399');

      this.charts.bar = new Chart(barEl, {
        type: 'bar',
        data: {
          labels: labels,
          datasets: [{
            label: 'Threat Score (0-100)',
            data: scores,
            backgroundColor: colors,
            borderRadius: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            y: { min: 0, max: 100, grid: { color: '#1e293b' }, ticks: { color: '#64748b' } },
            x: { grid: { display: false }, ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } } }
          },
          plugins: {
            legend: { display: false }
          }
        }
      });
    }
  }

  _escapeHtml(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // ─── GMAIL INBOX INTEGRATION ───────────────────────────────
  async renderGmailInbox() {
    const content = document.getElementById('page-content');
    if (!content) return;

    content.innerHTML = `
      <div class="gmail-inbox-page animate-in" style="width:100%">
        <!-- Top Official Gmail Inbox Header Card -->
        <div class="gmail-header-card">
          <div class="gmail-header-left">
            <div class="gmail-header-icon">✉️</div>
            <div style="min-width:0">
              <div class="gmail-header-title-row">
                <h2 class="gmail-header-title">Official Gmail Inbox</h2>
                <span class="badge ${this.gmailConnected ? 'badge-pass' : 'badge-unknown'}" style="font-size:9.5px;letter-spacing:0.5px">
                  ${this.gmailConnected ? '🟢 OAUTH CONNECTED' : 'DEMO MODE'}
                </span>
              </div>
              <p class="gmail-header-desc">
                Official Google OAuth 2.0 integration &bull; Least-privilege read-only access (<code>gmail.readonly</code>) &bull; On-demand forensic &amp; AI threat analysis.
              </p>
            </div>
          </div>
          <div class="gmail-header-actions">
            <button class="btn btn-secondary btn-sm" onclick="app.loadGmailMessages()">🔄 Sync Mailbox</button>
            <button class="btn btn-secondary btn-sm" onclick="app.toggleOAuthHelpModal()">📋 OAuth Setup Guide</button>
            ${this.gmailConnected ? `
              <button class="btn btn-secondary btn-sm" style="border-color:var(--critical)40;color:var(--critical)" onclick="app.disconnectGmail()">Disconnect</button>
            ` : ''}
          </div>
        </div>

        <!-- Connection / Session Banner -->
        <div id="gmail-connect-banner-container">
          ${this._renderGmailConnectionBanner()}
        </div>

        <!-- Search & Filter Bar -->
        <div class="gmail-filter-bar">
          <div class="gmail-search-box">
            <span style="color:var(--text-muted);font-size:13px">🔍</span>
            <input type="text" id="gmail-search-input" value="${this._escapeHtml(this.activeGmailSearch)}" placeholder="Search emails by sender, subject or snippet..." oninput="app.filterGmailMessages(this.value)">
          </div>
          <div class="gmail-filter-group" id="gmail-filter-group">
            <button class="gmail-filter-btn ${this.activeGmailFilter === 'all' ? 'active' : ''}" data-filter="all" onclick="app.setGmailFilter('all')">All (<span id="count-all">${this.gmailMessages.length}</span>)</button>
            <button class="gmail-filter-btn ${this.activeGmailFilter === 'unread' ? 'active' : ''}" data-filter="unread" onclick="app.setGmailFilter('unread')">Unread (<span id="count-unread">${this.gmailMessages.filter(m => m.is_unread).length}</span>)</button>
            <button class="gmail-filter-btn ${this.activeGmailFilter === 'attachments' ? 'active' : ''}" data-filter="attachments" onclick="app.setGmailFilter('attachments')">📎 Attachments (<span id="count-attachments">${this.gmailMessages.filter(m => m.has_attachments).length}</span>)</button>
            <button class="gmail-filter-btn ${this.activeGmailFilter === 'analyzed' ? 'active' : ''}" data-filter="analyzed" onclick="app.setGmailFilter('analyzed')">🎯 Analyzed (<span id="count-analyzed">${this.gmailMessages.filter(m => (this.analysisState[m.id]?.status === 'completed') || m.threat_score != null).length}</span>)</button>
            <button class="gmail-filter-btn ${this.activeGmailFilter === 'pending' ? 'active' : ''}" data-filter="pending" onclick="app.setGmailFilter('pending')">Pending (<span id="count-pending">${this.gmailMessages.filter(m => (!this.analysisState[m.id] || this.analysisState[m.id]?.status !== 'completed') && m.threat_score == null).length}</span>)</button>
          </div>
        </div>

        <!-- Mail List Card -->
        <div class="card" style="padding:0;overflow:hidden;border:1px solid var(--border)">
          <div id="gmail-messages-table-container" class="gmail-table-container">
            ${this._renderGmailMessagesTable()}
          </div>
        </div>

        <!-- Setup Guide Modal (Hidden by Default) -->
        <div id="gmail-oauth-modal" style="display:none;position:fixed;inset:0;background:#060b16ee;z-index:99999;align-items:center;justify-content:center;backdrop-filter:blur(6px);padding:20px">
          <div class="card animate-in" style="width:680px;max-width:96vw;max-height:90vh;overflow-y:auto;border-color:var(--cyan)">
            <div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
              <div class="card-title" style="display:flex;align-items:center;gap:8px">
                <span>🔑</span>
                <span>Google Cloud OAuth 2.0 Setup Guide</span>
              </div>
              <button class="btn btn-secondary btn-sm" onclick="app.toggleOAuthHelpModal()">✕ Close</button>
            </div>
            <div class="card-body" style="padding:20px;font-size:13px;line-height:1.6;color:var(--text-secondary)">
              <p style="color:var(--text-primary);margin-top:0">
                To connect your real Gmail account to GmailGuard using official Google OAuth:
              </p>
              <ol style="padding-left:20px;margin-bottom:16px">
                <li style="margin-bottom:8px">
                  <strong style="color:var(--text-primary)">Google Cloud Console:</strong> Visit <a href="https://console.cloud.google.com/apis/credentials" target="_blank" class="text-cyan" style="text-decoration:none">console.cloud.google.com/apis/credentials</a> and create a Project.
                </li>
                <li style="margin-bottom:8px">
                  <strong style="color:var(--text-primary)">Enable Gmail API:</strong> Under APIs &amp; Services &rarr; Enable <strong>Gmail API</strong>.
                </li>
                <li style="margin-bottom:8px">
                  <strong style="color:var(--text-primary)">Configure OAuth Consent Screen:</strong> Set User Type to <em>External</em>, add your email under Test Users, and add scope <code>https://www.googleapis.com/auth/gmail.readonly</code>.
                </li>
                <li style="margin-bottom:8px">
                  <strong style="color:var(--text-primary)">Create OAuth Client ID:</strong> Choose <em>Web application</em>. Set Authorized Redirect URI:
                  <div style="background:var(--bg-input);padding:8px 12px;border-radius:4px;font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--cyan);margin:6px 0;border:1px solid var(--border)">
                    http://127.0.0.1:8000/api/gmail/oauth2callback
                  </div>
                </li>
                <li style="margin-bottom:8px">
                  <strong style="color:var(--text-primary)">Save Credentials:</strong> Download <code>client_secret.json</code> into <code>backend/</code>, or set environment variables in <code>backend/.env</code>:
                  <div style="background:var(--bg-input);padding:8px 12px;border-radius:4px;font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--cyan);margin:6px 0;border:1px solid var(--border)">
                    GMAIL_CLIENT_ID=your_client_id.apps.googleusercontent.com<br>
                    GMAIL_CLIENT_SECRET=your_client_secret
                  </div>
                </li>
              </ol>
              <div style="background:rgba(0,212,255,0.05);border:1px solid rgba(0,212,255,0.2);padding:12px;border-radius:var(--radius-sm);font-size:12px">
                ℹ️ <strong>Security &amp; Privacy Assurance:</strong> GmailGuard requests <strong>read-only</strong> access. Tokens are securely handled server-side and never exposed to JavaScript. Emails are only analyzed when you explicitly click <strong>[Analyze]</strong>.
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    // Sync status and messages on opening inbox
    await this.loadGmailStatus();
    if (this.gmailConnected || this.gmailMessages.length === 0) {
      await this.loadGmailMessages();
    }
  }

  _renderGmailConnectionBanner() {
    if (this.gmailConnected) {
      const analyzedCount = this.gmailMessages.filter(m => m.analyzed || m.threat_score != null || (this.analysisState[m.id]?.status === 'completed')).length;
      return `
        <div class="gmail-connect-banner">
          <div style="display:flex;align-items:center;gap:12px;min-width:0;flex:1">
            <div class="gmail-user-avatar">
              👤
            </div>
            <div style="min-width:0">
              <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
                <span style="font-weight:700;font-size:13.5px;color:var(--text-primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                  ${this.gmailUser?.email_address || 'Connected Google Account'}
                </span>
                <span class="badge badge-pass" style="font-size:9.5px;padding:2px 7px">ACTIVE SESSION</span>
              </div>
              <div style="font-size:11.5px;color:var(--text-muted);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                Mailbox Messages: <strong style="color:var(--cyan)">${(this.gmailUser?.messages_total || this.gmailMessages.length).toLocaleString()}</strong> &bull;
                Analyzed in Session: <strong style="color:#34d399">${analyzedCount}</strong> &bull;
                Scope: <code style="color:var(--text-secondary)">gmail.readonly</code>
              </div>
            </div>
          </div>
          <div style="display:flex;gap:8px;flex-shrink:0">
            <button class="btn btn-secondary btn-sm" onclick="app.loadGmailMessages()">🔄 Refresh Mailbox</button>
            <button class="btn btn-secondary btn-sm" style="color:var(--critical);border-color:var(--critical)40" onclick="app.disconnectGmail()">Disconnect</button>
          </div>
        </div>
      `;
    }

    return `
      <div class="gmail-connect-banner" style="background:rgba(13, 21, 39, 0.95);border:1px solid var(--border)">
        <div style="min-width:0;flex:1">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">
            <span style="font-size:18px">🔐</span>
            <strong style="font-size:14px;color:var(--text-primary)">Connect Your Real Google Account</strong>
            <span class="badge" style="background:#1a73e820;color:#60a5fa;border:1px solid #1a73e850;font-size:10px">OAuth 2.0 Official</span>
          </div>
          <div style="font-size:11.5px;color:var(--text-secondary);max-width:720px;line-height:1.4">
            Authenticate directly with Google to retrieve and inspect your live inbox. GmailGuard requests read-only access (<code>gmail.readonly</code>). Emails are only analyzed on demand.
          </div>
        </div>
        <div style="flex-shrink:0">
          <button class="gmail-google-btn" onclick="app.connectGmail()">
            <svg width="18" height="18" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.79l7.97-6.2z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>
            <span>Connect with Google</span>
          </button>
        </div>
      </div>
    `;
  }

  _getSenderAvatar(name = '', email = '') {
    const s = ((name || '') + ' ' + (email || '')).toLowerCase();
    if (s.includes('canara') || s.includes('bank') || s.includes('hdfc') || s.includes('sbi') || s.includes('icici')) {
      return `<div class="brand-avatar" style="background:#1e3a5f;color:#60a5fa" title="Banking Alert">🏛️</div>`;
    }
    if (s.includes('mind tree') || s.includes('talent') || s.includes('hiring') || s.includes('recruit')) {
      return `<div class="brand-avatar" style="background:#1e40af;color:#93c5fd" title="Recruitment / HR">👥</div>`;
    }
    if (s.includes('zomato') || s.includes('swiggy') || s.includes('food') || s.includes('order')) {
      return `<div class="brand-avatar" style="background:#dc2626;color:#ffffff;font-weight:800;font-size:12px" title="Zomato">Z</div>`;
    }
    if (s.includes('acm') || s.includes('technews') || s.includes('ieee')) {
      return `<div class="brand-avatar" style="background:#0284c7;color:#ffffff;font-size:10px;font-weight:800;letter-spacing:-0.5px" title="ACM">ACM</div>`;
    }
    if (s.includes('docker')) {
      return `<div class="brand-avatar" style="background:#0284c7;color:#ffffff" title="Docker">🐳</div>`;
    }
    if (s.includes('google') || s.includes('gmail')) {
      return `<div class="brand-avatar" style="background:#ffffff;color:#4285f4;font-weight:900;font-size:13px;border:1px solid #e2e8f0" title="Google"><span style="color:#4285f4">G</span></div>`;
    }
    if (s.includes('github') || s.includes('gitlab')) {
      return `<div class="brand-avatar" style="background:#24292f;color:#ffffff" title="GitHub">🐙</div>`;
    }
    if (s.includes('microsoft') || s.includes('office') || s.includes('azure')) {
      return `<div class="brand-avatar" style="background:#0078d4;color:#ffffff" title="Microsoft">🪟</div>`;
    }
    if (s.includes('amazon') || s.includes('aws')) {
      return `<div class="brand-avatar" style="background:#ff9900;color:#111827;font-weight:800" title="Amazon">📦</div>`;
    }
    // Default: Clean initial letter
    const initial = ((name || email || 'M').trim()[0] || 'M').toUpperCase();
    const hues = [200, 260, 160, 320, 220, 280];
    const charCode = (name || email || 'M').charCodeAt(0) || 65;
    const hue = hues[charCode % hues.length];
    return `<div class="brand-avatar" style="background:hsl(${hue},60%,20%);color:hsl(${hue},80%,70%);border:1px solid hsl(${hue},60%,35%)">${initial}</div>`;
  }

  _formatGmailDate(rawDate) {
    if (!rawDate) return '<span style="color:var(--text-muted)">Today</span>';
    const parts = String(rawDate).trim().split(/\s+/);
    if (parts.length >= 5) {
      const dayName = parts[0];
      const day = parts[1];
      const month = parts[2];
      const year = parts[3];
      const time = parts[4];
      const tz = parts.slice(5).join(' ');
      return `<div>${dayName} ${day} ${month} ${year}</div><div style="font-size:10px;color:var(--text-muted);margin-top:1px">${time} ${tz}</div>`;
    }
    return `<div>${this._escapeHtml(rawDate)}</div>`;
  }

  getPaginatedGmailMessages() {
    const allFiltered = this.getFilteredGmailMessages();
    const totalItems = allFiltered.length;
    const totalPages = Math.max(1, Math.ceil(totalItems / this.gmailPageSize));
    const currentPage = Math.min(Math.max(1, this.gmailCurrentPage), totalPages);
    this.gmailCurrentPage = currentPage;
    const startIdx = (currentPage - 1) * this.gmailPageSize;
    const items = allFiltered.slice(startIdx, startIdx + this.gmailPageSize);
    return {
      items,
      totalItems,
      totalPages,
      currentPage,
      startIdx
    };
  }

  setGmailPage(page) {
    this.gmailCurrentPage = page;
    this.renderCurrentGmailMessagesView();
  }

  _renderGmailMessagesTable(messagesList = null) {
    const paginated = messagesList ? {
      items: messagesList.slice(0, this.gmailPageSize),
      totalItems: messagesList.length,
      totalPages: Math.max(1, Math.ceil(messagesList.length / this.gmailPageSize)),
      currentPage: 1,
      startIdx: 0
    } : this.getPaginatedGmailMessages();

    const { items, totalItems, totalPages, currentPage, startIdx } = paginated;

    if (!items || items.length === 0) {
      return `
        <div style="text-align:center;padding:50px 20px;color:var(--text-muted)">
          <div style="font-size:36px;margin-bottom:12px">📭</div>
          <div style="font-size:15px;font-weight:600;color:var(--text-primary);margin-bottom:6px">No Emails Found</div>
          <div style="font-size:12px">No messages matched your current search or filter criteria. Click "Refresh Mailbox" to check for new mail.</div>
        </div>
      `;
    }

    let pageBtnsHtml = '';
    for (let p = 1; p <= totalPages; p++) {
      pageBtnsHtml += `
        <button class="gmail-page-btn ${p === currentPage ? 'active' : ''}" onclick="app.setGmailPage(${p})">${p}</button>
      `;
    }

    return `
      <table class="gmail-table">
        <colgroup>
          <col class="gmail-col-sender">
          <col class="gmail-col-subject">
          <col class="gmail-col-date">
          <col class="gmail-col-signals">
          <col class="gmail-col-score">
          <col class="gmail-col-verdict">
          <col class="gmail-col-action">
        </colgroup>
        <thead>
          <tr>
            <th>Sender</th>
            <th>Subject &amp; Snippet</th>
            <th>Date / Time</th>
            <th>Signals</th>
            <th style="text-align:center">Forensic Score</th>
            <th style="text-align:center">AI Verdict</th>
            <th style="text-align:right">Action</th>
          </tr>
        </thead>
        <tbody>
          ${items.map(m => this._renderGmailRowHtml(m)).join('')}
        </tbody>
      </table>

      <!-- Pagination Footer -->
      <div class="gmail-pagination-bar">
        <div class="gmail-pagination-info">
          Showing ${totalItems === 0 ? 0 : startIdx + 1}&ndash;${Math.min(startIdx + this.gmailPageSize, totalItems)} of ${totalItems} emails
        </div>
        <div class="gmail-pagination-controls">
          <button class="gmail-page-btn" ${currentPage <= 1 ? 'disabled' : ''} onclick="app.setGmailPage(${currentPage - 1})" title="Previous Page">&lt;</button>
          ${pageBtnsHtml}
          <button class="gmail-page-btn" ${currentPage >= totalPages ? 'disabled' : ''} onclick="app.setGmailPage(${currentPage + 1})" title="Next Page">&gt;</button>
        </div>
      </div>
    `;
  }

  _renderGmailRowHtml(m) {
    const state = this.analysisState[m.id] || {};
    const status = state.status || (m.threat_score != null || m.analysis_status === 'ANALYZED' ? 'completed' : 'idle');
    const isAnalyzing = status === 'analyzing';
    const isCompleted = status === 'completed' || m.threat_score != null || m.analyzed;
    const isError = status === 'error';

    const threatScore = state.threatScore != null ? state.threatScore : m.threat_score;
    const threatVerdict = state.verdict || m.threat_verdict || (threatScore != null ? (threatScore >= 70 ? 'HIGH_RISK' : threatScore >= 40 ? 'MEDIUM_RISK' : 'LOW_RISK') : null);

    let scoreColor = '#34d399';
    let scoreBg = 'rgba(52, 211, 153, 0.12)';
    let scoreBorder = 'rgba(52, 211, 153, 0.4)';
    if ((threatScore || 0) >= 70) {
      scoreColor = '#ff2d55';
      scoreBg = 'rgba(255, 45, 85, 0.15)';
      scoreBorder = 'rgba(255, 45, 85, 0.4)';
    } else if ((threatScore || 0) >= 40) {
      scoreColor = '#ff6b35';
      scoreBg = 'rgba(255, 107, 53, 0.12)';
      scoreBorder = 'rgba(255, 107, 53, 0.4)';
    }

    let verdictColor = '#34d399';
    let verdictBg = 'rgba(52, 211, 153, 0.12)';
    let verdictBorder = 'rgba(52, 211, 153, 0.4)';
    if (threatVerdict === 'CRITICAL' || threatVerdict === 'HIGH_RISK' || threatVerdict === 'SUSPICIOUS') {
      verdictColor = '#ff2d55';
      verdictBg = 'rgba(255, 45, 85, 0.15)';
      verdictBorder = 'rgba(255, 45, 85, 0.4)';
    } else if (threatVerdict === 'MEDIUM_RISK' || threatVerdict === 'CAUTION') {
      verdictColor = '#ff6b35';
      verdictBg = 'rgba(255, 107, 53, 0.12)';
      verdictBorder = 'rgba(255, 107, 53, 0.4)';
    }

    return `
      <tr class="gmail-row ${m.is_unread ? 'unread' : ''}" id="gmail-row-${m.id}">
        <td style="overflow:hidden">
          <div style="display:flex;align-items:center;gap:10px;min-width:0">
            ${this._getSenderAvatar(m.sender_name, m.sender_email)}
            <div style="min-width:0;flex:1;overflow:hidden">
              <div style="font-weight:700;color:var(--text-primary);font-size:12.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${this._escapeHtml(m.sender_name || m.sender_email)}">
                ${this._escapeHtml(m.sender_name || m.sender_email)}
              </div>
              <div style="font-size:11px;color:var(--text-muted);font-family:'JetBrains Mono',monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${this._escapeHtml(m.sender_email)}">
                ${this._escapeHtml(m.sender_email)}
              </div>
            </div>
          </div>
        </td>
        <td style="overflow:hidden">
          <div style="font-weight:600;color:var(--text-primary);font-size:12.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-bottom:2px" title="${this._escapeHtml(m.subject || '(No Subject)')}">
            ${this._escapeHtml(m.subject || '(No Subject)')}
          </div>
          <div style="font-size:11.5px;color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${this._escapeHtml(m.snippet || '')}">
            "${this._escapeHtml(m.snippet || '')}"
          </div>
        </td>
        <td style="font-size:11px;color:var(--text-secondary);font-family:'JetBrains Mono',monospace;line-height:1.35;overflow:hidden">
          ${this._formatGmailDate(m.date)}
        </td>
        <td style="overflow:hidden">
          <div style="display:flex;gap:4px;flex-wrap:wrap;align-items:center">
            ${m.has_urls ? '<span class="gmail-indicator-tag" title="Contains Links">🔗 URL</span>' : ''}
            ${m.has_attachments ? '<span class="gmail-indicator-tag" title="Contains Attachment">📎 File</span>' : ''}
            ${!m.has_urls && !m.has_attachments ? '<span style="color:var(--text-muted);font-size:11px">—</span>' : ''}
          </div>
        </td>
        <td style="text-align:center;overflow:hidden">
          ${isAnalyzing ? `
            <span style="color:var(--cyan);font-size:11px;font-weight:600">Scanning...</span>
          ` : isCompleted && threatScore != null ? `
            <span class="badge" style="background:${scoreBg};color:${scoreColor};border:1px solid ${scoreBorder};font-weight:700;font-family:'JetBrains Mono',monospace;font-size:11px;padding:3px 8px;display:inline-block">
              ${threatScore}/100
            </span>
          ` : isError ? `
            <span class="badge" style="background:var(--critical)20;color:var(--critical);border:1px solid var(--critical)60;font-size:10px" title="${this._escapeHtml(state.error || 'Failed')}">FAILED</span>
          ` : `
            <span class="badge badge-unknown" style="font-size:10px">NOT ANALYZED</span>
          `}
        </td>
        <td style="text-align:center;overflow:hidden">
          ${isCompleted && threatVerdict ? `
            <span class="badge" style="background:${verdictBg};color:${verdictColor};border:1px solid ${verdictBorder};font-size:10.5px;font-weight:700;padding:3px 8px;display:inline-block">
              ${threatVerdict}
            </span>
          ` : isError ? `
            <span style="font-size:11px;color:var(--critical)">Error</span>
          ` : `
            <span style="font-size:11px;color:var(--text-muted)">—</span>
          `}
        </td>
        <td style="text-align:right;white-space:nowrap;overflow:hidden">
          ${isAnalyzing ? `
            <button class="btn btn-secondary btn-sm gmail-action-btn scanning" disabled>
              <span class="pulse-dot" style="--pulse-color:var(--cyan);width:6px;height:6px;display:inline-block;margin-right:6px"></span>Scanning...
            </button>
          ` : isCompleted ? `
            <div style="display:inline-flex;gap:4px;align-items:center;justify-content:flex-end">
              <button class="btn btn-primary btn-sm gmail-action-btn view-btn" onclick="app.viewGmailAnalysis('${m.id}')">
                View <span style="font-size:9px;margin-left:3px">▼</span>
              </button>
              <button class="btn btn-secondary btn-sm" style="padding:4px 8px;font-size:11px" onclick="app.analyzeGmailMessage('${m.id}', true)" title="Re-run forensic pipeline">🔄</button>
            </div>
          ` : isError ? `
            <button class="btn btn-secondary btn-sm gmail-action-btn retry-btn" onclick="app.analyzeGmailMessage('${m.id}', true)">⚠️ Retry</button>
          ` : `
            <button class="btn btn-primary btn-sm gmail-action-btn" onclick="app.analyzeGmailMessage('${m.id}', false)">⚡ Analyze</button>
          `}
        </td>
      </tr>
    `;
  }

  // ─── B. ANALYZE EMAIL ──────────────────────────────────────
  renderAnalyze() {
    const content = document.getElementById('page-content');
    const { DEMO_EMAILS } = window.MAILFORENSICS_DATA;

    const demoCards = Object.entries(DEMO_EMAILS).map(([key, demo]) => {
      const riskColors = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)' };
      const color = riskColors[demo.risk] || 'var(--cyan)';
      return `
        <div class="demo-card" style="--accent:${color}" onclick="app.runDemoInvestigation('${key}')">
          <div class="demo-card-label">${demo.label}</div>
          <div class="demo-card-type" style="color:${color};font-size:11px;font-weight:700;">${demo.risk.toUpperCase()} SEVERITY VECTOR</div>
          <div class="demo-card-footer">
            <span style="font-size:11px;color:var(--text-muted)">Load & Analyze</span>
            <span class="badge badge-${demo.risk}">Demo EML</span>
          </div>
        </div>
      `;
    }).join('');

    content.innerHTML = `
      <div style="max-width:1100px;margin:0 auto">
        <!-- Hero Header -->
        <div style="text-align:center;margin-bottom:28px" class="animate-in">
          <div style="display:inline-flex;align-items:center;gap:10px;font-size:28px;font-weight:800;color:var(--text-primary);letter-spacing:1px">
            <span style="color:var(--cyan)">⬡ GmailGuard</span>
          </div>
          <div style="font-size:15px;color:var(--cyan);font-weight:600;letter-spacing:2px;text-transform:uppercase;margin-top:4px">
            See Beyond the Inbox
          </div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:6px">
            SIH 2026 Problem Statement SIH26106 — AI-Powered Threat Detection, GeoLocation & Forensic Intelligence
          </div>
        </div>

        <!-- Ingestion Grid -->
        <div class="grid-2 animate-in" style="gap:24px;align-items:start">
          <!-- Primary Input Panel -->
          <div>
            <div class="card mb-16">
              <div class="card-header">
                <div class="card-title">📥 Input Suspicious Email (.eml / RFC 5322)</div>
              </div>
              <div class="card-body">
                <!-- Dropzone for .eml -->
                <div class="upload-zone" id="upload-zone" onclick="document.getElementById('file-input').click()">
                  <input type="file" id="file-input" accept=".eml,.txt,.msg" style="display:none" onchange="app.handleFileInput(event)">
                  <div class="upload-icon">📧</div>
                  <div class="upload-title" id="upload-label-title">Upload .eml or Drag & Drop Here</div>
                  <div class="upload-subtitle" id="upload-label-sub">RFC 5322 email source file (Max 10MB)</div>
                  <div class="upload-formats">
                    <span class="format-badge">.eml</span>
                    <span class="format-badge">.txt</span>
                    <span class="format-badge">Raw MIME</span>
                  </div>
                </div>

                <div class="divider" style="margin:20px 0;display:flex;align-items:center;text-align:center;color:var(--text-muted);font-size:11px;text-transform:uppercase;letter-spacing:1px">
                  <span style="flex:1;height:1px;background:var(--border)"></span>
                  <span style="padding:0 12px">OR PASTE RAW EMAIL HEADERS & BODY</span>
                  <span style="flex:1;height:1px;background:var(--border)"></span>
                </div>

                <!-- Paste raw email textarea -->
                <textarea class="paste-area font-mono" id="paste-area" style="min-height:160px;font-size:11px" placeholder="Paste full RFC 5322 email source here including Received: headers and MIME body...
From: security@bank-alert.com
To: victim@example.com
Subject: Account Verification Required
Received: from mail.bank-alert.com (185.234.219.47) by mx.example.com...
"></textarea>

                <div style="display:flex;gap:10px;margin-top:16px">
                  <button class="btn btn-primary" id="btn-analyze-submit" style="flex:1;padding:12px 18px;font-size:14px" onclick="app.executeAnalysis()">
                    ⚡ Analyze Email with GmailGuard
                  </button>
                  <button class="btn btn-secondary" onclick="document.getElementById('paste-area').value='';app.activeFile=null;document.getElementById('upload-label-title').textContent='Upload .eml or Drag & Drop Here';">
                    🗑 Clear
                  </button>
                </div>
              </div>
            </div>
          </div>

          <!-- Pipeline & Demo Cards Panel -->
          <div>
            <div class="card mb-16">
              <div class="card-header">
                <div class="card-title">🔬 Pre-Loaded Forensic Test Cases</div>
              </div>
              <div class="card-body">
                <div class="demo-cards" style="grid-template-columns:1fr;gap:12px">
                  ${demoCards}
                </div>
              </div>
            </div>

            <!-- Pipeline Execution Overview Card -->
            <div class="card">
              <div class="card-header">
                <div class="card-title">⚙️ Backend Forensic Pipeline Modules</div>
              </div>
              <div class="card-body" style="padding:14px 16px">
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:11px;color:var(--text-secondary)">
                  <div>✓ RFC 5322 Parser</div>
                  <div>✓ SPF/DKIM/DMARC Alignment</div>
                  <div>✓ 4-Tier Candidate Relays</div>
                  <div>✓ Hop Timeline & Clock Skew</div>
                  <div>✓ IPinfo Geo Observables</div>
                  <div>✓ PhishTank Verified Feeds</div>
                  <div>✓ Domain Typosquatting</div>
                  <div>✓ Static Attachment Inspection</div>
                  <div>✓ Linear SVM Hyperplane</div>
                  <div>✓ Evidence Correlation Engine</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- In-Flight Scanning Progress Modal (Hidden by Default) -->
        <div id="scan-progress-overlay" style="display:none;position:fixed;inset:0;background:#060b16ee;z-index:9999;align-items:center;justify-content:center;backdrop-filter:blur(6px)">
          <div class="card animate-in" style="width:520px;max-width:92vw;border-color:var(--cyan);box-shadow:0 0 40px #00d4ff25">
            <div class="card-header" style="border-bottom:1px solid var(--border)">
              <div class="card-title text-cyan" style="display:flex;align-items:center;gap:8px">
                <div class="pulse-dot" style="--pulse-color:var(--cyan)"></div>
                <span>GmailGuard Multi-Vector Analysis in Progress</span>
              </div>
            </div>
            <div class="card-body" style="padding:20px">
              <div class="scan-step-list" id="scan-steps-container">
                <!-- Dynamically populated scan steps -->
              </div>
              <div style="font-size:11px;color:var(--text-muted);text-align:center;margin-top:16px">
                Authoritative telemetry directly synthesized by FastAPI backend (Port 8000)
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    // Wire Drag & Drop
    const zone = document.getElementById('upload-zone');
    if (zone) {
      zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
      zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
      zone.addEventListener('drop', e => {
        e.preventDefault();
        zone.classList.remove('drag-over');
        const file = e.dataTransfer.files[0];
        if (file) this.processFileSelection(file);
      });
    }
  }

  handleFileInput(e) {
    const file = e.target.files[0];
    if (file) this.processFileSelection(file);
  }

  processFileSelection(file) {
    this.activeFile = file;
    const titleEl = document.getElementById('upload-label-title');
    const subEl = document.getElementById('upload-label-sub');
    if (titleEl) titleEl.textContent = `Attached: ${file.name}`;
    if (subEl) subEl.textContent = `${(file.size / 1024).toFixed(1)} KB — Ready to analyze`;

    const reader = new FileReader();
    reader.onload = ev => {
      const pasteArea = document.getElementById('paste-area');
      if (pasteArea) pasteArea.value = ev.target.result;
      this.showToast(`Loaded ${file.name} (${(file.size / 1024).toFixed(1)} KB)`, 'info', '📎');
    };
    reader.readAsText(file);
  }

  runDemoInvestigation(key) {
    const { DEMO_EMAILS } = window.MAILFORENSICS_DATA;
    const demo = DEMO_EMAILS[key];
    if (!demo) return;

    this.activeFile = null;
    this.showToast(`Ingesting demo: ${demo.label.replace(/^[^\s]+\s/, '')}`, 'info', '🔬');
    this.executeAnalysis(demo.raw);
  }

  async executeAnalysis(overrideText = null) {
    if (this.isAnalyzing) return;

    const rawText = overrideText || document.getElementById('paste-area')?.value?.trim();
    if (!rawText && !this.activeFile) {
      this.showToast('Please upload a .eml file or paste email text to analyze', 'error', '⚠️');
      return;
    }

    this.isAnalyzing = true;
    const overlay = document.getElementById('scan-progress-overlay');
    const container = document.getElementById('scan-steps-container');
    if (overlay) overlay.style.display = 'flex';

    // Meaningful pipeline stages corresponding to actual backend execution
    const stages = [
      { id: 'parse', label: 'Parsing email (RFC 5322 structure, MIME components)' },
      { id: 'headers', label: 'Analyzing headers (Received chains, hop provenance)' },
      { id: 'auth', label: 'Checking authentication (SPF, DKIM, DMARC alignment)' },
      { id: 'iocs', label: 'Extracting IOCs (Observable IPs, domains, URLs)' },
      { id: 'urls', label: 'Analyzing URLs & domains (PhishTank feed, typosquatting)' },
      { id: 'infra', label: 'Analyzing infrastructure (Transit nodes, clock skew)' },
      { id: 'ml', label: 'Running ML analysis (Linear SVM hyperplane classifier)' },
      { id: 'correlate', label: 'Correlating evidence & positive mitigation factors' },
      { id: 'score', label: 'Generating forensic assessment & threat score' }
    ];

    if (container) {
      container.innerHTML = stages.map((s, idx) => `
        <div class="scan-step ${idx === 0 ? 'active' : 'pending'}" id="scan-step-${idx}">
          <div class="scan-step-icon">${idx === 0 ? '⏳' : '⚪'}</div>
          <div class="scan-step-name">${s.label}</div>
          <div class="scan-step-status font-mono">${idx === 0 ? 'Running...' : 'Queued'}</div>
        </div>
      `).join('');
    }

    // Launch backend API request in parallel
    const apiPromise = (async () => {
      try {
        if (this.activeFile) {
          return await window.GmailGuardAPI.analyzeEmailFile(this.activeFile);
        } else {
          return await window.GmailGuardAPI.analyzeEmailText(rawText);
        }
      } catch (err) {
        return { error: err.message };
      }
    })();

    // Animate stages smoothly while request executes
    let stageIdx = 0;
    const progressInterval = setInterval(() => {
      if (stageIdx < stages.length - 1) {
        const prev = document.getElementById(`scan-step-${stageIdx}`);
        if (prev) {
          prev.className = 'scan-step done';
          prev.querySelector('.scan-step-icon').textContent = '✓';
          prev.querySelector('.scan-step-status').textContent = 'Done';
        }
        stageIdx++;
        const curr = document.getElementById(`scan-step-${stageIdx}`);
        if (curr) {
          curr.className = 'scan-step active';
          curr.querySelector('.scan-step-icon').textContent = '⏳';
          curr.querySelector('.scan-step-status').textContent = 'Running...';
        }
      }
    }, 180);

    const res = await apiPromise;
    clearInterval(progressInterval);

    // Mark all steps done
    stages.forEach((_, idx) => {
      const step = document.getElementById(`scan-step-${idx}`);
      if (step) {
        step.className = 'scan-step done';
        step.querySelector('.scan-step-icon').textContent = '✓';
        step.querySelector('.scan-step-status').textContent = 'Done';
      }
    });

    await new Promise(r => setTimeout(r, 250));
    if (overlay) overlay.style.display = 'none';
    this.isAnalyzing = false;

    // Check response
    if (res.error) {
      this.showToast(`Analysis Failed: ${res.error}`, 'error', '❌');
      this.renderAnalysisError(res.error);
      return;
    }

    try {
      const normalized = window.ThreatReportNormalizer.normalize(res, rawText);
      this.currentResult = normalized;

      // Add to session investigations (deduplicate by caseId)
      const existingIdx = this.sessionInvestigations.findIndex(c => c.caseId === normalized.caseId);
      if (existingIdx >= 0) {
        this.sessionInvestigations[existingIdx] = normalized;
      } else {
        this.sessionInvestigations.unshift(normalized);
      }

      this.backendConnected = true;
      this.updateBackendStatus(true, this.backendInfo);
      this.showToast(`Analysis complete: ${normalized.verdict} (Threat Score: ${normalized.threatScore}/100)`, 'success', '🎯');

      // Navigate to investigation view
      this.navigateTo('investigation');
    } catch (normErr) {
      console.error('Normalization error:', normErr);
      this.showToast(`Failed to parse analysis report: ${normErr.message}`, 'error', '❌');
    }
  }

  renderAnalysisError(errorMsg) {
    const content = document.getElementById('page-content');
    content.innerHTML = `
      <div style="max-width:680px;margin:40px auto" class="animate-in">
        <div class="card" style="border-color:var(--critical)">
          <div class="card-header" style="border-bottom:1px solid #ff2d5530">
            <div class="card-title text-critical">❌ Email Analysis Engine Error</div>
          </div>
          <div class="card-body" style="padding:24px">
            <div style="font-size:14px;color:var(--text-primary);margin-bottom:12px;line-height:1.5">
              The FastAPI backend was unable to complete forensic evaluation for the submitted payload.
            </div>
            <div style="background:#080e1c;border:1px solid #ff2d5540;border-radius:6px;padding:12px 16px;font-family:'JetBrains Mono',monospace;font-size:12px;color:#ff6b35;margin-bottom:20px;word-break:break-all">
              ${errorMsg}
            </div>
            <div style="font-size:12px;color:var(--text-muted);margin-bottom:20px">
              <strong>Potential Causes:</strong>
              <ul style="padding-left:20px;margin-top:6px;line-height:1.6">
                <li>Backend server on <code style="color:var(--cyan)">http://127.0.0.1:8000</code> is offline or unreachable.</li>
                <li>Input text is malformed or does not adhere to standard RFC 5322 email headers.</li>
                <li>Payload exceeds server upload limit (Max 10MB).</li>
              </ul>
            </div>
            <div style="display:flex;gap:12px">
              <button class="btn btn-primary" onclick="app.navigateTo('analyze')">← Try Again</button>
              <button class="btn btn-secondary" onclick="app.showBackendDiagnostics()">Inspect Engine Status</button>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  openInvestigation(caseId) {
    const found = this.sessionInvestigations.find(c => c.caseId === caseId);
    if (found) {
      this.currentResult = found;
      this.navigateTo('investigation');
    }
  }

  // ─── C. INVESTIGATION / ANALYSIS RESULT ────────────────────
  renderInvestigation() {
    const content = document.getElementById('page-content');
    const r = this.currentResult;

    if (!r) {
      content.innerHTML = `
        <div class="card" style="max-width:600px;margin:60px auto;text-align:center;padding:40px 20px">
          <div style="font-size:48px;margin-bottom:12px">🔍</div>
          <div style="font-size:18px;font-weight:700;color:var(--text-primary);margin-bottom:8px">No Email Loaded for Investigation</div>
          <div style="font-size:13px;color:var(--text-muted);margin-bottom:24px">
            Ingest an email via file upload (.eml) or raw text to observe full forensic threat assessment.
          </div>
          <button class="btn btn-primary" onclick="app.navigateTo('analyze')">Go to Analyze Email →</button>
        </div>
      `;
      return;
    }

    const scoreColor = r.threatScore >= 80 ? '#ff2d55' : r.threatScore >= 60 ? '#ff6b35' : r.threatScore >= 35 ? '#ffd60a' : '#34d399';
    const scoreCircumference = 2 * Math.PI * 70;

    content.innerHTML = `
      <!-- Top Action Bar -->
      <div class="flex-center gap-12 mb-20" style="flex-wrap:wrap">
        <div>
          <div style="font-size:10px;color:var(--text-muted);letter-spacing:1px;text-transform:uppercase;margin-bottom:2px">Case Identifier</div>
          <div class="font-mono text-cyan" style="font-size:16px;font-weight:700">${r.caseId}</div>
        </div>
        <div style="flex:1;min-width:240px">
          <div style="font-size:10px;color:var(--text-muted);letter-spacing:1px;text-transform:uppercase;margin-bottom:2px">Subject</div>
          <div style="font-size:14px;font-weight:600;color:var(--text-primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${r.email?.subject || '(No Subject)'}</div>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn btn-secondary btn-sm" onclick="app.navigateTo('analyze')">← New Analysis</button>
          <button class="btn btn-secondary btn-sm" onclick="app.downloadReport()">📄 Export Report</button>
          <button class="btn btn-primary btn-sm" onclick="app.printReport()">🖨️ Print</button>
        </div>
      </div>

      <div class="results-layout">
        <!-- Left Sidebar Summary -->
        <div class="results-sidebar">
          <!-- Threat Score Gauge -->
          <div class="card animate-in">
            <div class="card-header">
              <div class="card-title">🎯 Threat Score & Verdict</div>
            </div>
            <div class="threat-score-widget">
              <div class="score-ring">
                <svg viewBox="0 0 160 160" xmlns="http://www.w3.org/2000/svg" width="160" height="160">
                  <circle class="score-ring-bg" cx="80" cy="80" r="70"/>
                  <circle class="score-ring-fill" cx="80" cy="80" r="70"
                    stroke="${scoreColor}"
                    stroke-dasharray="${scoreCircumference}"
                    stroke-dashoffset="${scoreCircumference}"
                    id="score-ring-fill"/>
                </svg>
                <div style="text-align:center;z-index:1">
                  <div class="score-number font-mono" style="color:${scoreColor}" id="score-display">0</div>
                  <div class="score-label font-mono">/ 100</div>
                </div>
              </div>

              <!-- Threat Assessment Spectrum Bar -->
              <div style="width:100%;margin-top:12px">
                <div style="display:flex;justify-content:space-between;font-size:10px;color:var(--text-muted);margin-bottom:4px;font-family:'JetBrains Mono',monospace">
                  <span style="color:#34d399">SAFE (0)</span>
                  <span style="color:#ffd60a">SUSPICIOUS (50)</span>
                  <span style="color:#ff2d55">HIGH RISK (100)</span>
                </div>
                <div style="height:6px;width:100%;background:linear-gradient(90deg,#34d399,#ffd60a,#ff6b35,#ff2d55);border-radius:3px;position:relative">
                  <div style="position:absolute;top:-4px;left:${Math.min(96, Math.max(4, r.threatScore))}%;width:6px;height:14px;background:#fff;border-radius:2px;box-shadow:0 0 6px #000;transform:translateX(-50%)"></div>
                </div>
              </div>

              <div class="risk-badge mt-16" style="background:${scoreColor}20;color:${scoreColor};border:2px solid ${scoreColor}60">
                ${r.verdict}
              </div>

              <div class="score-meta mt-16">
                <div class="score-meta-item">
                  <div class="score-meta-label">Observable IPs</div>
                  <div class="score-meta-value font-mono">${r.geolocation?.length || 0}</div>
                </div>
                <div class="score-meta-item">
                  <div class="score-meta-label">Total IOCs</div>
                  <div class="score-meta-value font-mono">${r.iocs?.length || 0}</div>
                </div>
              </div>
            </div>
          </div>

          <!-- Quick Authentication Status Card -->
          <div class="card animate-in animate-in-delay-1">
            <div class="card-header"><div class="card-title">🛡️ Authentication Summary</div></div>
            <div class="card-body">
              <div class="auth-grid">
                ${this._renderAuthMiniCard('SPF', r.authentication?.spf)}
                ${this._renderAuthMiniCard('DKIM', r.authentication?.dkim)}
                ${this._renderAuthMiniCard('DMARC', r.authentication?.dmarc)}
              </div>
              <div style="font-size:10px;color:var(--text-muted);margin-top:10px;line-height:1.4">
                ℹ️ Domain authentication validates transit integrity, not sender legitimacy.
              </div>
            </div>
          </div>

          <!-- Explainable Threat Score Breakdown -->
          <div class="card animate-in animate-in-delay-2">
            <div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
              <div class="card-title">📊 Threat Score Breakdown</div>
              <span class="badge ${r.threatScore >= 70 ? 'badge-critical' : r.threatScore >= 40 ? 'badge-high' : 'badge-pass'} font-mono">${r.threatScore}/100</span>
            </div>
            <div class="card-body" style="padding:12px 14px">
              ${r.scoreBreakdown && r.scoreBreakdown.components ? `
                <div style="display:flex;flex-direction:column;gap:8px">
                  ${r.scoreBreakdown.components.map(c => `
                    <div style="padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.06)">
                      <div style="display:flex;justify-content:space-between;align-items:center">
                        <span style="font-size:11px;font-weight:600;color:var(--text-primary)">${c.name}</span>
                        <span class="font-mono" style="font-size:11px;font-weight:700;color:${c.contribution > 0 ? (c.contribution >= 15 ? 'var(--critical)' : 'var(--high)') : 'var(--low)'}">
                          ${c.contribution > 0 ? `+${c.contribution}` : '+0'}
                        </span>
                      </div>
                      <div style="display:flex;justify-content:space-between;align-items:center;margin-top:2px">
                        <span style="font-size:10px;color:var(--text-muted);max-width:170px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${c.reason}">${c.reason}</span>
                        <span style="font-size:10px;color:var(--text-muted);font-family:monospace">${c.sub_score}/100</span>
                      </div>
                    </div>
                  `).join('')}
                  <div style="display:flex;justify-content:space-between;align-items:center;padding-top:6px;font-size:11px;color:var(--text-muted)">
                    <span>Base: <strong style="color:var(--text-primary)">${r.scoreBreakdown.base_score}</strong></span>
                    <span>URL Boost: <strong style="color:var(--text-primary)">+${r.scoreBreakdown.url_boost}</strong></span>
                    <span>Att Boost: <strong style="color:var(--text-primary)">+${r.scoreBreakdown.attachment_boost}</strong></span>
                  </div>
                </div>
              ` : (r.subScores ? `
                ${Object.entries(r.subScores).map(([k, v]) => `
                  <div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--border)">
                    <span style="font-size:11px;color:var(--text-secondary);text-transform:capitalize">${k.replace(/_/g, ' ')}</span>
                    <span class="font-mono" style="font-size:12px;font-weight:600;color:${v >= 50 ? 'var(--critical)' : v >= 25 ? 'var(--medium)' : 'var(--low)'}">${v}/100</span>
                  </div>
                `).join('')}
              ` : '')}
            </div>
          </div>
        </div>

        <!-- Right Main Panel -->
        <div class="results-main animate-in">
          <!-- Navigation Sub-Tabs -->
          <div class="results-tabs">
            <div class="result-tab active" data-tab="overview" onclick="app.switchInvestigationTab('overview')">📊 Overview & Why?</div>
            <div class="result-tab" data-tab="gemini" onclick="app.switchInvestigationTab('gemini')">🤖 Gemini Security</div>
            <div class="result-tab" data-tab="relays" onclick="app.switchInvestigationTab('relays')">🎯 Relays & Skew</div>
            <div class="result-tab" data-tab="network" onclick="app.switchInvestigationTab('network')">🌍 Network & Geo</div>
            <div class="result-tab" data-tab="urls" onclick="app.switchInvestigationTab('urls')">🔗 URLs & Domains</div>
            <div class="result-tab" data-tab="attachments" onclick="app.switchInvestigationTab('attachments')">📎 Attachments</div>
            <div class="result-tab" data-tab="ai" onclick="app.switchInvestigationTab('ai')">🤖 AI Content Analysis</div>
            <div class="result-tab" data-tab="graph" onclick="app.switchInvestigationTab('graph')">🕸️ Graph</div>
            <div class="result-tab" data-tab="iocs" onclick="app.switchInvestigationTab('iocs')">🚨 IOCs</div>
          </div>

          <!-- TAB 1: OVERVIEW & WHY SUSPICIOUS -->
          <div class="tab-panel active" id="inv-tab-overview">
            <!-- Observational Scope Disclaimer -->
            <div class="scope-disclaimer-card">
              <div class="scope-disclaimer-icon">⚖️</div>
              <div>
                <div class="scope-disclaimer-title">Forensic Scope & Observational Taxonomy</div>
                <div class="scope-disclaimer-text">${r.forensicScope}</div>
              </div>
            </div>

            <!-- Gemini Plain-Language Executive Finding Callout -->
            ${this._renderGeminiOverviewCallout(r)}

            <!-- "Why was this email classified this way?" Card -->
            <div class="card mb-16" style="border-left:4px solid ${scoreColor}">
              <div class="card-header">
                <div class="card-title" style="font-size:14px">
                  🔍 Why Was This Email Classified as <span style="color:${scoreColor}">${r.verdict}</span>?
                </div>
              </div>
              <div class="card-body">
                <div style="font-size:12px;color:var(--text-secondary);margin-bottom:14px;line-height:1.5">
                  GmailGuard correlates independent forensic signals across email envelope, headers, observable infrastructure, URL intelligence, and linguistic classification. No single indicator alone dictates maliciousness.
                </div>
                ${(r.evidence && r.evidence.length > 0) ? `
                  <div style="display:flex;flex-direction:column;gap:10px">
                    ${r.evidence.map(e => {
                      const impColor = (e.impact || 0) >= 20 ? 'var(--critical)' : (e.impact || 0) >= 10 ? 'var(--high)' : 'var(--medium)';
                      return `
                        <div style="padding:12px;background:var(--bg-input);border-radius:var(--radius-sm);border:1px solid var(--border);border-left:3px solid ${impColor}">
                          <div style="display:flex;justify-content:space-between;align-items:center">
                            <div style="font-weight:700;font-size:13px;color:var(--text-primary)">${e.signal}</div>
                            <span class="badge" style="background:${impColor}20;color:${impColor};border:1px solid ${impColor}50">+${e.impact || 0} pts</span>
                          </div>
                          <div style="font-size:12px;color:var(--text-secondary);margin-top:4px;line-height:1.4">${e.explanation}</div>
                        </div>
                      `;
                    }).join('')}
                  </div>
                ` : '<div style="font-size:12px;color:var(--text-muted)">No adverse threat indicators identified.</div>'}
              </div>
            </div>

            <!-- Mitigating / Positive Signals -->
            ${(r.positiveEvidence && r.positiveEvidence.length > 0) ? `
            <div class="card mb-16">
              <div class="card-header">
                <div class="card-title text-low">🛡️ Mitigating & Positive Indicators (${r.positiveEvidence.length})</div>
              </div>
              <div class="card-body">
                <div class="positive-evidence-list">
                  ${r.positiveEvidence.map(p => `
                    <div class="pos-ev-item">
                      <div>
                        <div class="pos-ev-title">✓ ${p.signal}</div>
                        <div class="pos-ev-desc">${p.explanation}</div>
                      </div>
                      ${p.impact ? `<span class="badge badge-pass" style="margin-left:auto">-${Math.abs(p.impact)} pts</span>` : ''}
                    </div>
                  `).join('')}
                </div>
              </div>
            </div>` : ''}

            <!-- Email Envelope Metadata Overview -->
            <div class="card mb-16">
              <div class="card-header"><div class="card-title">📧 Email Envelope Metadata Overview</div></div>
              <div class="card-body">
                <div class="grid-2">
                  ${[
                    ['From', r.email?.from || 'Not available'],
                    ['To', r.email?.to || 'Not available'],
                    ['Subject', r.email?.subject || 'Not available'],
                    ['Date', r.email?.date || 'Not available'],
                    ['Sender Domain', r.email?.senderDomain || 'Not available'],
                    ['Reply-To', (r.email?.replyTo || 'Not available') + (r.email?.replyToDiffers ? ' ⚠️ (Differs from From)' : '')],
                    ['Return-Path', r.email?.returnPath || 'Not available'],
                    ['Message-ID', r.email?.messageId || 'Not available'],
                  ].map(([k, v]) => `
                    <div style="padding:10px;background:var(--bg-input);border-radius:var(--radius-sm);border:1px solid var(--border)">
                      <div style="font-size:10px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">${k}</div>
                      <div class="font-mono" style="font-size:12px;color:var(--text-primary);word-break:break-all">${v}</div>
                    </div>
                  `).join('')}
                </div>

                <!-- Sender IP Observability Notice -->
                <div style="margin-top:14px;padding:12px 14px;background:var(--bg-input);border-radius:var(--radius-sm);border:1px solid var(--border);border-left:3px solid ${r.senderIp?.isObservable ? 'var(--medium)' : 'var(--cyan)'}">
                  <div style="display:flex;justify-content:space-between;align-items:center">
                    <div style="font-size:11px;font-weight:700;color:var(--text-muted);text-transform:uppercase">Sender Originating Device IP</div>
                    <span class="badge ${r.senderIp?.isObservable ? 'badge-medium' : 'badge-low'}">${r.senderIp?.isObservable ? 'Client Reported' : 'Not Observable'}</span>
                  </div>
                  <div class="font-mono" style="font-size:13px;font-weight:700;color:${r.senderIp?.isObservable ? 'var(--medium)' : 'var(--cyan)'};margin-top:3px">
                    ${r.senderIp?.value}
                  </div>
                  <div style="font-size:11px;color:var(--text-secondary);margin-top:4px;line-height:1.4">
                    ${r.senderIp?.reason}
                  </div>
                </div>
              </div>
            </div>

            <!-- Sender Domain Intelligence (Envelope From Domain) -->
            ${r.domain ? `
            <div class="card mb-16">
              <div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
                <div class="card-title">🔍 Sender Email Domain Intelligence (${r.domain?.domain || r.email?.senderDomain || 'N/A'})</div>
                <span class="badge badge-outline" style="border-color:var(--cyan);color:var(--cyan);font-size:10px">Email Transport Envelope Domain</span>
              </div>
              <div class="card-body">
                <div class="grid-2">
                  <div class="info-card"><div class="info-label">Sender Domain Name</div><div class="info-value font-mono">${r.domain?.domain}</div></div>
                  <div class="info-card"><div class="info-label">Domain Age</div><div class="info-value">${r.domain?.ageDays != null ? r.domain.ageDays + ' days' : 'Not available'} ${r.domain?.ageDays != null && r.domain.ageDays < 30 ? '<span class="badge badge-fail" style="margin-left:6px">Newly Registered</span>' : ''}</div></div>
                  <div class="info-card"><div class="info-label">Registrar</div><div class="info-value">${r.domain?.registrar || 'Unknown'}</div></div>
                  <div class="info-card"><div class="info-label">Typosquatting Check</div><div class="info-value">${r.domain?.isTyposquat ? '<span class="badge badge-fail">TYPOSQUAT TARGET: ' + r.domain.typosquatTarget + '</span>' : 'None detected'}</div></div>
                </div>
              </div>
            </div>` : ''}
          </div>

          <!-- TAB: GEMINI SECURITY -->
          <div class="tab-panel" id="inv-tab-gemini">
            ${this._renderActiveEmailGeminiReport(r)}
          </div>

          <!-- TAB 2: RELAYS & SKEW -->
          <div class="tab-panel" id="inv-tab-relays">
            <!-- 4-Tier Candidate Relays -->
            <div class="card mb-16">
              <div class="card-header">
                <div class="card-title">🎯 Candidate Originating / Upstream Relays (4-Tier Taxonomy)</div>
              </div>
              <div class="card-body" style="padding:0">
                ${(r.candidateRelays && r.candidateRelays.length > 0) ? `
                  <table class="candidate-table">
                    <thead>
                      <tr>
                        <th>Tier</th>
                        <th>Provenance</th>
                        <th>Relay IP</th>
                        <th>Provider</th>
                        <th>Confidence</th>
                        <th>Evidence Class</th>
                        <th>Trust Rationale</th>
                      </tr>
                    </thead>
                    <tbody>
                      ${r.candidateRelays.map(c => `
                        <tr>
                          <td><span class="tier-pill tier-${c.tier || 1}">Tier ${c.tier}</span></td>
                          <td><span class="badge badge-unknown">${c.tierName}</span></td>
                          <td><strong class="font-mono">${c.ip}</strong></td>
                          <td>${c.provider}</td>
                          <td><span class="badge badge-${c.confidence === 'high' ? 'pass' : c.confidence === 'medium' ? 'medium' : 'low'}">${(c.confidence || 'medium').toUpperCase()}</span></td>
                          <td><span class="font-mono text-cyan" style="font-size:11px">${c.evidenceClass}</span></td>
                          <td style="font-size:11px;color:var(--text-secondary);max-width:280px">${c.rankingDisclaimer}</td>
                        </tr>
                      `).join('')}
                    </tbody>
                  </table>
                ` : '<div style="padding:20px;color:var(--text-muted)">No candidate relays extracted from headers.</div>'}
              </div>
            </div>

            <!-- Mail Server Hop Chain -->
            <div class="card mb-16">
              <div class="card-header">
                <div class="card-title">🔗 Mail Server Transit Hop Chain (${r.chronologicalHops?.length || 0} Hops)</div>
              </div>
              <div class="card-body">
                ${(r.chronologicalHops && r.chronologicalHops.length > 0) ? `
                  <div class="hop-chain">
                    ${r.chronologicalHops.map((h, i) => `
                      <div class="hop-item">
                        <div class="hop-num font-mono">#${h.hopNumber}</div>
                        <div class="hop-content">
                          <div class="hop-route font-mono">${h.fromHost} → ${h.byHost}</div>
                          <div class="hop-detail">
                            ${h.ip ? `IP: <span class="font-mono">${h.ip}</span> (${h.provider}) &nbsp;|&nbsp; ` : ''}
                            <span class="badge badge-unknown" style="font-size:9px">${h.provenance}</span> &nbsp;|&nbsp;
                            <span style="color:var(--text-muted)">${h.timestampRaw}</span>
                          </div>
                        </div>
                        <div class="hop-evidence"><span class="badge badge-low">${h.evidenceClass}</span></div>
                      </div>
                    `).join('')}
                  </div>
                ` : '<div style="color:var(--text-muted)">No chronological transit hops detected.</div>'}
              </div>
            </div>

            <!-- Timeline & Clock Skew -->
            ${(r.timelineAnalysis && r.timelineAnalysis.hopDiffs && r.timelineAnalysis.hopDiffs.length > 0) ? `
            <div class="card mb-16">
              <div class="card-header"><div class="card-title">⏱️ Hop Timeline & Clock Skew Analysis</div></div>
              <div class="card-body">
                <div class="skew-metric-grid mb-16">
                  <div class="skew-metric-card">
                    <div class="skew-metric-label">Hops Evaluated</div>
                    <div class="skew-metric-val text-cyan font-mono">${r.timelineAnalysis.hopsEvaluated}</div>
                  </div>
                  <div class="skew-metric-card">
                    <div class="skew-metric-label">Max Hop Delay</div>
                    <div class="skew-metric-val font-mono">${r.timelineAnalysis.maxHopDelaySec != null ? r.timelineAnalysis.maxHopDelaySec + 's' : 'N/A'}</div>
                  </div>
                  <div class="skew-metric-card">
                    <div class="skew-metric-label">Clock Skew Anomalies</div>
                    <div class="skew-metric-val font-mono ${r.timelineAnalysis.anomalies?.length ? 'text-critical' : 'text-low'}">
                      ${r.timelineAnalysis.anomalies?.length || 0}
                    </div>
                  </div>
                </div>
                <table class="candidate-table">
                  <thead>
                    <tr>
                      <th>Transition</th>
                      <th>Delta Seconds</th>
                      <th>Tolerance (±120s)</th>
                      <th>Anomaly Note</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${r.timelineAnalysis.hopDiffs.map(d => `
                      <tr>
                        <td>Hop ${d.fromHop} → Hop ${d.toHop}</td>
                        <td class="font-mono"><strong>${d.deltaSeconds}s</strong></td>
                        <td><span class="badge badge-${d.withinTolerance ? 'pass' : 'fail'}">${d.withinTolerance ? 'NORMAL' : 'SKEW DETECTED'}</span></td>
                        <td style="font-size:11px;color:${d.anomaly ? 'var(--critical)' : 'var(--low)'}">${d.anomaly || 'Timing consistent'}</td>
                      </tr>
                    `).join('')}
                  </tbody>
                </table>
              </div>
            </div>` : ''}

            <!-- Raw RFC 5322 Headers viewer -->
            <div class="card">
              <div class="card-header">
                <div class="card-title">📝 Raw Email Headers</div>
                <button class="btn btn-secondary btn-sm" onclick="navigator.clipboard.writeText(app.currentResult.rawHeaders);app.showToast('Headers copied!','success','📋')">Copy Headers</button>
              </div>
              <div class="card-body" style="padding:0">
                <div class="raw-headers">${this._colorizeHeaders(r.rawHeaders || '')}</div>
              </div>
            </div>
          </div>

          <!-- TAB 3: NETWORK & GEO -->
          <div class="tab-panel" id="inv-tab-network">
            <!-- Timezone Divergence Card -->
            ${r.timezoneCorrelation ? `
            <div class="timezone-card mb-16">
              <div style="font-size:11px;font-weight:700;text-transform:uppercase;color:var(--cyan);letter-spacing:1px;margin-bottom:8px">
                🌐 Header vs Observable IP Timezone Correlation
              </div>
              <div class="grid-3" style="margin-bottom:10px">
                <div><span style="font-size:10px;color:var(--text-muted);text-transform:uppercase">Header Date Claim</span><div class="font-mono" style="font-size:12px;margin-top:2px">${r.timezoneCorrelation.headerTz}</div></div>
                <div><span style="font-size:10px;color:var(--text-muted);text-transform:uppercase">Observable IP Timezone</span><div class="font-mono" style="font-size:12px;margin-top:2px">${r.timezoneCorrelation.geoTz}</div></div>
                <div><span style="font-size:10px;color:var(--text-muted);text-transform:uppercase">Timezone Divergence</span><div style="margin-top:2px"><span class="divergence-pill ${r.timezoneCorrelation.divergenceHours > 4 ? 'divergence-high' : 'divergence-normal'}">${r.timezoneCorrelation.divergenceHours} Hours</span></div></div>
              </div>
              <div style="font-size:11px;color:var(--text-secondary);line-height:1.4">${r.timezoneCorrelation.divergenceNote}</div>
            </div>` : ''}

            <!-- Observable Geolocation Cards -->
            <div class="card">
              <div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
                <div class="card-title">🌍 Observable Mail Infrastructure Geolocation (${r.geolocation?.length || 0})</div>
                <div style="font-size:11px;color:var(--text-muted)">
                  Observable Sender IP: <strong class="font-mono" style="color:${r.senderIp && r.senderIp !== 'NOT_OBSERVABLE' ? 'var(--cyan)' : 'var(--text-muted)'}">${r.senderIp || 'NOT_OBSERVABLE'}</strong>
                </div>
              </div>
              <div class="card-body">
                <div style="font-size:11px;color:var(--text-muted);margin-bottom:14px">
                  CRITICAL RULE: Geolocation coordinates represent public transit relay infrastructure, NOT verified physical sender locations.
                </div>
                ${(r.geolocation && r.geolocation.length > 0) ? `
                  <div class="geo-list">
                    ${r.geolocation.map(g => `
                      <div class="geo-item">
                        <div class="geo-flag">${g.flag || '🌐'}</div>
                        <div style="flex:1">
                          <div style="display:flex;align-items:center;gap:8px">
                            <div class="geo-ip font-mono">${g.ip}</div>
                            <span class="badge ${g.status === 'SUCCESS' ? 'badge-low' : 'badge-medium'}" style="font-size:9px">IPinfo: ${g.status || 'SUCCESS'}</span>
                            <span class="badge badge-outline" style="font-size:9px;color:var(--text-muted)">${g.source || 'IPinfo'}</span>
                          </div>
                          <div class="geo-location">${g.city || 'Unknown'}, ${g.region ? g.region + ', ' : ''}${g.country || 'Unknown'}</div>
                          <div class="geo-org font-mono" style="font-size:11px">${g.asn || ''} • ${g.org || 'Unknown'} &nbsp;|&nbsp; TZ: ${g.timezone}</div>
                          ${g.reason ? `<div style="font-size:10px;color:var(--amber);margin-top:2px">⚠️ Note: ${g.reason}</div>` : ''}
                          <div style="font-size:10px;color:var(--text-muted);margin-top:3px">ℹ️ ${g.forensicNote}</div>
                        </div>
                        <div class="geo-right">
                          <span class="badge badge-medium" style="font-size:10px">${g.locationType}</span>
                        </div>
                      </div>
                    `).join('')}
                  </div>
                ` : '<div style="color:var(--text-muted)">No routable public IPs observed in headers. Sender IP: <code>NOT_OBSERVABLE</code></div>'}
              </div>
            </div>
          </div>

          <!-- TAB 4: URLS & DOMAINS -->
          <div class="tab-panel" id="inv-tab-urls">
            <!-- URL Intelligence -->
            <div class="card mb-16">
              <div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
                <div class="card-title">🔗 Extracted URLs & Threat Intelligence (${r.urls?.length || 0})</div>
                <div style="display:flex;gap:8px;align-items:center">
                  <span class="badge badge-outline" style="border-color:var(--cyan);color:var(--cyan);font-size:10px">🛡️ Local Browserless Sandbox (Chromium Docker)</span>
                  <span class="badge badge-outline" style="border-color:var(--border-color);color:var(--text-muted);font-size:10px">Ephemeral Container Isolation</span>
                </div>
              </div>
              <div class="card-body">
                <div style="font-size:11px;color:var(--text-muted);margin-bottom:12px">
                  ℹ️ Security Policy: URLs are handled as immutable forensic data, dynamically evaluated inside an isolated local Browserless Chromium container with strict SSRF controls.
                </div>
                ${(r.urls && r.urls.length > 0) ? `
                  <div style="display:flex;flex-direction:column;gap:12px">
                    ${r.urls.map(u => `
                      <div class="url-item" style="display:flex;flex-direction:column;gap:8px;padding:12px;background:#060d1b;border:1px solid rgba(255,255,255,0.06);border-radius:6px">
                        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
                          <span>${(u.sandbox && u.sandbox.is_malicious) || u.isPhishTankVerified || u.isIpUrl ? '🔴' : (u.sandbox && u.sandbox.verdict === 'SUSPICIOUS') ? '🟠' : '🟡'}</span>
                          <span class="url-text font-mono" style="font-weight:600">${u.url}</span>
                          ${u.sandbox ? `
                            <span class="badge" style="background:#132035;color:var(--text-muted);font-size:9px">SANDBOX: ${u.sandbox.status || 'COMPLETED'}</span>
                            ${u.sandbox.status === 'ERROR' || u.sandbox.status === 'TIMEOUT' || u.sandbox.status === 'FAILED' ? `
                              <span class="badge badge-high" style="font-size:10px">⚠️ Sandbox: ${u.sandbox.status} (${u.sandbox.error || 'Failed'})</span>
                            ` : u.sandbox.status === 'BLOCKED' ? `
                              <span class="badge badge-critical" style="font-size:10px">🛡️ SSRF Blocked</span>
                            ` : u.sandbox.content_category === 'ADULT_CONTENT' || (u.sandbox.behavior_indicators && u.sandbox.behavior_indicators.includes('ADULT_CONTENT_DETECTED')) ? `
                              <span class="badge badge-high" style="font-size:10px">⚠️ Adult Content Detected</span>
                            ` : `
                              <span class="badge badge-${u.sandbox.verdict === 'MALICIOUS' ? 'critical' : u.sandbox.verdict === 'SUSPICIOUS' ? 'high' : u.sandbox.verdict === 'CLEAN' ? 'low' : 'medium'}" style="font-size:10px">
                                🛡️ Browser Sandbox: ${u.sandbox.verdict} (${u.sandbox.malicious_score}/100)
                              </span>
                            `}
                          ` : ''}
                          ${u.isPhishTankVerified ? `<span class="badge badge-phishtank">🚨 PhishTank #${u.phishTankId || 'MATCH'} (Target: ${u.phishTankTarget || 'Brand'})</span>` : ''}
                          ${u.isIpUrl ? '<span class="badge badge-critical">IP-Based URL</span>' : ''}
                          <span class="badge badge-${u.riskScore >= 50 ? 'critical' : u.riskScore >= 25 ? 'high' : 'low'}">Risk: ${u.riskScore}</span>
                        </div>

                        ${u.sandbox ? (() => {
                          const stripSlash = (s) => s && s.endsWith('/') ? s.slice(0, -1) : (s || '');
                          const isRedirect = u.sandbox.effective_url && stripSlash(u.sandbox.effective_url).toLowerCase() !== stripSlash(u.url).toLowerCase();
                          return `
                          <div style="font-size:11px;color:var(--text-secondary);background:rgba(0,0,0,0.3);padding:10px 12px;border-radius:6px;border:1px solid rgba(0,212,255,0.12);display:flex;flex-direction:column;gap:6px">
                            <div style="display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid rgba(255,255,255,0.05);padding-bottom:6px">
                              <span style="color:var(--cyan);font-weight:600">🌐 Browserless Telemetry & Observable Behavior</span>
                              <span style="font-size:10px;color:var(--text-muted)">Mode: <strong>${u.sandbox.mode || 'LIVE'}</strong> | Status: <strong>${u.sandbox.status}</strong></span>
                            </div>

                            ${isRedirect ? `
                              <div style="color:var(--amber);background:rgba(245,158,11,0.08);padding:6px 8px;border-radius:4px">
                                <strong>↪ Final Effective URL:</strong> <span class="font-mono" style="word-break:break-all">${u.sandbox.effective_url}</span>
                                ${u.sandbox.redirects && u.sandbox.redirects.length > 0 ? `
                                  <div style="font-size:10px;color:var(--text-muted);margin-top:3px">
                                    Chain: ${u.sandbox.redirects.map(r => `${r.from} ➔ ${r.to}`).join(' | ')}
                                  </div>
                                ` : ''}
                              </div>
                            ` : `
                              <div><strong>Effective URL:</strong> <span class="font-mono" style="word-break:break-all">${u.sandbox.effective_url || u.url}</span></div>
                            `}

                            <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(200px, 1fr));gap:8px;background:rgba(255,255,255,0.02);padding:6px 8px;border-radius:4px">
                              <div><strong>Server:</strong> ${u.sandbox.page_info?.server || 'Unknown'} (HTTP ${u.sandbox.page_info?.status_code || '200'})</div>
                              <div><strong>Resolved IP:</strong> ${u.sandbox.page_info?.ip || 'N/A'}</div>
                              <div><strong>Contacted Domains:</strong> ${(u.sandbox.contacted_domains || []).slice(0, 4).join(', ') || 'N/A'}</div>
                              <div><strong>Contacted IPs:</strong> ${(u.sandbox.contacted_ips || []).slice(0, 4).join(', ') || 'N/A'}</div>
                              ${u.sandbox.network_requests ? `<div><strong>Network Events:</strong> ${u.sandbox.network_requests.length} requests captured</div>` : ''}
                            </div>

                            ${u.sandbox.downloads && u.sandbox.downloads.length > 0 ? `
                              <div style="color:var(--red);background:rgba(239,68,68,0.1);padding:6px 8px;border-radius:4px;font-weight:600">
                                ⚠️ Intercepted Payload Download (Quarantined): ${u.sandbox.downloads.map(d => `${d.filename} (${d.mime_type || 'binary'})`).join(', ')}
                              </div>
                            ` : ''}

                            ${(u.sandbox.console_errors && u.sandbox.console_errors.length > 0) || (u.sandbox.page_errors && u.sandbox.page_errors.length > 0) ? `
                              <div style="color:var(--amber);background:rgba(245,158,11,0.06);padding:6px 8px;border-radius:4px;font-size:10px">
                                <strong>⚠️ Page / Console Errors (${(u.sandbox.console_errors?.length || 0) + (u.sandbox.page_errors?.length || 0)}):</strong>
                                <ul style="margin:2px 0 0 16px;padding:0">
                                  ${(u.sandbox.console_errors || []).slice(0, 3).map(e => `<li>${e}</li>`).join('')}
                                  ${(u.sandbox.page_errors || []).slice(0, 2).map(e => `<li>${e}</li>`).join('')}
                                </ul>
                              </div>
                            ` : ''}

                            ${u.sandbox.behavior_indicators && u.sandbox.behavior_indicators.length > 0 ? `
                              <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
                                <span style="font-size:10px;color:var(--text-muted)"><strong>Behavior Findings:</strong></span>
                                ${u.sandbox.behavior_indicators.map(ind => `
                                  <span class="badge" style="background:#172554;color:#93c5fd;font-size:9px">${ind}</span>
                                `).join('')}
                              </div>
                            ` : ''}

                            ${u.sandbox.reasons && u.sandbox.reasons.length > 0 ? `
                              <div style="font-size:10px;color:var(--text-muted)">
                                <strong>Notes:</strong> ${u.sandbox.reasons.join(' • ')}
                              </div>
                            ` : ''}

                            ${u.sandbox.screenshot_url ? `
                              <div style="margin-top:6px;border-top:1px solid rgba(255,255,255,0.06);padding-top:6px">
                                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
                                  <span style="font-weight:600;color:var(--cyan)">📸 Live Isolated Browser Screenshot:</span>
                                  <a href="${u.sandbox.screenshot_url}" target="_blank" rel="noopener noreferrer" style="color:var(--cyan);text-decoration:none;font-size:11px">
                                    Open Fullscreen ↗
                                  </a>
                                </div>
                                <div style="border-radius:6px;overflow:hidden;border:1px solid rgba(0,212,255,0.25);background:#020617;max-width:480px">
                                  <a href="${u.sandbox.screenshot_url}" target="_blank" rel="noopener noreferrer">
                                    <img src="${u.sandbox.screenshot_url}" alt="Sandbox Screenshot for ${u.url}" style="width:100%;max-height:240px;object-fit:cover;object-position:top;display:block" />
                                  </a>
                                </div>
                              </div>
                            ` : ''}
                          </div>
                        `;})() : ''}
                      </div>
                    `).join('')}
                  </div>
                ` : '<div style="color:var(--text-muted)">No URLs detected in message body.</div>'}
              </div>
            </div>


            <!-- Forensic Domain Attribution & Separation -->
            <div class="card">
              <div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
                <div class="card-title">🔍 Forensic Domain Attribution & Disambiguation</div>
                <span class="badge badge-outline" style="border-color:var(--cyan);color:var(--cyan);font-size:10px">RFC Domain Isolation</span>
              </div>
              <div class="card-body">
                <div style="font-size:11px;color:var(--text-muted);margin-bottom:12px">
                  ℹ️ <strong>Forensic Principle:</strong> Sender email transport domain, body URL target domains, and sandbox contacted domains operate across distinct security boundaries and are evaluated independently.
                </div>
                <div class="grid-2" style="gap:12px">
                  <div class="info-card" style="border-left:3px solid var(--cyan)">
                    <div class="info-label">📧 Sender Envelope Domain (Transport)</div>
                    <div class="info-value font-mono">${r.email?.senderDomain || r.domain?.domain || 'N/A'}</div>
                    <div style="font-size:10px;color:var(--text-muted);margin-top:4px">Originating envelope from address</div>
                  </div>
                  <div class="info-card" style="border-left:3px solid var(--medium)">
                    <div class="info-label">🔗 Body URL Target Domain(s) (Payload)</div>
                    <div class="info-value font-mono">${(r.urls && r.urls.length > 0) ? [...new Set(r.urls.map(u => u.domain).filter(Boolean))].join(', ') : 'None'}</div>
                    <div style="font-size:10px;color:var(--text-muted);margin-top:4px">Target domains extracted from message body</div>
                  </div>
                  <div class="info-card" style="border-left:3px solid #8b5cf6">
                    <div class="info-label">↪ Final Effective Destination(s)</div>
                    <div class="info-value font-mono">
                      ${(r.urls && r.urls.length > 0) ? [...new Set(r.urls.map(u => {
                        if (u.sandbox && u.sandbox.effective_url) {
                          try { return new URL(u.sandbox.effective_url).hostname; } catch(e) { return u.sandbox.effective_url; }
                        }
                        return u.domain || 'N/A';
                      }))].join(', ') : 'None'}
                    </div>
                    <div style="font-size:10px;color:var(--text-muted);margin-top:4px">Landing domain after Browserless dynamic execution</div>
                  </div>
                  <div class="info-card" style="border-left:3px solid #06b6d4">
                    <div class="info-label">🌐 Contacted Infrastructure Domains</div>
                    <div class="info-value font-mono" style="font-size:11px">
                      ${(() => {
                        const allContacted = [];
                        (r.urls || []).forEach(u => {
                          if (u.sandbox && Array.isArray(u.sandbox.contacted_domains)) {
                            allContacted.push(...u.sandbox.contacted_domains);
                          }
                        });
                        const unique = [...new Set(allContacted)];
                        return unique.length > 0 ? (unique.slice(0, 5).join(', ') + (unique.length > 5 ? ` (+${unique.length - 5} more)` : '')) : 'None';
                      })()}
                    </div>
                    <div style="font-size:10px;color:var(--text-muted);margin-top:4px">Domains contacted for scripts, APIs, CDNs during rendering</div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- TAB 5: ATTACHMENTS -->
          <div class="tab-panel" id="inv-tab-attachments">
            <div class="card">
              <div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
                <div class="card-title">📎 Deep Attachment & Content Forensics (${r.attachments?.length || 0})</div>
                <div style="font-size:11px;color:var(--text-muted)">SIH26106 Deep Document Inspection Engine</div>
              </div>
              <div class="card-body">
                <div style="background:#080e1c;border-left:3px solid var(--cyan);padding:10px 14px;border-radius:4px;font-size:12px;color:var(--text-secondary);margin-bottom:20px;display:flex;justify-content:space-between;align-items:center">
                  <div>
                    ℹ️ <strong>Safety Guarantee:</strong> Attachments are safely inspected using structural object parsing. Documents are <strong>NEVER executed</strong> on host.
                  </div>
                  <span class="badge badge-outline" style="border-color:var(--cyan);color:var(--cyan);font-size:10px">ZERO EXECUTION ENVIRONMENT</span>
                </div>

                ${(r.attachments && r.attachments.length > 0) ? `
                  <div style="display:flex;flex-direction:column;gap:24px">
                    ${r.attachments.map((a, idx) => {
                      const ca = a.contentAnalysis;
                      const isPdf = a.extension === '.pdf' || a.fileType === 'PDF';
                      const isLocked = ca?.encrypted || false;
                      const statusColor = ca?.status === 'ANALYZED' ? 'var(--low)' : ca?.status === 'LIMITED' ? 'var(--medium)' : 'var(--text-muted)';
                      const verdictColor = (a.riskScore >= 60 || ca?.contentVerdict === 'HIGH_RISK') ? 'var(--critical)' : (a.riskScore >= 30 || ca?.contentVerdict === 'SUSPICIOUS') ? 'var(--high)' : isLocked ? 'var(--medium)' : 'var(--low)';
                      const verdictBadge = isLocked ? 'NOT ANALYZABLE (LOCKED)' : (a.riskScore >= 60 ? 'HIGH RISK' : a.riskScore >= 30 ? 'SUSPICIOUS' : 'CLEAN / EVALUATED');

                      return `
                        <div class="attachment-deep-card" style="background:#0a1020;border:1px solid var(--border);border-radius:10px;padding:18px;display:flex;flex-direction:column;gap:16px">
                          
                          <!-- 1. ATTACHMENT OVERVIEW -->
                          <div style="display:flex;align-items:flex-start;justify-content:space-between;padding-bottom:14px;border-bottom:1px solid var(--border)">
                            <div style="display:flex;align-items:center;gap:12px">
                              <div style="font-size:28px">${isPdf ? '📕' : ['docm','doc','xls','xlsm'].includes(a.extension) ? '📘' : a.isArchive ? '📦' : '📄'}</div>
                              <div>
                                <div class="font-mono" style="font-size:15px;font-weight:700;color:var(--text-primary)">${a.filename}</div>
                                <div style="font-size:12px;color:var(--text-muted);display:flex;align-items:center;gap:8px;margin-top:2px">
                                  <span>${a.contentType}</span>
                                  <span>•</span>
                                  <span>${a.sizeMb} MB (${a.sizeBytes.toLocaleString()} bytes)</span>
                                  <span>•</span>
                                  <span style="color:var(--cyan);font-weight:600">${a.fileType}</span>
                                </div>
                              </div>
                            </div>
                            <div style="display:flex;flex-direction:column;align-items:flex-end;gap:6px">
                              <div style="display:flex;gap:6px">
                                ${isLocked ? `
                                  <span class="badge" style="background:var(--medium-dim);color:var(--medium);border:1px solid var(--medium)">
                                    🔒 PASSWORD PROTECTED
                                  </span>
                                ` : `
                                  <span class="badge" style="background:var(--low-dim);color:var(--low);border:1px solid var(--low)">
                                    🔓 UNENCRYPTED
                                  </span>
                                `}
                                <span class="badge" style="background:${verdictColor}20;color:${verdictColor};border:1px solid ${verdictColor}">
                                  ${verdictBadge}
                                </span>
                              </div>
                              ${a.isMacroEnabled ? '<span class="badge badge-critical">⚠ MACRO ENABLED FILE</span>' : ''}
                            </div>
                          </div>

                          <!-- 2. CONTENT ANALYSIS INSPECTION -->
                          ${ca ? `
                            <div style="background:#060a14;border:1px solid #142238;border-radius:8px;padding:14px">
                              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
                                <div style="font-size:13px;font-weight:700;color:var(--cyan);display:flex;align-items:center;gap:6px">
                                  <span>🔍 Deep Document Content Inspection</span>
                                </div>
                                <span class="badge" style="background:${statusColor}18;color:${statusColor};border:1px solid ${statusColor}40;font-size:11px">
                                  STATUS: ${ca.status}
                                </span>
                              </div>

                              ${isLocked ? `
                                <div style="background:#161204;border:1px solid #3d3106;border-radius:6px;padding:10px 14px;font-size:12px;color:var(--medium);margin-bottom:8px">
                                  ⚠️ <strong>Content Analysis Limited:</strong> ${ca.reason || 'PDF is password protected/encrypted. In accordance with security constraints, password bypass was not attempted.'}
                                  <div style="margin-top:4px;color:var(--text-muted);font-size:11px">File cannot be claimed safe merely because it is encrypted. Content verdict is set to <strong>NOT ANALYZABLE</strong>.</div>
                                </div>
                              ` : `
                                <!-- Inspection Matrix -->
                                <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(160px, 1fr));gap:10px;margin-bottom:12px">
                                  <div style="background:#0c1527;padding:8px 12px;border-radius:6px">
                                    <div style="font-size:11px;color:var(--text-muted)">Page Count</div>
                                    <div class="font-mono" style="font-size:14px;font-weight:700;color:var(--text-primary)">${ca.pages} page(s)</div>
                                  </div>
                                  <div style="background:#0c1527;padding:8px 12px;border-radius:6px">
                                    <div style="font-size:11px;color:var(--text-muted)">Text Extraction</div>
                                    <div class="font-mono" style="font-size:14px;font-weight:700;color:${ca.textExtracted ? 'var(--low)' : 'var(--text-muted)'}">
                                      ${ca.textExtracted ? `✓ ${ca.textLength} chars` : 'None / Scanned'}
                                    </div>
                                  </div>
                                  <div style="background:#0c1527;padding:8px 12px;border-radius:6px">
                                    <div style="font-size:11px;color:var(--text-muted)">JavaScript Token</div>
                                    <div class="font-mono" style="font-size:14px;font-weight:700;color:${ca.javascriptDetected ? 'var(--critical)' : 'var(--low)'}">
                                      ${ca.javascriptDetected ? '⚠ DETECTED' : '✓ None'}
                                    </div>
                                  </div>
                                  <div style="background:#0c1527;padding:8px 12px;border-radius:6px">
                                    <div style="font-size:11px;color:var(--text-muted)">Document Actions</div>
                                    <div class="font-mono" style="font-size:14px;font-weight:700;color:${ca.actionsDetected.length > 0 ? 'var(--high)' : 'var(--text-muted)'}">
                                      ${ca.actionsDetected.length > 0 ? ca.actionsDetected.join(', ') : 'None'}
                                    </div>
                                  </div>
                                  <div style="background:#0c1527;padding:8px 12px;border-radius:6px">
                                    <div style="font-size:11px;color:var(--text-muted)">Embedded Payloads</div>
                                    <div class="font-mono" style="font-size:14px;font-weight:700;color:${ca.embeddedFiles.length > 0 ? 'var(--critical)' : 'var(--low)'}">
                                      ${ca.embeddedFiles.length > 0 ? `${ca.embeddedFiles.length} file(s)` : 'None'}
                                    </div>
                                  </div>
                                  <div style="background:#0c1527;padding:8px 12px;border-radius:6px">
                                    <div style="font-size:11px;color:var(--text-muted)">Interactive Forms</div>
                                    <div class="font-mono" style="font-size:14px;font-weight:700;color:${ca.formsDetected ? 'var(--medium)' : 'var(--text-muted)'}">
                                      ${ca.formsDetected ? 'AcroForm Present' : 'None'}
                                    </div>
                                  </div>
                                </div>

                                <!-- Text Preview if available -->
                                ${ca.textPreview ? `
                                  <div style="margin-top:10px;background:#050912;border:1px solid #141e30;border-radius:6px;padding:10px">
                                    <div style="font-size:11px;color:var(--text-muted);margin-bottom:4px;font-weight:600">EXTRACTED CONTENT PREVIEW:</div>
                                    <div class="font-mono" style="font-size:12px;color:var(--text-secondary);max-height:80px;overflow-y:auto;white-space:pre-wrap">${ca.textPreview}</div>
                                  </div>
                                ` : ''}

                                <!-- Document Metadata if available -->
                                ${Object.keys(ca.metadata || {}).length > 0 ? `
                                  <div style="margin-top:10px;display:flex;flex-wrap:wrap;gap:8px">
                                    ${Object.entries(ca.metadata).map(([k, v]) => `
                                      <span style="background:#0c1527;border:1px solid #1e2d45;border-radius:4px;padding:3px 8px;font-size:11px;color:var(--text-secondary)">
                                        <strong style="color:var(--cyan)">${k}:</strong> ${v}
                                      </span>
                                    `).join('')}
                                  </div>
                                ` : ''}
                              `}
                            </div>
                          ` : ''}

                          <!-- 3. EXTRACTED IOCS & EMBEDDED URLS -->
                          ${ca && ca.urls && ca.urls.length > 0 ? `
                            <div style="background:#060a14;border:1px solid #142238;border-radius:8px;padding:14px">
                              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
                                <div style="font-size:13px;font-weight:700;color:var(--cyan)">🔗 Discovered Links & IOCs (${ca.urls.length})</div>
                                <span style="font-size:11px;color:var(--text-muted)">Piped to Threat Intelligence Pipeline</span>
                              </div>
                              <div style="display:flex;flex-direction:column;gap:8px">
                                ${ca.urls.map(u => {
                                  const matchedTI = (ca.urlIntelligence || []).find(item => item.url === u);
                                  const rep = matchedTI?.reputation || 'unknown';
                                  const repColor = rep === 'malicious' ? 'var(--critical)' : rep === 'suspicious' ? 'var(--high)' : 'var(--low)';
                                  return `
                                    <div style="background:#0c1527;border:1px solid #1b2840;border-radius:6px;padding:8px 12px;display:flex;justify-content:space-between;align-items:center">
                                      <div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-right:12px">
                                        <div class="font-mono" style="font-size:12px;color:var(--cyan)">${u}</div>
                                        ${matchedTI?.reasons?.length ? `
                                          <div style="font-size:11px;color:var(--text-muted);margin-top:2px">${matchedTI.reasons.join('; ')}</div>
                                        ` : ''}
                                      </div>
                                      <div style="display:flex;align-items:center;gap:8px;flex-shrink:0">
                                        <span class="badge" style="background:${repColor}18;color:${repColor};border:1px solid ${repColor}40;font-size:10px">
                                          ${rep.toUpperCase()}
                                        </span>
                                        ${matchedTI?.riskScore != null ? `
                                          <span class="font-mono" style="font-size:12px;font-weight:700;color:${repColor}">${matchedTI.riskScore}/100</span>
                                        ` : ''}
                                      </div>
                                    </div>
                                  `;
                                }).join('')}
                              </div>
                            </div>
                          ` : ''}

                          <!-- 4. ATTACHMENT VERDICT & RISK FACTORS -->
                          <div style="background:#060a14;border:1px solid #142238;border-radius:8px;padding:14px">
                            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
                              <div style="font-size:13px;font-weight:700;color:var(--text-primary)">⚖️ Attachment Threat Verdict</div>
                              <div class="font-mono" style="font-size:16px;font-weight:800;color:${verdictColor}">
                                Risk Score: ${a.riskScore}/100
                              </div>
                            </div>
                            <div style="margin-bottom:10px">
                              <div style="height:6px;background:#142238;border-radius:3px;overflow:hidden">
                                <div style="height:100%;width:${a.riskScore}%;background:${verdictColor};border-radius:3px"></div>
                              </div>
                            </div>
                            <div style="display:flex;flex-direction:column;gap:4px">
                              ${(a.reasons || []).map(rText => `
                                <div style="font-size:12px;color:var(--text-secondary);display:flex;align-items:flex-start;gap:6px">
                                  <span style="color:${verdictColor}">•</span>
                                  <span>${rText}</span>
                                </div>
                              `).join('')}
                            </div>
                          </div>

                          <!-- 5. FORENSIC TIMELINE -->
                          ${ca && ca.timeline && ca.timeline.length > 0 ? `
                            <div style="padding-top:10px;border-top:1px solid #142238">
                              <div style="font-size:11px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:10px">
                                ⏱️ Forensic Inspection Timeline
                              </div>
                              <div style="display:flex;flex-direction:column;gap:6px">
                                ${ca.timeline.map((step, sIdx) => {
                                  const stepIcon = step.status === 'completed' ? '✓' : step.status === 'limited' ? '⚠' : '✗';
                                  const stepColor = step.status === 'completed' ? 'var(--cyan)' : step.status === 'limited' ? 'var(--medium)' : 'var(--critical)';
                                  return `
                                    <div style="display:flex;align-items:center;gap:10px;font-size:11px">
                                      <span class="font-mono" style="width:20px;height:20px;border-radius:50%;background:${stepColor}20;color:${stepColor};display:flex;align-items:center;justify-content:center;font-weight:700;font-size:10px;flex-shrink:0">
                                        ${stepIcon}
                                      </span>
                                      <span class="font-mono" style="color:var(--text-muted);width:55px;flex-shrink:0">+${step.timestamp_offset_ms || (sIdx * 4)}ms</span>
                                      <span style="color:var(--text-secondary)">${step.description}</span>
                                    </div>
                                  `;
                                }).join('')}
                              </div>
                            </div>
                          ` : ''}

                        </div>
                      `;
                    }).join('')}
                  </div>
                ` : `
                  <div class="empty-state">
                    <div class="empty-icon">📎</div>
                    <div class="empty-title">No Attachments Detected</div>
                    <div class="empty-text">This email contains no MIME attachments.</div>
                  </div>
                `}
              </div>
            </div>
          </div>

          <!-- TAB 6: AI CONTENT ANALYSIS -->
          <div class="tab-panel" id="inv-tab-ai">
            <!-- Google Gemini AI Contextual Threat Reasoning -->
            ${this._renderGeminiAnalysis(r.geminiAnalysis)}

            <!-- Linear SVM Phishing Decision Meter -->
            <div class="ml-decision-container mb-16">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
                <div>
                  <div style="font-size:14px;font-weight:700;color:var(--text-primary)">AI Content Analysis (Linear Support Vector Machine)</div>
                  <div style="font-size:11px;color:var(--text-muted)">TF-IDF word vector classification and linguistic feature evaluation</div>
                </div>
                <div style="text-align:right">
                  <div class="font-mono" style="font-size:18px;font-weight:700;color:${r.ml?.isMalicious ? 'var(--critical)' : 'var(--low)'}">
                    ${r.ml?.decisionScore != null ? (r.ml.decisionScore > 0 ? '+' : '') + r.ml.decisionScore.toFixed(3) : 'Model Available'}
                  </div>
                  <div style="font-size:10px;color:var(--text-muted)">SVM Hyperplane Distance</div>
                </div>
              </div>
              <div class="ml-boundary-track">
                <div class="ml-boundary-marker" style="left:${Math.min(95, Math.max(5, 50 + (r.ml?.decisionScore || 0) * 18))}%"></div>
              </div>
              <div class="ml-boundary-labels">
                <span>Legitimate Mail (&lt; 0.0)</span>
                <span>Decision Threshold (0.0)</span>
                <span>Malicious Phishing (&gt; 0.0)</span>
              </div>
            </div>

            <div class="card">
              <div class="card-header"><div class="card-title">🤖 AI Content Features & Decision Boundary Context</div></div>
              <div class="card-body">
                <div class="grid-2 mb-16">
                  <div class="info-card">
                    <div class="info-label">Classifier Verdict</div>
                    <div class="info-value" style="color:${r.ml?.isMalicious ? 'var(--critical)' : 'var(--low)'};font-weight:700">
                      ${r.ml?.prediction === 1 ? 'PHISHING PATTERNS DETECTED' : r.ml?.prediction === 0 ? 'LEGITIMATE CONTENT PROFILE' : 'MODEL EVALUATED'}
                    </div>
                  </div>
                  <div class="info-card">
                    <div class="info-label">Confidence Note</div>
                    <div class="info-value font-mono" style="font-size:11px;color:var(--text-secondary)">
                      Calibrated Hyperplane Distance (No Fake Confidence %)
                    </div>
                  </div>
                </div>
                <div style="font-size:12px;color:var(--text-secondary);line-height:1.5">
                  ${r.ml?.note}
                  <br><br>
                  <em>Note: The ML model is one component inside GmailGuard's overall threat assessment. GmailGuard combines linguistic analysis with domain reputation, cryptographic authentication, and IP network telemetry to compute the unified score.</em>
                </div>
              </div>
            </div>
          </div>

          <!-- TAB 7: GRAPH -->
          <div class="tab-panel" id="inv-tab-graph">
            <div class="card">
              <div class="card-header">
                <div class="card-title">🕸️ Evidence Relationship Graph</div>
                <div style="font-size:12px;color:var(--text-muted)">Interactive D3 force simulation connecting envelope, observables & IOCs</div>
              </div>
              <div class="graph-container" id="threat-graph" style="min-height:420px"></div>
            </div>
          </div>

          <!-- TAB 8: IOCS -->
          <div class="tab-panel" id="inv-tab-iocs">
            <div class="card">
              <div class="card-header">
                <div class="card-title">🚨 Extracted Indicators of Compromise (${r.iocs?.length || 0})</div>
                <div style="display:flex;gap:8px">
                  <button class="btn btn-secondary btn-sm" onclick="app.copyAllIOCs()">📋 Copy All</button>
                  <button class="btn btn-primary btn-sm" onclick="app.exportIOCsJSON()">📤 Export JSON</button>
                </div>
              </div>
              <div class="card-body">
                ${(r.iocs && r.iocs.length > 0) ? `
                  <div class="ioc-list">
                    ${r.iocs.map(ioc => `
                      <div class="ioc-item">
                        <span class="ioc-type-badge badge badge-unknown">${ioc.type}</span>
                        <span class="ioc-value font-mono">${ioc.value}</span>
                        <span class="badge badge-${ioc.risk === 'CRITICAL' ? 'critical' : 'low'}">${ioc.risk}</span>
                        <span class="ioc-source">${ioc.category}</span>
                      </div>
                    `).join('')}
                  </div>
                ` : '<div style="color:var(--text-muted)">No IOCs extracted.</div>'}
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    // Animate score ring
    setTimeout(() => {
      const ring = document.getElementById('score-ring-fill');
      const display = document.getElementById('score-display');
      if (ring) {
        const offset = scoreCircumference - (r.threatScore / 100) * scoreCircumference;
        ring.style.strokeDashoffset = offset;
      }
      if (display) {
        let current = 0;
        const target = r.threatScore;
        const step = () => {
          if (current < target) {
            current = Math.min(current + 2, target);
            display.textContent = current;
            requestAnimationFrame(step);
          }
        };
        requestAnimationFrame(step);
      }
    }, 80);
  }

  _renderAuthMiniCard(protocol, result) {
    const colors = { pass: 'var(--low)', fail: 'var(--critical)', softfail: 'var(--medium)', neutral: 'var(--medium)', none: 'var(--text-muted)', unknown: 'var(--text-muted)' };
    const icons = { pass: '✓', fail: '✗', softfail: '~', neutral: '~', none: '?', unknown: '?' };
    const res = (result || 'UNKNOWN').toLowerCase();
    const c = colors[res] || 'var(--text-muted)';
    return `
      <div class="auth-card" style="border-color:${c}40">
        <div class="auth-protocol">${protocol}</div>
        <div class="auth-result" style="color:${c}">${icons[res] || '?'}</div>
        <span class="badge badge-${res}">${res.toUpperCase()}</span>
      </div>
    `;
  }

  _colorizeHeaders(raw) {
    if (!raw) return '';
    return raw
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/^([A-Za-z0-9\-]+):/gm, '<span style="color:var(--cyan);font-weight:600">$1:</span>');
  }

  _renderGeminiAnalysis(gemini) {
    if (!gemini || !gemini.available) {
      const reason = gemini?.reason || 'GEMINI_API_KEY is not configured in backend/.env.';
      return `
        <div class="card mb-16" style="border: 1px solid rgba(0, 212, 255, 0.25); background: linear-gradient(135deg, rgba(13, 21, 39, 0.9) 0%, rgba(10, 25, 47, 0.8) 100%);">
          <div class="card-header" style="display:flex;justify-content:space-between;align-items:center;">
            <div style="display:flex;align-items:center;gap:10px">
              <span style="font-size:20px">✨</span>
              <div>
                <div class="card-title" style="font-size:15px;color:var(--cyan);font-weight:700">Google Gemini AI Threat Reasoning</div>
                <div style="font-size:11px;color:var(--text-muted)">Contextual Large Language Model Security Intelligence</div>
              </div>
            </div>
            <span class="badge badge-unknown" style="letter-spacing:1px">UNCONFIGURED</span>
          </div>
          <div class="card-body">
            <div style="display:flex;align-items:flex-start;gap:14px;background:rgba(255,255,255,0.02);padding:16px;border-radius:var(--radius-sm);border:1px dashed var(--border)">
              <div style="font-size:28px">🔑</div>
              <div style="flex:1">
                <div style="font-weight:600;font-size:13px;color:var(--text-primary);margin-bottom:4px">
                  Contextual AI Reasoning Ready for Activation
                </div>
                <div style="font-size:12px;color:var(--text-secondary);line-height:1.5;margin-bottom:12px">
                  ${reason} To enable automated LLM reasoning, deceptive linguistics analysis, brand impersonation detection, and SOC playbook recommendations:
                </div>
                <div style="background:var(--bg-input);padding:10px 14px;border-radius:4px;font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--cyan);margin-bottom:12px;border:1px solid var(--border)">
                  GEMINI_API_KEY=your_gemini_api_key_here
                </div>
                <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
                  <a href="https://aistudio.google.com/app/apikey" target="_blank" rel="noopener noreferrer" class="btn btn-secondary btn-sm" style="text-decoration:none">
                    Get Free Google AI Studio Key ↗
                  </a>
                  <button class="btn btn-primary btn-sm" onclick="app.triggerGeminiAnalysis()">
                    ⚡ Test / Run Gemini Analysis Now
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      `;
    }

    const classificationColors = {
      phishing: 'var(--critical)',
      suspicious: 'var(--high)',
      benign: 'var(--low)',
      insufficient_evidence: 'var(--medium)',
      unavailable: 'var(--text-muted)'
    };
    const cColor = classificationColors[gemini.classification] || 'var(--cyan)';

    const riskColors = {
      critical: '#ff2d55',
      high: '#ff6b35',
      medium: '#ffd60a',
      low: '#34d399',
      none: '#64748b'
    };
    const rColor = riskColors[gemini.riskLevel] || '#64748b';

    return `
      <div class="card mb-16" style="border: 1px solid ${cColor}40; background: linear-gradient(135deg, rgba(13, 21, 39, 0.95) 0%, rgba(10, 25, 47, 0.85) 100%); box-shadow: 0 4px 20px rgba(0,0,0,0.3);">
        <div class="card-header" style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;border-bottom:1px solid var(--border)">
          <div style="display:flex;align-items:center;gap:10px">
            <span style="font-size:22px">✨</span>
            <div>
              <div class="card-title" style="font-size:15px;color:var(--text-primary);font-weight:700">
                Google Gemini Contextual Threat Reasoning
              </div>
              <div style="font-size:11px;color:var(--cyan);font-family:'JetBrains Mono',monospace">
                Model: ${gemini.modelUsed || 'gemini-flash'} &bull; Google GenAI SDK
              </div>
            </div>
          </div>
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            <span class="badge" style="background:${cColor}20;color:${cColor};border:1px solid ${cColor}60;font-weight:700;font-size:11px;padding:4px 10px">
              ${gemini.classification.toUpperCase()}
            </span>
            <span class="badge" style="background:${rColor}20;color:${rColor};border:1px solid ${rColor}60;font-weight:700;font-size:11px;padding:4px 10px">
              RISK: ${gemini.riskLevel.toUpperCase()}
            </span>
            <button class="btn btn-secondary btn-sm" onclick="app.triggerGeminiAnalysis()" style="font-size:11px;padding:4px 10px">
              🔄 Re-run AI
            </button>
          </div>
        </div>

        <div class="card-body">
          <!-- Executive Summary Callout -->
          <div style="padding:14px 16px;background:rgba(0, 212, 255, 0.05);border-radius:var(--radius-sm);border-left:4px solid ${cColor};margin-bottom:16px">
            <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;font-weight:700;color:var(--text-muted);margin-bottom:4px">
              Executive AI Security Summary
            </div>
            <div style="font-size:13px;color:var(--text-primary);line-height:1.5;font-weight:500">
              ${gemini.plainLanguageSummary || gemini.summary}
            </div>
            <div style="display:flex;align-items:center;gap:14px;margin-top:10px;font-size:11px;color:var(--text-secondary)">
              <div>AI Confidence: <strong style="color:var(--cyan);font-family:'JetBrains Mono',monospace">${gemini.confidence}${typeof gemini.confidence === 'number' ? '%' : ''}</strong></div>
              ${typeof gemini.confidence === 'number' ? `
                <div style="flex:1;max-width:140px;height:5px;background:var(--bg-input);border-radius:3px;overflow:hidden">
                  <div style="width:${gemini.confidence}%;height:100%;background:${cColor};border-radius:3px"></div>
                </div>
              ` : ''}
            </div>
          </div>

          <!-- Grid: Threat Indicators & Social Engineering -->
          <div class="grid-2 mb-16">
            <!-- Threat Indicators -->
            <div style="background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius-sm);padding:14px">
              <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);margin-bottom:10px;display:flex;align-items:center;gap:6px">
                <span>🎯 Specific Threat Indicators (${gemini.threatIndicators.length})</span>
              </div>
              ${gemini.threatIndicators.length > 0 ? `
                <div style="display:flex;flex-direction:column;gap:8px">
                  ${gemini.threatIndicators.map(ti => {
                    const sev = (ti.severity || 'medium').toLowerCase();
                    const sColor = sev === 'high' ? 'var(--critical)' : sev === 'medium' ? 'var(--medium)' : 'var(--low)';
                    return `
                      <div style="padding:8px 10px;background:rgba(255,255,255,0.02);border-radius:4px;border-left:3px solid ${sColor}">
                        <div style="display:flex;justify-content:space-between;align-items:center">
                          <strong style="font-size:12px;color:var(--text-primary)">${ti.indicator}</strong>
                          <span class="badge" style="background:${sColor}20;color:${sColor};font-size:9px">${sev.toUpperCase()}</span>
                        </div>
                        <div style="font-size:11px;color:var(--text-secondary);margin-top:2px;line-height:1.4">${ti.evidence}</div>
                      </div>
                    `;
                  }).join('')}
                </div>
              ` : '<div style="font-size:11px;color:var(--text-muted)">No explicit technical indicators flagged.</div>'}
            </div>

            <!-- Social Engineering Tactics -->
            <div style="background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius-sm);padding:14px">
              <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);margin-bottom:10px">
                🧠 Psychological & Urgency Tactics (${gemini.socialEngineeringIndicators.length})
              </div>
              ${gemini.socialEngineeringIndicators.length > 0 ? `
                <ul style="padding-left:18px;margin:0;font-size:12px;color:var(--text-secondary);line-height:1.6">
                  ${gemini.socialEngineeringIndicators.map(t => `<li style="margin-bottom:4px"><span style="color:var(--text-primary)">${t}</span></li>`).join('')}
                </ul>
              ` : '<div style="font-size:11px;color:var(--text-muted)">No aggressive social engineering patterns identified.</div>'}

              <!-- Suspicious URLs or Domains identified by Gemini -->
              ${(gemini.suspiciousUrls.length > 0 || gemini.suspiciousDomains.length > 0) ? `
                <div style="margin-top:12px;padding-top:10px;border-top:1px solid var(--border)">
                  <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);margin-bottom:6px">
                    🚨 AI-Identified Deceptive Entities
                  </div>
                  <div style="display:flex;flex-direction:column;gap:4px">
                    ${gemini.suspiciousDomains.map(d => `<div class="font-mono text-critical" style="font-size:11px">🌐 Domain: ${d}</div>`).join('')}
                    ${gemini.suspiciousUrls.map(u => `<div class="font-mono text-warning" style="font-size:11px;word-break:break-all">🔗 Link: ${u}</div>`).join('')}
                  </div>
                </div>
              ` : ''}
            </div>
          </div>

          <!-- Recommended Actions / SOC Guidance -->
          ${gemini.recommendedActions.length > 0 ? `
            <div style="margin-bottom:16px;padding:12px 14px;background:rgba(52, 211, 153, 0.05);border:1px solid rgba(52, 211, 153, 0.2);border-radius:var(--radius-sm)">
              <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--low);margin-bottom:6px">
                🛡️ Recommended SOC Remediation & Defense Actions
              </div>
              <div style="display:flex;flex-direction:column;gap:6px">
                ${gemini.recommendedActions.map((act, i) => `
                  <div style="display:flex;align-items:flex-start;gap:8px;font-size:12px;color:var(--text-primary)">
                    <span style="color:var(--low);font-weight:bold">${i + 1}.</span>
                    <span>${act}</span>
                  </div>
                `).join('')}
              </div>
            </div>
          ` : ''}

          <!-- Detailed Explanation -->
          ${gemini.explanation ? `
            <div style="background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius-sm);padding:14px">
              <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);margin-bottom:8px">
                📝 In-Depth Forensic & Linguistic Rationale
              </div>
              <div style="font-size:12px;color:var(--text-secondary);line-height:1.6;white-space:pre-line">
                ${gemini.explanation}
              </div>
            </div>
          ` : ''}
        </div>
      </div>
    `;
  }

  async triggerGeminiAnalysis() {
    if (!this.currentResult) {
      this.showToast('No active email analysis loaded.', 'warning', '⚠️');
      return;
    }
    this.showToast('Requesting Gemini AI contextual security reasoning...', 'info', '✨');
    try {
      const rawEmail = this.currentResult.rawHeaders || '';
      const report = this.currentResult.rawResult || {};
      const aiResult = await window.GmailGuardAPI.analyzeWithGemini(rawEmail, report);

      this.currentResult.geminiAnalysis = aiResult;
      if (this.currentResult.rawResult) {
        this.currentResult.rawResult.gemini_analysis = aiResult;
        this.currentResult.rawResult.ai_analysis = aiResult;
      }
      this.showToast('Gemini AI analysis complete!', 'success', '✨');
      this.renderInvestigation();
      this.switchInvestigationTab('ai');
    } catch (err) {
      this.showToast(`Gemini AI analysis failed: ${err.message}`, 'error', '❌');
    }
  }

  switchInvestigationTab(tabId) {
    this.activeResultTab = tabId;
    document.querySelectorAll('.result-tab').forEach(t => {
      t.classList.toggle('active', t.dataset.tab === tabId);
    });
    document.querySelectorAll('.tab-panel').forEach(p => {
      p.classList.toggle('active', p.id === `inv-tab-${tabId}`);
    });

    if (tabId === 'graph' && this.currentResult) {
      setTimeout(() => {
        const graph = new window.ThreatGraph('threat-graph', this.currentResult);
        graph.build();
      }, 50);
    }
  }

  // ─── D. INFRASTRUCTURE & GEOLOCATION ──────────────────────
  renderInfrastructure() {
    if (!this.currentResult) {
      this.renderInvestigation();
      return;
    }
    this.navigateTo('investigation');
    this.switchInvestigationTab('network');
  }

  // ─── E. THREAT INTEL / IOCS ────────────────────────────────
  renderThreatIntel() {
    if (!this.currentResult) {
      this.renderInvestigation();
      return;
    }
    this.navigateTo('investigation');
    this.switchInvestigationTab('urls');
  }

  // ─── F. FORENSIC EVIDENCE ──────────────────────────────────
  renderForensics() {
    if (!this.currentResult) {
      this.renderInvestigation();
      return;
    }
    this.navigateTo('investigation');
    this.switchInvestigationTab('ai');
  }

  _renderGeminiOverviewCallout(r) {
    const gemini = r.geminiAnalysis;
    if (!gemini || !gemini.available) return '';
    const assessment = (gemini.overallAssessment || gemini.geminiAssessment || 'CAUTION').toUpperCase();
    const color = assessment === 'HIGH_RISK' ? 'var(--critical)' : assessment === 'CAUTION' || assessment === 'SUSPICIOUS' ? 'var(--warning)' : 'var(--low)';
    const icon = assessment === 'HIGH_RISK' ? '🚨' : assessment === 'CAUTION' || assessment === 'SUSPICIOUS' ? '⚠️' : '✓';

    return `
      <div class="card mb-16" style="border-left:4px solid ${color};background:linear-gradient(135deg, rgba(13, 21, 39, 0.95) 0%, rgba(10, 25, 47, 0.85) 100%)">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;flex-wrap:wrap;gap:8px">
          <div style="display:flex;align-items:center;gap:8px">
            <span style="font-size:18px">${icon}</span>
            <strong style="font-size:14px;color:${color}">Gemini Human-Readable Intelligence: ${assessment}</strong>
          </div>
          <button class="btn btn-secondary btn-sm" onclick="app.navigateTo('gemini-security')" style="font-size:11px;padding:4px 10px">
            Open Full Gemini Security Tab →
          </button>
        </div>
        <div style="font-size:13px;color:var(--text-primary);line-height:1.5;margin-bottom:6px">
          ${this._escapeHtml(gemini.plainLanguageSummary || gemini.summary || '')}
        </div>
        <div style="font-size:11px;color:var(--text-muted);display:flex;gap:12px;flex-wrap:wrap">
          <span>Stated Intent: <strong style="color:var(--text-secondary)">${this._escapeHtml(gemini.likelyIntent || 'General')}</strong></span>
          <span>&bull;</span>
          <span>Categories: <strong style="color:var(--cyan)">${(gemini.contentCategory || []).join(', ') || 'Standard'}</strong></span>
        </div>
      </div>
    `;
  }

  // ─── AI SECURITY: GEMINI SECURITY DASHBOARD ────────────────
  async renderGeminiSecurity() {
    const content = document.getElementById('page-content');
    if (!content) return;

    // Default overview from session cases
    let overview = {
      total_analyzed: this.sessionInvestigations.length,
      requires_attention: this.sessionInvestigations.filter(c => c.threatScore >= 40).length,
      high_risk_count: this.sessionInvestigations.filter(c => c.threatScore >= 70).length,
      suspicious_count: this.sessionInvestigations.filter(c => c.threatScore >= 40 && c.threatScore < 70).length,
      caution_count: this.sessionInvestigations.filter(c => c.geminiAnalysis?.overallAssessment === 'CAUTION').length,
      safe_count: this.sessionInvestigations.filter(c => c.threatScore < 40).length,
      common_patterns: [],
      categories_distribution: {}
    };

    try {
      const remoteOverview = await window.GmailGuardAPI.getGeminiOverview();
      if (remoteOverview && remoteOverview.total_analyzed > 0) {
        overview = remoteOverview;
      }
    } catch (_) {}

    const r = this.currentResult;

    content.innerHTML = `
      <div style="max-width:1200px;margin:0 auto" class="animate-in gemini-security-container">
        <!-- Top Section: Overview Header -->
        <div class="gmail-inbox-header">
          <div>
            <div style="display:flex;align-items:center;gap:10px">
              <span style="font-size:26px">🤖</span>
              <h1 style="font-size:22px;font-weight:800;color:var(--text-primary);margin:0">Google Gemini Security Intelligence</h1>
              <span class="badge badge-pass font-mono" style="font-size:10px">GenAI Active</span>
            </div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:4px">
              Human-readable security explanations, intent reasoning, and content risk categorization powered by Google GenAI.
            </div>
          </div>
          <div style="display:flex;gap:10px">
            <button class="btn btn-secondary btn-sm" onclick="app.navigateTo('gmail-inbox')">📧 Open Gmail Inbox</button>
            <button class="btn btn-primary btn-sm" onclick="app.navigateTo('analyze')">🔍 Analyze New Email</button>
          </div>
        </div>

        <!-- PART 14 B: GEMINI MAIL SECURITY OVERVIEW DASHBOARD -->
        <div class="card" style="border:1px solid rgba(0, 212, 255, 0.25);background:linear-gradient(135deg, rgba(13, 21, 39, 0.95) 0%, rgba(10, 25, 47, 0.85) 100%)">
          <div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
            <div class="card-title" style="color:var(--cyan);display:flex;align-items:center;gap:8px">
              <span>📊</span>
              <span>Gemini Mail Security Overview</span>
            </div>
            <span class="badge badge-unknown font-mono" style="font-size:11px">${overview.total_analyzed} Emails Evaluated</span>
          </div>
          <div class="card-body">
            <!-- Metrics Grid -->
            <div class="stats-grid mb-20" style="grid-template-columns:repeat(auto-fit, minmax(180px, 1fr))">
              <div class="stat-card" style="--accent-color:var(--cyan)">
                <div class="stat-value">${overview.total_analyzed}</div>
                <div class="stat-label">Analyzed Emails</div>
              </div>
              <div class="stat-card" style="--accent-color:var(--warning)">
                <div class="stat-value text-warning">${overview.requires_attention}</div>
                <div class="stat-label">⚠️ Requires Attention</div>
              </div>
              <div class="stat-card" style="--accent-color:var(--critical)">
                <div class="stat-value text-critical">${overview.high_risk_count}</div>
                <div class="stat-label">🔴 High-Risk</div>
              </div>
              <div class="stat-card" style="--accent-color:#ffd60a">
                <div class="stat-value" style="color:#ffd60a">${overview.suspicious_count}</div>
                <div class="stat-label">🟡 Suspicious</div>
              </div>
              <div class="stat-card" style="--accent-color:var(--low)">
                <div class="stat-value text-low">${overview.safe_count}</div>
                <div class="stat-label">🟢 No Major Concerns</div>
              </div>
            </div>

            <!-- Common Patterns & Category Distribution -->
            <div class="grid-2" style="gap:16px">
              <div style="background:var(--bg-input);padding:14px;border-radius:var(--radius-sm);border:1px solid var(--border)">
                <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);margin-bottom:10px">
                  🧠 Common Patterns Observed Across Mailbox
                </div>
                ${overview.common_patterns && overview.common_patterns.length > 0 ? `
                  <ul style="padding-left:18px;margin:0;font-size:12px;color:var(--text-secondary);line-height:1.7">
                    ${overview.common_patterns.map(p => `<li><span style="color:var(--text-primary)">${this._escapeHtml(p)}</span></li>`).join('')}
                  </ul>
                ` : `
                  <div style="font-size:12px;color:var(--text-muted)">
                    No recurring threat patterns observed in analyzed messages yet.
                  </div>
                `}
              </div>

              <div style="background:var(--bg-input);padding:14px;border-radius:var(--radius-sm);border:1px solid var(--border)">
                <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);margin-bottom:10px">
                  🏷️ Content Category Distribution
                </div>
                <div style="display:flex;flex-wrap:wrap;gap:8px">
                  ${Object.keys(overview.categories_distribution || {}).length > 0 ? `
                    ${Object.entries(overview.categories_distribution).map(([cat, count]) => `
                      <span class="badge" style="background:rgba(0, 212, 255, 0.1);color:var(--cyan);border:1px solid rgba(0, 212, 255, 0.3);font-size:11px;padding:4px 8px">
                        ${this._escapeHtml(cat)} (${count})
                      </span>
                    `).join('')}
                  ` : `
                    <span style="font-size:12px;color:var(--text-muted)">No category tags recorded yet.</span>
                  `}
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- PART 13 & 14 A: PER-EMAIL HUMAN-READABLE GEMINI SECURITY REPORT -->
        ${r ? this._renderActiveEmailGeminiReport(r) : `
          <div class="card" style="text-align:center;padding:50px 20px">
            <div style="font-size:42px;margin-bottom:12px">🎯</div>
            <div style="font-size:16px;font-weight:700;color:var(--text-primary);margin-bottom:6px">No Specific Email Selected for In-Depth AI Explanation</div>
            <div style="font-size:13px;color:var(--text-secondary);max-width:520px;margin:0 auto 20px;line-height:1.5">
              Select any message from your connected Gmail inbox, or upload a .eml file to inspect the complete human-readable Gemini security reasoning.
            </div>
            <div style="display:flex;gap:12px;justify-content:center">
              <button class="btn btn-primary" onclick="app.navigateTo('gmail-inbox')">Open Gmail Inbox →</button>
              <button class="btn btn-secondary" onclick="app.navigateTo('analyze')">Upload / Paste .EML →</button>
            </div>
          </div>
        `}
      </div>
    `;
  }

  _renderActiveEmailGeminiReport(r) {
    const gemini = r.geminiAnalysis;
    const assessment = (gemini?.overallAssessment || gemini?.geminiAssessment || (r.threatScore >= 70 ? 'HIGH_RISK' : r.threatScore >= 40 ? 'SUSPICIOUS' : 'SAFE')).toUpperCase();
    const isSafe = assessment === 'SAFE';
    const isCaution = assessment === 'CAUTION';
    const isSuspicious = assessment === 'SUSPICIOUS';
    const isHighRisk = assessment === 'HIGH_RISK';

    const bannerClass = isHighRisk ? 'high_risk' : isSuspicious ? 'suspicious' : isCaution ? 'caution' : 'safe';
    const bannerIcon = isHighRisk ? '🚨' : isSuspicious ? '⚠️' : isCaution ? '⚠️' : '🟢';
    const bannerTitle = isHighRisk ? 'CRITICAL SECURITY THREAT DETECTED' : isSuspicious ? 'SUSPICIOUS EMAIL — EXERCISE CAUTION' : isCaution ? 'BE CAREFUL — POTENTIAL CONCERN' : 'NO MAJOR SECURITY THREATS DETECTED';
    const bannerColor = isHighRisk ? 'var(--critical)' : isSuspicious ? 'var(--high)' : isCaution ? 'var(--warning)' : 'var(--low)';

    const plainSummary = gemini?.plainLanguageSummary || gemini?.summary || 'Our security analysis has evaluated this email.';
    const whatItIsAbout = gemini?.whatThisEmailIsAbout || r.email?.subject || 'Message communication';
    const likelyIntent = gemini?.likelyIntent || 'General communication';
    const categories = gemini?.contentCategory || [];
    const concerns = gemini?.securityConcerns || [];
    const actions = gemini?.userActions || gemini?.recommendedActions || [];
    const techSummary = gemini?.technicalFindingsSummary || gemini?.explanation || 'Authentication and dynamic sandbox checks completed.';

    return `
      <!-- Human-Readable Assessment Banner -->
      <div class="gemini-banner-card ${bannerClass}">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px">
          <div>
            <div class="gemini-verdict-title" style="color:${bannerColor}">
              <span>${bannerIcon}</span>
              <span>${bannerTitle}</span>
            </div>
            <div style="font-size:15px;font-weight:600;color:var(--text-primary);margin-bottom:8px;line-height:1.5">
              ${this._escapeHtml(plainSummary)}
            </div>
            <div style="font-size:12px;color:var(--text-secondary);display:flex;align-items:center;gap:12px;flex-wrap:wrap">
              <span>Subject: <strong style="color:var(--text-primary)">${this._escapeHtml(r.email?.subject || '(No Subject)')}</strong></span>
              <span>&bull;</span>
              <span>Sender: <code style="color:var(--cyan)">${this._escapeHtml(r.email?.from || '')}</code></span>
            </div>
          </div>
          <div style="display:flex;gap:8px;align-items:center">
            <span class="badge font-mono" style="background:${bannerColor}25;color:${bannerColor};border:1px solid ${bannerColor}60;font-size:12px;padding:6px 12px">
              ${assessment}
            </span>
          </div>
        </div>

        <!-- Why? Section -->
        <div style="margin-top:20px;padding-top:16px;border-top:1px solid var(--border)">
          <div style="font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);margin-bottom:10px">
            Why is this email flagged as ${assessment}?
          </div>
          <ul style="padding-left:18px;margin:0 0 16px 0;font-size:13px;color:var(--text-secondary);line-height:1.7">
            <li><strong style="color:var(--text-primary)">Sender's Stated Message:</strong> ${this._escapeHtml(whatItIsAbout)}</li>
            <li><strong style="color:var(--text-primary)">Identified Intent:</strong> ${this._escapeHtml(likelyIntent)}</li>
            ${concerns.map(c => `
              <li><strong style="color:var(--text-primary)">${this._escapeHtml(c.title || 'Security Concern')}:</strong> ${this._escapeHtml(c.explanation || '')}</li>
            `).join('')}
            ${concerns.length === 0 ? `
              <li>Our technical checks and language models found standard communication patterns without aggressive urgency or deceit.</li>
            ` : ''}
          </ul>
        </div>

        <!-- Plain Technical Security Checks (Part 13) -->
        <div style="margin-top:16px;background:rgba(0,0,0,0.25);padding:14px;border-radius:var(--radius-sm);border:1px solid var(--border)">
          <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);margin-bottom:10px">
            🛡️ Technical Security Checks in Plain Language
          </div>
          <div style="display:flex;flex-direction:column;gap:8px">
            <div class="gemini-check-item">
              <span class="gemini-check-icon ${r.authentication?.spf?.status === 'PASS' ? 'pass' : 'warn'}">
                ${r.authentication?.spf?.status === 'PASS' ? '✓' : '⚠️'}
              </span>
              <div>
                <strong>Cryptographic Authentication (SPF/DKIM/DMARC):</strong>
                ${r.authentication?.spf?.status === 'PASS' && r.authentication?.dkim?.status === 'PASS' ? 
                  'The sender domain verified cryptographically, confirming transit integrity.' : 
                  'Authentication headers are absent or misaligned; domain ownership cannot be mathematically verified.'}
              </div>
            </div>
            <div class="gemini-check-item">
              <span class="gemini-check-icon ${(r.urls?.suspicious_count || 0) === 0 ? 'pass' : 'fail'}">
                ${(r.urls?.suspicious_count || 0) === 0 ? '✓' : '✗'}
              </span>
              <div>
                <strong>Link & Dynamic Sandbox Inspection:</strong>
                ${(r.urls?.suspicious_count || 0) === 0 ? 
                  'Links were inspected dynamically in our isolated Chromium sandbox. No known malware payloads or phishing landing pages were detected.' : 
                  'One or more links match known phishing databases or triggered suspicious behaviors in the browser sandbox.'}
              </div>
            </div>
            <div class="gemini-check-item">
              <span class="gemini-check-icon ${(r.attachments?.length || 0) === 0 || !r.attachments?.some(a => a.is_dangerous) ? 'pass' : 'fail'}">
                ${(r.attachments?.length || 0) === 0 || !r.attachments?.some(a => a.is_dangerous) ? '✓' : '✗'}
              </span>
              <div>
                <strong>Attachment Threat Assessment:</strong>
                ${(r.attachments?.length || 0) === 0 ? 
                  'No attachments present in this email.' : 
                  !r.attachments?.some(a => a.is_dangerous) ? 
                  'Attachments inspected statically. No macro scripts or suspicious executable signatures identified.' : 
                  'Dangerous file types or suspicious code identified in attached files.'}
              </div>
            </div>
          </div>
        </div>

        <!-- Actionable Recommendations -->
        ${actions.length > 0 ? `
          <div style="margin-top:16px;padding:14px;background:rgba(52, 211, 153, 0.08);border:1px solid rgba(52, 211, 153, 0.25);border-radius:var(--radius-sm)">
            <div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--low);margin-bottom:8px">
              💡 Actionable Recommendations for You
            </div>
            <div style="display:flex;flex-direction:column;gap:6px">
              ${actions.map((act, i) => `
                <div style="display:flex;align-items:flex-start;gap:8px;font-size:13px;color:var(--text-primary)">
                  <span style="color:var(--low);font-weight:700">${i + 1}.</span>
                  <span>${this._escapeHtml(act)}</span>
                </div>
              `).join('')}
            </div>
          </div>
        ` : ''}
      </div>

      <!-- PART 16: VISUAL DISTINCTION: TECHNICAL FORENSIC SCORE vs GEMINI INTENT ASSESSMENT -->
      <div class="gemini-contrast-container">
        <!-- Card 1: Technical Threat Score -->
        <div class="gemini-contrast-box technical">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
            <div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--cyan)">
              🎯 Technical Threat Score
            </div>
            <span class="badge" style="font-size:12px;font-weight:700;background:var(--bg-input);color:var(--cyan);border:1px solid var(--cyan)50">
              ${r.threatScore}/100 — ${r.verdict}
            </span>
          </div>
          <div style="font-size:13px;color:var(--text-secondary);line-height:1.5;margin-bottom:12px">
            Synthesized from deterministic technical evidence: RFC 5322 header anomaly checks, SPF/DKIM/DMARC alignment, IP geolocation, PhishTank threat feeds, and Browserless Chromium sandbox execution.
          </div>
          <div style="font-size:11px;color:var(--text-muted);font-family:'JetBrains Mono',monospace">
            SPF: ${r.authentication?.spf?.status || 'NONE'} &bull; DKIM: ${r.authentication?.dkim?.status || 'NONE'} &bull; URLs Scanned: ${r.urls?.count || 0}
          </div>
        </div>

        <!-- Card 2: Gemini Intent & Content Assessment -->
        <div class="gemini-contrast-box intent">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
            <div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#a855f7">
              🤖 Gemini Content Assessment
            </div>
            <span class="badge" style="font-size:12px;font-weight:700;background:#a855f720;color:#c084fc;border:1px solid #a855f750">
              ${assessment}
            </span>
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px">
            ${categories.map(c => `
              <span class="badge" style="background:rgba(168, 85, 247, 0.15);color:#d8b4fe;border:1px solid rgba(168, 85, 247, 0.3);font-size:10px">
                ${this._escapeHtml(c)}
              </span>
            `).join('')}
          </div>
          <div style="font-size:13px;color:var(--text-secondary);line-height:1.5">
            <strong>Key Distinction:</strong> Technical checks evaluate whether software is actively attacking your computer. Gemini evaluates human intent, social pressure, sensitive requests, and inappropriate content. An email may contain clean URLs while still being a social engineering scam or adult content!
          </div>
        </div>
      </div>

      <!-- Collapsible Raw Audit Details for SOC / Engineers -->
      <div class="card" style="margin-top:16px">
        <div class="card-header" style="cursor:pointer;display:flex;justify-content:space-between;align-items:center" onclick="const b=document.getElementById('gemini-raw-audit');b.style.display=b.style.display==='none'?'block':'none'">
          <div class="card-title" style="font-size:13px">🔬 Show / Hide SOC Technical AI Audit Payload (JSON)</div>
          <span style="font-size:12px;color:var(--text-muted)">Toggle ▼</span>
        </div>
        <div class="card-body" id="gemini-raw-audit" style="display:none;padding:14px">
          <pre class="font-mono" style="background:var(--bg-input);padding:14px;border-radius:6px;font-size:11px;color:var(--cyan);overflow-x:auto;max-height:360px">${this._escapeHtml(JSON.stringify(gemini, null, 2))}</pre>
        </div>
      </div>
    `;
  }

  // ─── GMAIL ACTIONS & HANDLERS ──────────────────────────────
  async loadGmailStatus() {
    try {
      const status = await window.GmailGuardAPI.getGmailStatus();
      this.gmailConnected = Boolean(status.connected);
      this.gmailConfigured = Boolean(status.configured);
      this.gmailUser = status.user || (status.email ? { email_address: status.email, messages_total: status.messages_total } : null);
      this.renderSidebar();
      const statusBadge = document.getElementById('gmail-status-badge');
      if (statusBadge) {
        statusBadge.className = `badge ${this.gmailConnected ? 'badge-pass' : 'badge-unknown'} font-mono`;
        statusBadge.textContent = this.gmailConnected ? '🟢 OAuth Connected' : '🟡 Offline Demo Stream';
      }
      const bannerContainer = document.getElementById('gmail-connect-banner-container');
      if (bannerContainer) {
        bannerContainer.innerHTML = this._renderGmailConnectionBanner();
      }
    } catch (_) {}
  }

  async loadGmailMessages(query = '') {
    this.gmailLoading = true;
    try {
      const res = await window.GmailGuardAPI.getGmailMessages(25, query);
      this.gmailMessages = res.messages || [];
      if (res.connected != null) {
        this.gmailConnected = Boolean(res.connected);
        this.gmailUser = res.user || this.gmailUser;
        this.renderSidebar();
      }

      // Populate per-email analysisState without clobbering any active in-flight states
      this.gmailMessages.forEach(m => {
        if (!this.analysisState[m.id] || this.analysisState[m.id].status !== 'analyzing') {
          if (m.threat_score != null || m.analysis_status === 'ANALYZED') {
            this.analysisState[m.id] = {
              status: 'completed',
              threatScore: m.threat_score,
              verdict: m.threat_verdict || 'EVALUATED',
              geminiAssessment: m.gemini_assessment || 'EVALUATED',
              error: null,
            };
            this.analysisResults[m.id] = this.analysisResults[m.id] || {
              threatScore: m.threat_score,
              verdict: m.threat_verdict,
              geminiAnalysis: { overallAssessment: m.gemini_assessment }
            };
          } else if (!this.analysisState[m.id]) {
            this.analysisState[m.id] = {
              status: 'idle',
              threatScore: null,
              verdict: null,
              geminiAssessment: null,
              error: null,
            };
          }
        }
      });

      this.renderCurrentGmailMessagesView();

      const bannerContainer = document.getElementById('gmail-connect-banner-container');
      if (bannerContainer) {
        bannerContainer.innerHTML = this._renderGmailConnectionBanner();
      }
    } catch (err) {
      this.showToast(`Failed to load Gmail messages: ${err.message}`, 'error', '⚠️');
    } finally {
      this.gmailLoading = false;
    }
  }

  getFilteredGmailMessages() {
    let list = [...this.gmailMessages];
    const filterType = this.activeGmailFilter || 'all';

    if (filterType === 'unread') {
      list = list.filter(m => m.is_unread);
    } else if (filterType === 'attachments') {
      list = list.filter(m => m.has_attachments);
    } else if (filterType === 'analyzed') {
      list = list.filter(m => {
        const st = this.analysisState[m.id];
        return (st && (st.status === 'completed' || st.threatScore != null)) || m.threat_score != null || m.analyzed;
      });
    } else if (filterType === 'pending') {
      list = list.filter(m => {
        const st = this.analysisState[m.id];
        return (!st || (st.status !== 'completed' && st.threatScore == null)) && m.threat_score == null && !m.analyzed;
      });
    }

    const q = (this.activeGmailSearch || '').toLowerCase().trim();
    if (q) {
      list = list.filter(m =>
        (m.sender_name || '').toLowerCase().includes(q) ||
        (m.sender_email || '').toLowerCase().includes(q) ||
        (m.subject || '').toLowerCase().includes(q) ||
        (m.snippet || '').toLowerCase().includes(q)
      );
    }

    return list;
  }

  _updateFilterCounts() {
    const total = this.gmailMessages.length;
    const unreadCount = this.gmailMessages.filter(m => m.is_unread).length;
    const attachCount = this.gmailMessages.filter(m => m.has_attachments).length;
    const analyzedCount = this.gmailMessages.filter(m => {
      const st = this.analysisState[m.id];
      return (st && (st.status === 'completed' || st.threatScore != null)) || m.threat_score != null || m.analyzed;
    }).length;
    const pendingCount = total - analyzedCount;

    const countAll = document.getElementById('count-all');
    if (countAll) countAll.textContent = total;
    const countUnread = document.getElementById('count-unread');
    if (countUnread) countUnread.textContent = unreadCount;
    const countAttachments = document.getElementById('count-attachments');
    if (countAttachments) countAttachments.textContent = attachCount;
    const countAnalyzed = document.getElementById('count-analyzed');
    if (countAnalyzed) countAnalyzed.textContent = analyzedCount;
    const countPending = document.getElementById('count-pending');
    if (countPending) countPending.textContent = pendingCount;
  }

  renderCurrentGmailMessagesView() {
    const container = document.getElementById('gmail-messages-table-container');
    if (!container) return;
    container.innerHTML = this._renderGmailMessagesTable();
    this._updateFilterCounts();
  }

  _updateGmailRow(messageId) {
    const msg = this.gmailMessages.find(m => m.id === messageId);
    if (!msg) return;

    // If currently filtered by pending/analyzed, check if message still belongs in current view
    const filterType = this.activeGmailFilter || 'all';
    const st = this.analysisState[messageId] || {};
    const isNowAnalyzed = (st.status === 'completed' || st.threatScore != null);

    if ((filterType === 'pending' && isNowAnalyzed) || (filterType === 'analyzed' && !isNowAnalyzed)) {
      this.renderCurrentGmailMessagesView();
      return;
    }

    const rowEl = document.getElementById(`gmail-row-${messageId}`);
    if (rowEl) {
      const tempWrapper = document.createElement('tbody');
      tempWrapper.innerHTML = this._renderGmailRowHtml(msg);
      const newRow = tempWrapper.firstElementChild;
      if (newRow) {
        rowEl.replaceWith(newRow);
      }
    } else {
      this.renderCurrentGmailMessagesView();
    }
    this._updateFilterCounts();
  }

  filterGmailMessages(query) {
    this.activeGmailSearch = query || '';
    this.gmailCurrentPage = 1;
    this.renderCurrentGmailMessagesView();
  }

  setGmailFilter(filterType) {
    this.activeGmailFilter = filterType;
    this.gmailCurrentPage = 1;
    document.querySelectorAll('.gmail-filter-btn').forEach(b => {
      b.classList.toggle('active', b.dataset.filter === filterType);
    });
    this.renderCurrentGmailMessagesView();
  }

  async connectGmail() {
    this.showToast('Initiating Google OAuth consent flow...', 'info', '🔐');
    try {
      const auth = await window.GmailGuardAPI.getGmailAuthUrl();
      if (auth.auth_url) {
        window.location.href = auth.auth_url;
      } else {
        this.toggleOAuthHelpModal();
        this.showToast('Google OAuth Client ID not configured. See Setup Guide.', 'warning', '⚠️');
      }
    } catch (err) {
      this.toggleOAuthHelpModal();
      this.showToast(`OAuth setup required: ${err.message}`, 'warning', '⚠️');
    }
  }

  async disconnectGmail() {
    try {
      await window.GmailGuardAPI.disconnectGmail();
      this.gmailConnected = false;
      this.gmailUser = null;
      this.analysisState = {};
      this.analysisResults = {};
      this.showToast('Gmail account disconnected.', 'info', '🔌');
      this.renderSidebar();
      await this.loadGmailMessages();
    } catch (err) {
      this.showToast(`Disconnect error: ${err.message}`, 'error', '⚠️');
    }
  }

  toggleOAuthHelpModal() {
    const modal = document.getElementById('gmail-oauth-modal');
    if (modal) {
      modal.style.display = modal.style.display === 'none' ? 'flex' : 'none';
    }
  }

  async analyzeGmailMessage(messageId, reanalyze = false) {
    // Set per-message state to analyzing
    this.analysisState[messageId] = {
      status: 'analyzing',
      threatScore: null,
      verdict: null,
      geminiAssessment: null,
      error: null,
      timestamp: Date.now(),
    };

    // Update only this specific row in the DOM
    this._updateGmailRow(messageId);
    this.showToast(`Analyzing email ${messageId.slice(0, 8)}...`, 'info', '⚡');

    try {
      const report = await window.GmailGuardAPI.analyzeGmailMessage(messageId, reanalyze);
      const normalized = window.ThreatReportNormalizer.normalize(report);

      // Key full forensic results by Gmail message ID
      this.analysisResults[messageId] = normalized;
      this.currentResult = normalized;

      // Update per-email state
      this.analysisState[messageId] = {
        status: 'completed',
        threatScore: normalized.threatScore,
        verdict: normalized.verdict,
        geminiAssessment: normalized.geminiAnalysis?.overallAssessment || 'EVALUATED',
        error: null,
        timestamp: Date.now(),
      };

      // Update message entry in local array
      const idx = this.gmailMessages.findIndex(m => m.id === messageId);
      if (idx >= 0) {
        this.gmailMessages[idx].threat_score = normalized.threatScore;
        this.gmailMessages[idx].threat_verdict = normalized.verdict;
        this.gmailMessages[idx].gemini_assessment = normalized.geminiAnalysis?.overallAssessment || 'EVALUATED';
        this.gmailMessages[idx].analyzed = true;
        this.gmailMessages[idx].is_unread = false;
      }

      // Add to session investigations list
      const existing = this.sessionInvestigations.findIndex(c => c.caseId === normalized.caseId);
      if (existing >= 0) {
        this.sessionInvestigations[existing] = normalized;
      } else {
        this.sessionInvestigations.unshift(normalized);
      }

      this.showToast(`Analysis complete: ${normalized.verdict} (Score: ${normalized.threatScore}/100)`, 'success', '🎯');

      // Update only this specific row in DOM without re-rendering or navigating away
      this._updateGmailRow(messageId);
      this._updateFilterCounts();

      // Update session banner counts if present in DOM
      const bannerContainer = document.getElementById('gmail-connect-banner-container');
      if (bannerContainer) {
        bannerContainer.innerHTML = this._renderGmailConnectionBanner();
      }
    } catch (err) {
      this.analysisState[messageId] = {
        status: 'error',
        threatScore: null,
        verdict: null,
        geminiAssessment: null,
        error: err.message || 'Analysis failed',
        timestamp: Date.now(),
      };
      this._updateGmailRow(messageId);
      this._updateFilterCounts();
      this.showToast(`Analysis failed: ${err.message}`, 'error', '❌');
    }
  }

  async viewGmailAnalysis(messageId) {
    // Check if in session investigations first
    const fromSession = this.sessionInvestigations.find(c => c.rawResult?.gmail_message_id === messageId);
    if (fromSession) {
      this.currentResult = fromSession;
      this.navigateTo('gemini-security');
      return;
    }

    if (this.analysisResults[messageId] && this.analysisResults[messageId].caseId) {
      this.currentResult = this.analysisResults[messageId];
      this.navigateTo('gemini-security');
      return;
    }

    try {
      this.showToast('Fetching cached forensic and Gemini analysis...', 'info', '🔍');
      const cached = await window.GmailGuardAPI.getGmailAnalysis(messageId);
      if (cached && !cached.error) {
        const normalized = window.ThreatReportNormalizer.normalize(cached);
        this.currentResult = normalized;
        this.navigateTo('gemini-security');
      } else {
        // Run analysis on demand
        await this.analyzeGmailMessage(messageId, false);
      }
    } catch (err) {
      this.showToast(`Error opening analysis: ${err.message}`, 'error', '⚠️');
    }
  }

  // ─── G. REPORTS ────────────────────────────────────────────
  renderReports() {
    const content = document.getElementById('page-content');
    const r = this.currentResult;

    if (!r) {
      content.innerHTML = `
        <div class="card" style="max-width:600px;margin:60px auto;text-align:center;padding:40px 20px">
          <div style="font-size:48px;margin-bottom:12px">📋</div>
          <div style="font-size:18px;font-weight:700;color:var(--text-primary);margin-bottom:8px">No Case Report Available</div>
          <div style="font-size:13px;color:var(--text-muted);margin-bottom:24px">
            Ingest and analyze an email first to synthesize a forensic report.
          </div>
          <button class="btn btn-primary" onclick="app.navigateTo('analyze')">Analyze Email →</button>
        </div>
      `;
      return;
    }

    const gen = new window.ForensicReportGenerator(r);
    content.innerHTML = `
      <div style="max-width:1000px;margin:0 auto">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;flex-wrap:wrap;gap:12px">
          <div>
            <div style="font-size:18px;font-weight:700;color:var(--text-primary)">Case Report: ${r.caseId}</div>
            <div style="font-size:12px;color:var(--text-muted)">Forensic Audit & SOC Export View</div>
          </div>
          <div style="display:flex;gap:10px">
            <button class="btn btn-primary btn-sm" onclick="app.downloadReport()">📥 Download HTML Report</button>
            <button class="btn btn-secondary btn-sm" onclick="app.printReport()">🖨️ Print / Save PDF</button>
          </div>
        </div>

        <div class="card" style="padding:0;overflow:hidden">
          <iframe id="report-preview-frame" style="width:100%;height:780px;border:none;background:#060b16"></iframe>
        </div>
      </div>
    `;

    setTimeout(() => {
      const iframe = document.getElementById('report-preview-frame');
      if (iframe) {
        iframe.srcdoc = gen.generateHTML();
      }
    }, 50);
  }

  // ─── Export Utilities ──────────────────────────────────────
  downloadReport() {
    if (!this.currentResult) {
      this.showToast('No active investigation to export', 'error', '⚠️');
      return;
    }
    const gen = new window.ForensicReportGenerator(this.currentResult);
    gen.download();
    this.showToast('Forensic report downloaded!', 'success', '📄');
  }

  printReport() {
    if (!this.currentResult) {
      this.showToast('No active investigation to print', 'error', '⚠️');
      return;
    }
    const gen = new window.ForensicReportGenerator(this.currentResult);
    gen.print();
  }

  copyAllIOCs() {
    if (!this.currentResult || !this.currentResult.iocs) return;
    const text = this.currentResult.iocs.map(i => `${i.type}: ${i.value} (${i.category})`).join('\n');
    navigator.clipboard.writeText(text);
    this.showToast(`${this.currentResult.iocs.length} IOCs copied to clipboard!`, 'success', '📋');
  }

  exportIOCsJSON() {
    if (!this.currentResult || !this.currentResult.iocs) return;
    const jsonStr = JSON.stringify(this.currentResult.iocs, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `GmailGuard-IOCs-${this.currentResult.caseId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    this.showToast('IOCs exported as JSON', 'success', '📥');
  }
}

// App class is instantiated from index.html with error boundary wrapping.
