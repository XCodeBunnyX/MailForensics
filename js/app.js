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
      { id: 'analyze', icon: '🔍', label: 'Analyze Email' },
      { id: 'investigation', icon: '🎯', label: 'Investigation', badge: this.currentResult ? 'Active' : null },
      { id: 'infrastructure', icon: '🌍', label: 'Infrastructure & Geo' },
      { id: 'threat-intel', icon: '🌐', label: 'Threat Intel & IOCs' },
      { id: 'forensics', icon: '🔬', label: 'Forensic Evidence' },
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
      ${nav.slice(0, 2).map(n => this._navItem(n)).join('')}
      <div class="sidebar-section">Forensic Analysis</div>
      ${nav.slice(2, 6).map(n => this._navItem(n)).join('')}
      <div class="sidebar-section">Intelligence</div>
      ${nav.slice(6).map(n => this._navItem(n)).join('')}
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
      analyze: ['Analyze Email', 'RFC 5322 Ingestion, File Parsing & Engine Pipeline'],
      investigation: ['Investigation / Analysis Result', 'Comprehensive Multi-Vector Threat Assessment'],
      infrastructure: ['Infrastructure & Geolocation', 'Candidate Relays, Transit Observables & Clock Skew'],
      'threat-intel': ['Threat Intelligence & IOCs', 'Domain Reputation, PhishTank Feeds & Extracted Artifacts'],
      forensics: ['Forensic Evidence & AI Analysis', 'Authentication Verification, Static Attachments & SVM Hyperplane'],
      reports: ['Forensic Reports', 'Audit-Ready Digital Forensic Investigation Summaries']
    };
    const [title, sub] = titles[this.currentPage] || ['GmailGuard', ''];
    const topbar = document.getElementById('topbar');
    if (!topbar) return;

    topbar.innerHTML = `
      <div>
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
      analyze: () => this.renderAnalyze(),
      investigation: () => this.renderInvestigation(),
      infrastructure: () => this.renderInfrastructure(),
      'threat-intel': () => this.renderThreatIntel(),
      forensics: () => this.renderForensics(),
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

          <!-- Sub-scores breakdown -->
          ${r.subScores ? `
          <div class="card animate-in animate-in-delay-2">
            <div class="card-header"><div class="card-title">📊 Multi-Vector Sub-Scores</div></div>
            <div class="card-body" style="padding:12px 16px">
              ${Object.entries(r.subScores).map(([k, v]) => `
                <div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--border)">
                  <span style="font-size:11px;color:var(--text-secondary);text-transform:capitalize">${k.replace(/_/g, ' ')}</span>
                  <span class="font-mono" style="font-size:12px;font-weight:600;color:${v >= 20 ? 'var(--critical)' : v >= 10 ? 'var(--medium)' : 'var(--low)'}">+${v}</span>
                </div>
              `).join('')}
            </div>
          </div>` : ''}
        </div>

        <!-- Right Main Panel -->
        <div class="results-main animate-in">
          <!-- Navigation Sub-Tabs -->
          <div class="results-tabs">
            <div class="result-tab active" data-tab="overview" onclick="app.switchInvestigationTab('overview')">📊 Overview & Why?</div>
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
              <div class="card-header">
                <div class="card-title">🌍 Observable Mail Infrastructure Geolocation (${r.geolocation?.length || 0})</div>
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
                          <div class="geo-ip font-mono">${g.ip}</div>
                          <div class="geo-location">${g.city || 'Unknown'}, ${g.region ? g.region + ', ' : ''}${g.country || 'Unknown'}</div>
                          <div class="geo-org font-mono" style="font-size:11px">${g.asn || ''} • ${g.org || 'Unknown'} &nbsp;|&nbsp; TZ: ${g.timezone}</div>
                          <div style="font-size:10px;color:var(--text-muted);margin-top:3px">ℹ️ ${g.forensicNote}</div>
                        </div>
                        <div class="geo-right">
                          <span class="badge badge-medium" style="font-size:10px">${g.locationType}</span>
                        </div>
                      </div>
                    `).join('')}
                  </div>
                ` : '<div style="color:var(--text-muted)">No routable public IPs observed in headers.</div>'}
              </div>
            </div>
          </div>

          <!-- TAB 4: URLS & DOMAINS -->
          <div class="tab-panel" id="inv-tab-urls">
            <!-- URL Intelligence -->
            <div class="card mb-16">
              <div class="card-header">
                <div class="card-title">🔗 Extracted URLs & Threat Intelligence (${r.urls?.length || 0})</div>
              </div>
              <div class="card-body">
                <div style="font-size:11px;color:var(--text-muted);margin-bottom:12px">
                  ℹ️ Security Policy: URLs are handled as immutable forensic data, not clickable hyperlinks.
                </div>
                ${(r.urls && r.urls.length > 0) ? `
                  <div style="display:flex;flex-direction:column;gap:10px">
                    ${r.urls.map(u => `
                      <div class="url-item">
                        <span>${u.isPhishTankVerified || u.isIpUrl ? '🔴' : '🟠'}</span>
                        <span class="url-text font-mono">${u.url}</span>
                        ${u.isPhishTankVerified ? `<span class="badge badge-phishtank">🚨 PhishTank #${u.phishTankId || 'MATCH'} (Target: ${u.phishTankTarget || 'Brand'})</span>` : ''}
                        ${u.isIpUrl ? '<span class="badge badge-critical">IP-Based URL</span>' : ''}
                        <span class="badge badge-${u.riskScore >= 50 ? 'critical' : u.riskScore >= 25 ? 'high' : 'low'}">Risk: ${u.riskScore}</span>
                      </div>
                    `).join('')}
                  </div>
                ` : '<div style="color:var(--text-muted)">No URLs detected in message body.</div>'}
              </div>
            </div>

            <!-- Domain Intelligence -->
            <div class="card">
              <div class="card-header">
                <div class="card-title">🔍 Sender Domain Intelligence</div>
              </div>
              <div class="card-body">
                <div class="grid-2">
                  <div class="info-card"><div class="info-label">Domain Name</div><div class="info-value">${r.domain?.domain}</div></div>
                  <div class="info-card"><div class="info-label">Domain Age</div><div class="info-value">${r.domain?.ageDays != null ? r.domain.ageDays + ' days' : 'Not available'} ${r.domain?.ageDays != null && r.domain.ageDays < 30 ? '<span class="badge badge-fail" style="margin-left:6px">Newly Registered</span>' : ''}</div></div>
                  <div class="info-card"><div class="info-label">Registrar</div><div class="info-value">${r.domain?.registrar}</div></div>
                  <div class="info-card"><div class="info-label">Typosquatting Check</div><div class="info-value">${r.domain?.isTyposquat ? '<span class="badge badge-fail">TYPOSQUAT TARGET: ' + r.domain.typosquatTarget + '</span>' : 'None detected'}</div></div>
                </div>
              </div>
            </div>
          </div>

          <!-- TAB 5: ATTACHMENTS -->
          <div class="tab-panel" id="inv-tab-attachments">
            <div class="card">
              <div class="card-header">
                <div class="card-title">📎 Attachment Forensics (${r.attachments?.length || 0})</div>
              </div>
              <div class="card-body">
                <div style="background:#080e1c;border-left:3px solid var(--cyan);padding:10px 14px;border-radius:4px;font-size:12px;color:var(--text-secondary);margin-bottom:16px">
                  ℹ️ <strong>Static Analysis Notice:</strong> Files are analyzed statically. Suspicious files are NOT executed.
                </div>
                ${(r.attachments && r.attachments.length > 0) ? `
                  <div style="display:flex;flex-direction:column;gap:12px">
                    ${r.attachments.map(a => `
                      <div class="attachment-item">
                        <div class="attach-header">
                          <div class="attach-icon">${a.extension === 'pdf' ? '📕' : ['docm','doc','xls','xlsm'].includes(a.extension) ? '📘' : '📄'}</div>
                          <div>
                            <div class="attach-name font-mono">${a.filename}</div>
                            <div class="attach-meta">${a.contentType} • ${a.sizeMb} MB</div>
                          </div>
                          <div style="margin-left:auto;display:flex;flex-direction:column;align-items:flex-end;gap:6px">
                            <span class="badge badge-${a.riskScore >= 60 ? 'critical' : a.riskScore >= 30 ? 'high' : 'low'}">
                              ${a.riskScore >= 60 ? 'DANGEROUS' : a.riskScore >= 30 ? 'SUSPICIOUS' : 'EVALUATED'}
                            </span>
                            ${a.isMacroEnabled ? '<span class="badge badge-critical">⚠ MACRO ENABLED</span>' : ''}
                          </div>
                        </div>
                        <div class="attach-hashes">
                          <div class="hash-row"><div class="hash-label">Extension Findings</div><div class="hash-value">${a.isDangerousExtension ? 'Dangerous File Extension Flagged' : 'Standard Extension'}</div></div>
                          <div class="hash-row"><div class="hash-label">Risk Factors</div><div class="hash-value">${(a.reasons || []).join('; ') || 'No anomalies detected'}</div></div>
                        </div>
                      </div>
                    `).join('')}
                  </div>
                ` : `
                  <div class="empty-state">
                    <div class="empty-icon">📎</div>
                    <div class="empty-title">No Attachments Detected</div>
                    <div class="empty-text">This email has no file attachments.</div>
                  </div>
                `}
              </div>
            </div>
          </div>

          <!-- TAB 6: AI CONTENT ANALYSIS -->
          <div class="tab-panel" id="inv-tab-ai">
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

// Instantiate application on window load
window.addEventListener('DOMContentLoaded', () => {
  window.app = new GmailGuardApp();
  window.app.init();
});
