// ============================================================
// MailForensics — Main Application Controller
// ============================================================

class MailForensicsApp {
  constructor() {
    this.currentPage = 'dashboard';
    this.currentResult = null;
    this.investigations = [...window.MAILFORENSICS_DATA.DEMO_INVESTIGATIONS];
    this.charts = {};
    this.clockInterval = null;
  }

  init() {
    this.renderSidebar();
    this.renderMainArea();   // must run before renderTopbar — creates #topbar element
    this.renderTopbar();
    this.startClock();
    this.navigateTo('dashboard');
    this.setupToastContainer();
  }

  startClock() {
    const update = () => {
      const el = document.getElementById('topbar-clock');
      if (el) el.textContent = new Date().toLocaleTimeString('en-IN', { hour12: false });
    };
    update();
    this.clockInterval = setInterval(update, 1000);
  }

  setupToastContainer() {
    const div = document.createElement('div');
    div.className = 'toast-container';
    div.id = 'toast-container';
    document.body.appendChild(div);
  }

  showToast(message, type = 'info', icon = 'ℹ️') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
    container.appendChild(toast);
    setTimeout(() => { toast.style.opacity = '0'; toast.style.transform = 'translateX(100%)'; toast.style.transition = '0.3s'; setTimeout(() => toast.remove(), 300); }, 3500);
  }

  renderSidebar() {
    const nav = [
      { id: 'dashboard', icon: '⬡', label: 'Dashboard' },
      { id: 'analyze', icon: '🔍', label: 'Analyze Email', badge: null },
      { id: 'investigations', icon: '📁', label: 'Investigations', badge: this.investigations.filter(i => i.status === 'review').length },
      { id: 'threat-intel', icon: '🌐', label: 'Threat Intelligence' },
      { id: 'indicators', icon: '🚨', label: 'Indicators' },
      { id: 'reports', icon: '📋', label: 'Reports' },
      { id: 'settings', icon: '⚙️', label: 'Settings' },
    ];

    document.getElementById('sidebar').innerHTML = `
      <div class="sidebar-logo">
        <div class="logo-icon">⬡</div>
        <div>
          <div class="logo-text">MailForensics</div>
          <div class="logo-tagline">Email Forensics Platform</div>
        </div>
      </div>
      <div class="sidebar-section">Navigation</div>
      ${nav.slice(0,2).map(n => this._navItem(n)).join('')}
      <div class="sidebar-section">Investigations</div>
      ${nav.slice(2,6).map(n => this._navItem(n)).join('')}
      <div class="sidebar-section">System</div>
      ${nav.slice(6).map(n => this._navItem(n)).join('')}
      <div class="sidebar-footer">
        <div class="threat-level-indicator">
          <div class="threat-level-header">🛡️ System Threat Level</div>
          <div class="threat-level-value">
            <div class="pulse-dot"></div>
            ELEVATED
          </div>
        </div>
        <div style="margin-top:12px;font-size:11px;color:var(--text-muted);text-align:center;">
          SIH 2026 — Problem SIH26106<br>Team AICTE | v2.6.0
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

  renderTopbar() {
    const titles = {
      dashboard: ['Dashboard', 'Overview & Statistics'],
      analyze: ['Analyze Email', 'Upload & Investigate Suspicious Emails'],
      investigations: ['Investigations', 'Case Management'],
      'threat-intel': ['Threat Intelligence', 'IOC Database & Feeds'],
      indicators: ['Indicators of Compromise', 'Extracted IOC Repository'],
      reports: ['Reports', 'Forensic Investigation Reports'],
      settings: ['Settings', 'Platform Configuration']
    };
    const [title, sub] = titles[this.currentPage] || ['MailForensics', ''];
    document.getElementById('topbar').innerHTML = `
      <div>
        <div class="topbar-title">${title}</div>
        <div class="topbar-subtitle">${sub}</div>
      </div>
      <div class="topbar-right">
        <div class="topbar-time font-mono" id="topbar-clock"></div>
        <div class="topbar-status"><div class="pulse-dot" style="--pulse-color:var(--low)"></div>All Systems Operational</div>
        <div class="topbar-avatar" title="SOC Analyst">👤</div>
      </div>
    `;
    this.startClock();
  }

  renderMainArea() {
    const main = document.getElementById('main-content');
    main.innerHTML = `
      <div id="topbar" class="topbar"></div>
      <div id="page-content" class="page-content"></div>
    `;
  }

  navigateTo(page) {
    this.currentPage = page;
    document.querySelectorAll('.nav-item').forEach(el => {
      el.classList.toggle('active', el.dataset.page === page);
    });
    this.renderTopbar();

    const content = document.getElementById('page-content');
    content.innerHTML = '';
    content.style.animation = 'none';
    requestAnimationFrame(() => {
      content.style.animation = 'fadeInUp 0.3s ease-out both';
    });

    const pages = {
      dashboard: () => this.renderDashboard(),
      analyze: () => this.renderAnalyze(),
      investigations: () => this.renderInvestigations(),
      'threat-intel': () => this.renderThreatIntel(),
      indicators: () => this.renderIndicators(),
      reports: () => this.renderReports(),
      settings: () => this.renderSettings(),
    };

    if (pages[page]) pages[page]();
    else content.innerHTML = `<div class="empty-state"><div class="empty-icon">🚧</div><div class="empty-title">Coming Soon</div></div>`;
  }

  // ─── Dashboard Page ─────────────────────────────────────
  renderDashboard() {
    const content = document.getElementById('page-content');
    const { CHART_DATA } = window.MAILFORENSICS_DATA;
    const criticalCount = this.investigations.filter(i => i.risk === 'critical').length;
    const highCount = this.investigations.filter(i => i.risk === 'high').length;
    const urlCount = 23;
    const iocCount = 47;

    content.innerHTML = `
      <!-- Stats -->
      <div class="stats-grid mb-24">
        <div class="stat-card animate-in" style="--accent-color:var(--cyan)" onclick="app.navigateTo('investigations')">
          <div class="stat-icon">📁</div>
          <div class="stat-value">${this.investigations.length}</div>
          <div class="stat-label">Total Investigations</div>
          <div class="stat-change up">↑ 12 this week</div>
        </div>
        <div class="stat-card animate-in animate-in-delay-1" style="--accent-color:var(--critical)">
          <div class="stat-icon">🚨</div>
          <div class="stat-value text-critical">${criticalCount}</div>
          <div class="stat-label">Critical Threats</div>
          <div class="stat-change up">↑ 3 today</div>
        </div>
        <div class="stat-card animate-in animate-in-delay-2" style="--accent-color:var(--high)">
          <div class="stat-icon">⚠️</div>
          <div class="stat-value text-high">${highCount}</div>
          <div class="stat-label">High Risk Emails</div>
          <div class="stat-change up">↑ 5 this week</div>
        </div>
        <div class="stat-card animate-in animate-in-delay-3" style="--accent-color:var(--medium)">
          <div class="stat-icon">🔗</div>
          <div class="stat-value text-medium">${urlCount}</div>
          <div class="stat-label">Suspicious URLs</div>
          <div class="stat-change up">↑ 8 today</div>
        </div>
        <div class="stat-card animate-in animate-in-delay-4" style="--accent-color:var(--purple)">
          <div class="stat-icon">🚩</div>
          <div class="stat-value" style="color:var(--purple)">${iocCount}</div>
          <div class="stat-label">Malicious Indicators</div>
          <div class="stat-change up">↑ 14 this week</div>
        </div>
      </div>

      <!-- Charts Row -->
      <div class="grid-2 mb-24">
        <div class="card animate-in">
          <div class="card-header">
            <div class="card-title">📈 Threat Activity (7 Days)</div>
          </div>
          <div class="card-body">
            <div class="chart-wrap"><canvas id="threat-trend-chart"></canvas></div>
          </div>
        </div>
        <div class="card animate-in animate-in-delay-1">
          <div class="card-header">
            <div class="card-title">🥧 Threat Type Distribution</div>
          </div>
          <div class="card-body">
            <div class="chart-wrap"><canvas id="type-donut-chart"></canvas></div>
          </div>
        </div>
      </div>

      <!-- Recent Investigations -->
      <div class="card animate-in animate-in-delay-2">
        <div class="card-header">
          <div class="card-title">📋 Recent Investigations</div>
          <button class="btn btn-secondary btn-sm" onclick="app.navigateTo('investigations')">View All</button>
        </div>
        <div class="data-table-wrap">
          ${this._renderInvestigationsTable(this.investigations.slice(0, 6))}
        </div>
      </div>
    `;

    setTimeout(() => this._initDashboardCharts(), 100);
  }

  _renderInvestigationsTable(rows) {
    const scoreColor = s => s >= 80 ? 'critical' : s >= 60 ? 'high' : s >= 35 ? 'medium' : 'low';
    return `
      <table class="data-table">
        <thead>
          <tr>
            <th>Case ID</th>
            <th>Sender</th>
            <th>Subject</th>
            <th>Risk</th>
            <th>Threat Type</th>
            <th>Score</th>
            <th>Date</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map(r => `
            <tr onclick="app.openInvestigation('${r.id}')">
              <td class="case-id-cell">${r.id}</td>
              <td class="email-cell" title="${r.email}">${r.email}</td>
              <td class="email-cell" title="${r.subject}">${r.subject}</td>
              <td><span class="badge badge-${r.risk}">${r.risk.toUpperCase()}</span></td>
              <td style="font-size:12px;color:var(--text-secondary)">${r.type}</td>
              <td class="score-cell text-${scoreColor(r.score)}">${r.score}</td>
              <td class="mono" style="font-size:11px;color:var(--text-muted)">${r.date}</td>
              <td><span class="badge badge-${r.status}">${r.status.toUpperCase()}</span></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  }

  _initDashboardCharts() {
    const { CHART_DATA } = window.MAILFORENSICS_DATA;
    if (document.getElementById('threat-trend-chart')) {
      this.charts.trend = new Chart(document.getElementById('threat-trend-chart'), {
        type: 'line',
        data: {
          labels: CHART_DATA.threatTrend.labels,
          datasets: [
            { label: 'Critical', data: CHART_DATA.threatTrend.critical, borderColor: '#ff2d55', backgroundColor: '#ff2d5510', tension: 0.4, fill: true, pointRadius: 3 },
            { label: 'High', data: CHART_DATA.threatTrend.high, borderColor: '#ff6b35', backgroundColor: '#ff6b3510', tension: 0.4, fill: true, pointRadius: 3 },
            { label: 'Medium', data: CHART_DATA.threatTrend.medium, borderColor: '#ffd60a', backgroundColor: '#ffd60a10', tension: 0.4, fill: true, pointRadius: 3 },
            { label: 'Low', data: CHART_DATA.threatTrend.low, borderColor: '#34d399', backgroundColor: '#34d39910', tension: 0.4, fill: true, pointRadius: 3 },
          ]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { labels: { color: '#64748b', font: { size: 11 }, boxWidth: 12 } } },
          scales: {
            x: { ticks: { color: '#4a5568', font: { size: 10 } }, grid: { color: '#1e293b' } },
            y: { ticks: { color: '#4a5568', font: { size: 10 } }, grid: { color: '#1e293b' } }
          }
        }
      });
    }
    if (document.getElementById('type-donut-chart')) {
      this.charts.donut = new Chart(document.getElementById('type-donut-chart'), {
        type: 'doughnut',
        data: {
          labels: CHART_DATA.typeBreakdown.labels,
          datasets: [{ data: CHART_DATA.typeBreakdown.values, backgroundColor: ['#ff2d55','#ff6b35','#7c3aed','#00d4ff','#ffd60a','#34d399'], borderWidth: 0, hoverOffset: 6 }]
        },
        options: {
          responsive: true, maintainAspectRatio: false, cutout: '70%',
          plugins: { legend: { position: 'right', labels: { color: '#64748b', font: { size: 11 }, boxWidth: 12, padding: 12 } } }
        }
      });
    }
  }

  // ─── Analyze Page ─────────────────────────────────────────
  renderAnalyze() {
    const content = document.getElementById('page-content');
    const { DEMO_EMAILS } = window.MAILFORENSICS_DATA;
    const demoCards = Object.entries(DEMO_EMAILS).map(([key, demo]) => {
      const riskColors = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)' };
      const color = riskColors[demo.risk] || 'var(--cyan)';
      return `<div class="demo-card" style="--accent:${color}" onclick="app.runDemoAnalysis('${key}')">
        <div class="demo-card-label">${demo.label}</div>
        <div class="demo-card-type" style="color:${color};font-size:12px;font-weight:600;">${demo.risk.toUpperCase()} RISK</div>
        <div class="demo-card-footer">
          <span style="font-size:11px;color:var(--text-muted)">Click to analyze</span>
          <span class="badge badge-${demo.risk}">Demo</span>
        </div>
      </div>`;
    }).join('');

    content.innerHTML = `
      <div class="grid-2 animate-in" style="gap:24px;align-items:start">
        <!-- Upload Panel -->
        <div>
          <div class="section-header mb-16">
            <div class="section-title">Upload Suspicious Email</div>
          </div>
          <div class="upload-zone" id="upload-zone" onclick="document.getElementById('file-input').click()">
            <input type="file" id="file-input" accept=".eml,.txt,.msg" style="display:none" onchange="app.handleFileUpload(event)">
            <div class="upload-icon">📧</div>
            <div class="upload-title">Drop your email file here</div>
            <div class="upload-subtitle">or click to browse your files</div>
            <div class="upload-formats">
              <span class="format-badge">.eml</span>
              <span class="format-badge">.txt</span>
              <span class="format-badge">.msg</span>
              <span class="format-badge">Raw Text</span>
            </div>
          </div>
          <div class="divider"></div>
          <div class="section-title mb-16" style="margin-bottom:12px">Or Paste Raw Email Text</div>
          <textarea class="paste-area" id="paste-area" placeholder="Paste the full email source here including headers...
Example:
From: sender@domain.com
To: recipient@example.com
Subject: Test Email
..."></textarea>
          <div style="display:flex;gap:10px;margin-top:12px">
            <button class="btn btn-primary" style="flex:1" onclick="app.analyzeFromPaste()">
              🔍 Analyze Email
            </button>
            <button class="btn btn-secondary" onclick="document.getElementById('paste-area').value=''">
              🗑 Clear
            </button>
          </div>
        </div>

        <!-- Demo Panel -->
        <div>
          <div class="section-header mb-16">
            <div class="section-title">Try a Demo Investigation</div>
          </div>
          <div class="demo-cards" style="grid-template-columns:1fr">
            ${demoCards}
          </div>
          <div class="card mt-16" style="margin-top:16px">
            <div class="card-body" style="padding:16px">
              <div style="font-size:12px;font-weight:700;color:var(--text-muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:1px">ℹ️ What MailForensics Analyzes</div>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:12px;color:var(--text-secondary)">
                <div>✓ Header forensics</div>
                <div>✓ SPF/DKIM/DMARC</div>
                <div>✓ IP geolocation</div>
                <div>✓ URL intelligence</div>
                <div>✓ Domain reputation</div>
                <div>✓ Attachment analysis</div>
                <div>✓ NLP threat scoring</div>
                <div>✓ IOC extraction</div>
                <div>✓ Relationship graph</div>
                <div>✓ Forensic report</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    // Setup drag and drop
    const zone = document.getElementById('upload-zone');
    zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
    zone.addEventListener('drop', e => { e.preventDefault(); zone.classList.remove('drag-over'); const file = e.dataTransfer.files[0]; if (file) this.processFile(file); });
  }

  handleFileUpload(event) {
    const file = event.target.files[0];
    if (file) this.processFile(file);
  }

  processFile(file) {
    const reader = new FileReader();
    reader.onload = e => {
      document.getElementById('paste-area') && (document.getElementById('paste-area').value = e.target.result);
      this.showToast(`File loaded: ${file.name}`, 'success', '📎');
      this.startAnalysis(e.target.result);
    };
    reader.readAsText(file);
  }

  analyzeFromPaste() {
    const text = document.getElementById('paste-area')?.value?.trim();
    if (!text || text.length < 10) {
      this.showToast('Please paste email content first', 'error', '⚠️');
      return;
    }
    this.startAnalysis(text);
  }

  runDemoAnalysis(key) {
    const { DEMO_EMAILS } = window.MAILFORENSICS_DATA;
    const demo = DEMO_EMAILS[key];
    if (!demo) return;
    this.showToast(`Loading demo: ${demo.label.replace(/^[^\s]+\s/, '')}`, 'info', '🔬');
    this.startAnalysis(demo.raw);
  }

  startAnalysis(rawEmail) {
    this.showScannerState(rawEmail);
  }

  showScannerState(rawEmail) {
    const content = document.getElementById('page-content');
    const steps = [
      { icon: '📋', label: 'Parsing Email Headers' },
      { icon: '🛡️', label: 'Checking SPF/DKIM/DMARC' },
      { icon: '🔗', label: 'Extracting URLs & Domains' },
      { icon: '🌍', label: 'Performing IP Geolocation' },
      { icon: '🔍', label: 'Domain Intelligence Lookup' },
      { icon: '📎', label: 'Analyzing Attachments' },
      { icon: '🤖', label: 'AI/ML Threat Assessment' },
      { icon: '📊', label: 'Computing Threat Score' },
      { icon: '🚨', label: 'Extracting IOCs' },
      { icon: '✅', label: 'Generating Investigation Report' },
    ];

    content.innerHTML = `
      <div class="scanner-container animate-in">
        <div class="scanner-hex">
          <svg viewBox="0 0 120 120" xmlns="http://www.w3.org/2000/svg">
            <circle cx="60" cy="60" r="52" stroke="#00d4ff20" stroke-width="2" fill="none"/>
            <circle cx="60" cy="60" r="52" stroke="url(#scanGrad)" stroke-width="3" fill="none" stroke-dasharray="327" stroke-dashoffset="82"/>
            <defs>
              <linearGradient id="scanGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stop-color="#00d4ff"/>
                <stop offset="100%" stop-color="#7c3aed"/>
              </linearGradient>
            </defs>
          </svg>
          <div class="scanner-hex-inner">🔬</div>
        </div>
        <div style="font-size:22px;font-weight:700;color:var(--text-primary);margin-bottom:8px">Analyzing Email Threat...</div>
        <div style="font-size:14px;color:var(--text-muted);margin-bottom:32px">MailForensics AI Engine running forensic analysis</div>
        <div class="scan-steps" id="scan-steps">
          ${steps.map((s, i) => `
            <div class="scan-step pending" id="step-${i}">
              <span class="scan-step-icon">${s.icon}</span>
              <span class="scan-step-label">${s.label}</span>
              <span class="scan-step-status">Waiting...</span>
            </div>
          `).join('')}
        </div>
      </div>
    `;

    let current = 0;
    const runStep = () => {
      if (current > 0) {
        const prev = document.getElementById(`step-${current - 1}`);
        if (prev) { prev.className = 'scan-step done'; prev.querySelector('.scan-step-status').textContent = '✓ Done'; }
      }
      if (current < steps.length) {
        const el = document.getElementById(`step-${current}`);
        if (el) { el.className = 'scan-step active'; el.querySelector('.scan-step-status').textContent = 'Running...'; }
        current++;
        const delay = current === steps.length ? 400 : (150 + Math.random() * 200);
        setTimeout(runStep, delay);
      } else {
        // Analysis complete — run actual analysis
        const analyzer = new window.EmailAnalyzer(rawEmail);
        const result = analyzer.analyze();
        this.currentResult = result;

        // Add to investigations
        const newCase = {
          id: result.caseId,
          email: result.sender.from.replace(/.*<(.+)>/, '$1').trim(),
          subject: result.subject,
          risk: result.riskLevel.toLowerCase(),
          type: result.threatType,
          date: new Date().toLocaleString('en-IN', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }),
          status: result.threatScore >= 70 ? 'confirmed' : 'review',
          score: result.threatScore
        };
        this.investigations.unshift(newCase);

        setTimeout(() => this.showResults(result), 300);
      }
    };

    setTimeout(runStep, 400);
  }

  showResults(result) {
    const content = document.getElementById('page-content');
    const riskColors = { CRITICAL: 'var(--critical)', HIGH: 'var(--high)', MEDIUM: 'var(--medium)', LOW: 'var(--low)' };
    const rColor = riskColors[result.riskLevel] || 'var(--cyan)';
    const scoreCircumference = 2 * Math.PI * 70;
    const scoreFill = scoreCircumference - (result.threatScore / 100) * scoreCircumference;
    const scoreColor = result.threatScore >= 80 ? '#ff2d55' : result.threatScore >= 60 ? '#ff6b35' : result.threatScore >= 35 ? '#ffd60a' : '#34d399';

    const tabs = [
      { id: 'overview', label: '📊 Overview', icon: '📊' },
      { id: 'headers', label: '📋 Headers', icon: '📋' },
      { id: 'network', label: '🌍 Network', icon: '🌍' },
      { id: 'urls', label: '🔗 URLs & Domains', icon: '🔗' },
      { id: 'attachments', label: '📎 Attachments', icon: '📎' },
      { id: 'ai', label: '🤖 AI Analysis', icon: '🤖' },
      { id: 'graph', label: '🕸️ Graph', icon: '🕸️' },
      { id: 'iocs', label: '🚨 IOCs', icon: '🚨' },
    ];

    content.innerHTML = `
      <!-- Top Row: Score + Actions -->
      <div class="flex-center gap-12 mb-24" style="flex-wrap:wrap">
        <div>
          <div style="font-size:11px;color:var(--text-muted);letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Case ID</div>
          <div class="font-mono text-cyan" style="font-size:16px;font-weight:700">${result.caseId}</div>
        </div>
        <div style="flex:1;min-width:200px">
          <div style="font-size:11px;color:var(--text-muted);letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Subject</div>
          <div style="font-size:14px;font-weight:600;color:var(--text-primary)">${result.subject}</div>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn btn-secondary btn-sm" onclick="app.navigateTo('analyze')">← New Analysis</button>
          <button class="btn btn-primary btn-sm" onclick="app.downloadReport()">📄 Download Report</button>
        </div>
      </div>

      <div class="results-layout">
        <!-- Left Sidebar -->
        <div class="results-sidebar">
          <!-- Threat Score -->
          <div class="card animate-in">
            <div class="card-header">
              <div class="card-title">🎯 Threat Score</div>
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
                  <div class="score-number" style="color:${scoreColor}" id="score-display">0</div>
                  <div class="score-label">/ 100</div>
                </div>
              </div>
              <div class="risk-badge" style="background:${scoreColor}20;color:${scoreColor};border:2px solid ${scoreColor}60">
                ${result.riskLevel}
              </div>
              <div class="score-meta">
                <div class="score-meta-item">
                  <div class="score-meta-label">Confidence</div>
                  <div class="score-meta-value">${result.confidence}</div>
                </div>
                <div class="score-meta-item">
                  <div class="score-meta-label">IOCs</div>
                  <div class="score-meta-value">${result.iocs.length}</div>
                </div>
              </div>
            </div>
          </div>

          <!-- Threat Type -->
          <div class="card animate-in animate-in-delay-1">
            <div class="card-body">
              <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Threat Classification</div>
              <div style="font-size:16px;font-weight:700;color:var(--text-primary);margin-bottom:8px">${result.threatType}</div>
              <div style="font-size:12px;color:var(--text-secondary)">AI Confidence: <span class="text-cyan font-mono">${result.confidence}</span></div>
            </div>
          </div>

          <!-- Auth Status -->
          <div class="card animate-in animate-in-delay-2">
            <div class="card-header"><div class="card-title">🛡️ Email Authentication</div></div>
            <div class="card-body">
              <div class="auth-grid">
                ${this._authCard('SPF', result.auth.spf)}
                ${this._authCard('DKIM', result.auth.dkim)}
                ${this._authCard('DMARC', result.auth.dmarc)}
              </div>
            </div>
          </div>

          <!-- Factor Breakdown -->
          <div class="card animate-in animate-in-delay-3">
            <div class="card-header"><div class="card-title">📊 Score Breakdown</div></div>
            <div class="card-body">
              <div class="factor-list">
                ${result.factors.filter(f => f.score > 0).map(f => {
                  const fc = f.severity === 'critical' ? '#ff2d55' : f.severity === 'high' ? '#ff6b35' : f.severity === 'medium' ? '#ffd60a' : '#34d399';
                  const pct = (f.score / 20) * 100;
                  return `<div class="factor-item" data-tooltip="${f.detail}">
                    <div class="factor-name">${f.name}</div>
                    <div class="factor-bar-wrap"><div class="factor-bar-fill" style="width:0%;background:${fc}" data-width="${pct}%"></div></div>
                    <div class="factor-score-val">+${f.score}</div>
                  </div>`;
                }).join('')}
              </div>
            </div>
          </div>
        </div>

        <!-- Right Main -->
        <div class="results-main animate-in">
          <div class="results-tabs">
            ${tabs.map((t, i) => `<div class="result-tab${i===0?' active':''}" data-tab="${t.id}" onclick="app.switchTab('${t.id}')">${t.label}</div>`).join('')}
          </div>

          <!-- Overview Tab -->
          <div class="tab-panel active" id="tab-overview">
            <!-- Sender Info -->
            <div class="card mb-16">
              <div class="card-header"><div class="card-title">👤 Sender Intelligence</div></div>
              <div class="card-body">
                <div class="grid-2">
                  ${[['From', result.sender.from],['To', result.recipient.to],['Reply-To', result.sender.replyTo],['Return-Path', result.sender.returnPath],['X-Originating-IP', result.sender.xOriginatingIP],['X-Mailer', result.sender.xMailer],['Date', result.date],['Message-ID', result.messageId]].map(([k,v]) =>
                    `<div style="padding:10px;background:var(--bg-input);border-radius:var(--radius-sm);border:1px solid var(--border)">
                      <div style="font-size:10px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">${k}</div>
                      <div class="font-mono" style="font-size:12px;color:var(--text-primary);word-break:break-all">${v}</div>
                    </div>`
                  ).join('')}
                </div>
              </div>
            </div>

            <!-- Key Findings -->
            <div class="card">
              <div class="card-header"><div class="card-title">🔍 Key Forensic Findings</div></div>
              <div class="card-body">
                ${result.keyFindings.length === 0 ? '<div class="empty-state" style="padding:20px"><div class="empty-icon">✅</div><div class="empty-title">No significant threats found</div></div>' :
                  result.keyFindings.map((f, i) => {
                    const icons = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };
                    return `<div class="finding-item animate-in" style="animation-delay:${i*0.06}s">
                      <div class="finding-icon">${icons[f.severity] || '⚪'}</div>
                      <div class="finding-body">
                        <div class="finding-title">${f.title}</div>
                        <div class="finding-detail">${f.detail}</div>
                      </div>
                      <div class="finding-severity"><span class="badge badge-${f.severity}">${f.severity}</span></div>
                    </div>`;
                  }).join('')}
              </div>
            </div>
          </div>

          <!-- Headers Tab -->
          <div class="tab-panel" id="tab-headers">
            <div class="card mb-16">
              <div class="card-header"><div class="card-title">🔗 Mail Server Hop Chain</div></div>
              <div class="card-body">
                ${result.hops.length === 0 ? '<div style="color:var(--text-muted);font-size:13px">No Received headers found</div>' :
                  `<div class="hop-chain">
                    ${result.hops.map((h, i) => {
                      const colors = ['#ff2d55','#ff6b35','#ffd60a','#34d399','#00d4ff'];
                      const c = colors[i % colors.length];
                      return `<div class="hop-item">
                        <div class="hop-num" style="color:${c};border-color:${c}40">${h.hop}</div>
                        <div class="hop-content">
                          <div class="hop-route">${h.from} → ${h.by}</div>
                          <div class="hop-detail">${h.ip ? `IP: ${h.ip}  ` : ''}${h.timestamp ? `Time: ${h.timestamp}` : ''}</div>
                        </div>
                        ${h.ip ? `<span class="badge badge-${this._ipRisk(h.ip)}">${h.ip}</span>` : ''}
                      </div>`;
                    }).join('')}
                  </div>`}
              </div>
            </div>
            <div class="card">
              <div class="card-header">
                <div class="card-title">📝 Raw Email Headers</div>
                <button class="btn btn-secondary btn-sm" onclick="navigator.clipboard.writeText(app.currentResult.rawHeaders);app.showToast('Headers copied!','success','📋')">Copy</button>
              </div>
              <div class="card-body" style="padding:0">
                <div class="raw-headers">${this._colorizeHeaders(result.rawHeaders)}</div>
              </div>
            </div>
          </div>

          <!-- Network Tab -->
          <div class="tab-panel" id="tab-network">
            <div class="card">
              <div class="card-header"><div class="card-title">🌍 IP Geolocation Analysis</div></div>
              <div class="card-body">
                ${result.geoResults.length === 0 ? '<div style="color:var(--text-muted)">No routable IPs extracted</div>' :
                  `<div class="geo-list">
                    ${result.geoResults.map(g => `
                      <div class="geo-item">
                        <div class="geo-flag">${g.flag || '🌐'}</div>
                        <div>
                          <div class="geo-ip">${g.ip}</div>
                          <div class="geo-location">${g.city || 'Unknown'}, ${g.country || 'Unknown'}</div>
                          <div class="geo-org">${g.asn || ''} • ${g.org || 'Unknown'}</div>
                        </div>
                        <div class="geo-right">
                          <span class="badge badge-${g.risk}">${(g.risk||'unknown').toUpperCase()}</span>
                          ${g.risk === 'critical' ? '<div style="font-size:10px;color:var(--critical);margin-top:4px">⚠ Known Threat</div>' : ''}
                        </div>
                      </div>
                    `).join('')}
                  </div>`}
              </div>
            </div>
          </div>

          <!-- URLs Tab -->
          <div class="tab-panel" id="tab-urls">
            <div class="card mb-16">
              <div class="card-header"><div class="card-title">🔗 Extracted URLs (${result.urls.length})</div></div>
              <div class="card-body">
                ${result.urls.length === 0 ? '<div style="color:var(--text-muted)">No URLs found</div>' :
                  result.urls.map(u => `
                    <div class="url-item">
                      <span>${u.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) ? '🔴' : '🟠'}</span>
                      <span class="url-text">${u}</span>
                      <span class="badge badge-${u.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) ? 'critical' : 'high'}">${u.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) ? 'IP URL' : 'External'}</span>
                    </div>
                  `).join('')}
              </div>
            </div>
            <div class="card">
              <div class="card-header"><div class="card-title">🔍 Domain Intelligence (${result.domainResults.filter(d => d.age_days !== null).length} analyzed)</div></div>
              <div class="card-body">
                ${result.domainResults.filter(d => d.age_days !== null || (d.categories && d.categories.length > 0)).map(d => `
                  <div class="domain-item">
                    <div class="domain-header">
                      <span class="domain-name">${d.domain}</span>
                      <span class="badge badge-${d.risk||'unknown'}">${(d.risk||'unknown').toUpperCase()}</span>
                      ${d.categories ? d.categories.map(c => `<span class="badge badge-medium" style="font-size:9px">${c}</span>`).join('') : ''}
                    </div>
                    <div class="domain-meta-grid">
                      <div><span class="dm-key">Registrar: </span><span class="dm-val">${d.registrar||'N/A'}</span></div>
                      <div><span class="dm-key">Age: </span><span class="dm-val">${d.age_days != null ? d.age_days+' days' : 'N/A'}</span></div>
                      <div><span class="dm-key">Created: </span><span class="dm-val">${d.created||'N/A'}</span></div>
                      <div><span class="dm-key">Similar To: </span><span class="dm-val">${d.similar_to||'—'}</span></div>
                      <div><span class="dm-key">VirusTotal: </span><span class="dm-val" style="color:var(--critical)">${d.virustotal_detections||'N/A'}</span></div>
                    </div>
                  </div>
                `).join('') || '<div style="color:var(--text-muted)">No domain intelligence available</div>'}
              </div>
            </div>
          </div>

          <!-- Attachments Tab -->
          <div class="tab-panel" id="tab-attachments">
            ${result.attachments.length === 0 ?
              '<div class="empty-state"><div class="empty-icon">📎</div><div class="empty-title">No Attachments Found</div><div class="empty-text">This email had no attachments</div></div>' :
              result.attachments.map(a => `
                <div class="attachment-item">
                  <div class="attach-header">
                    <div class="attach-icon">${a.ext === 'pdf' ? '📕' : ['docm','doc'].includes(a.ext) ? '📘' : '📄'}</div>
                    <div>
                      <div class="attach-name">${a.name}</div>
                      <div class="attach-meta">${a.type} • ${a.size}</div>
                    </div>
                    <div style="margin-left:auto;display:flex;flex-direction:column;align-items:flex-end;gap:6px">
                      <span class="badge badge-${a.risk}">${a.risk.toUpperCase()}</span>
                      ${a.malicious ? '<span class="badge badge-critical">⚠ POTENTIALLY MALICIOUS</span>' : ''}
                    </div>
                  </div>
                  <div class="attach-hashes">
                    <div class="hash-row"><div class="hash-label">MD5</div><div class="hash-value">${a.hash_md5}</div></div>
                    <div class="hash-row"><div class="hash-label">SHA-256</div><div class="hash-value">${a.hash_sha256}</div></div>
                  </div>
                </div>
              `).join('')}
          </div>

          <!-- AI Analysis Tab -->
          <div class="tab-panel" id="tab-ai">
            <div class="card mb-16">
              <div class="card-header"><div class="card-title">🤖 AI/ML Threat Assessment</div></div>
              <div class="card-body">
                ${result.mlFindings.map(f => {
                  const labelColors = { MALICIOUS: 'var(--critical)', SUSPICIOUS: 'var(--high)', LEGITIMATE: 'var(--low)', ANOMALY_DETECTED: 'var(--high)', CAMPAIGN_MATCH: 'var(--purple)', SOCIAL_ENGINEERING: 'var(--medium)', MALWARE_SIGNATURE: 'var(--critical)' };
                  const lc = labelColors[f.label] || 'var(--cyan)';
                  return `<div class="ml-finding">
                    <div class="ml-finding-header">
                      <span style="font-size:18px">${f.icon}</span>
                      <span class="ml-model-name">${f.model}</span>
                      <span class="ml-label" style="background:${lc}20;color:${lc}">${f.label}</span>
                      <span class="ml-confidence">${f.confidence}</span>
                    </div>
                    <div class="ml-finding-text">${f.finding}</div>
                  </div>`;
                }).join('')}
              </div>
            </div>
          </div>

          <!-- Graph Tab -->
          <div class="tab-panel" id="tab-graph">
            <div class="card">
              <div class="card-header">
                <div class="card-title">🕸️ Email Relationship Graph</div>
                <div style="font-size:12px;color:var(--text-muted)">Drag nodes to rearrange</div>
              </div>
              <div class="graph-container" id="threat-graph"></div>
            </div>
          </div>

          <!-- IOCs Tab -->
          <div class="tab-panel" id="tab-iocs">
            <div class="card">
              <div class="card-header">
                <div class="card-title">🚨 Indicators of Compromise (${result.iocs.length})</div>
                <button class="btn btn-secondary btn-sm" onclick="app.exportIOCs()">📤 Export IOCs</button>
              </div>
              <div class="card-body">
                ${result.iocs.length === 0 ? '<div class="empty-state" style="padding:20px"><div class="empty-icon">✅</div><div class="empty-title">No IOCs Found</div></div>' :
                  `<div class="ioc-list">
                    ${result.iocs.map(ioc => `
                      <div class="ioc-item">
                        <span class="ioc-type-badge badge badge-${ioc.risk}">${ioc.type}</span>
                        <span class="ioc-value">${ioc.value}${ioc.name ? ' ('+ioc.name+')' : ''}</span>
                        <span class="badge badge-${ioc.risk}">${ioc.risk.toUpperCase()}</span>
                        <span class="ioc-source">${ioc.source}</span>
                      </div>
                    `).join('')}
                  </div>`}
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
        const circumference = 2 * Math.PI * 70;
        const offset = circumference - (result.threatScore / 100) * circumference;
        ring.style.strokeDashoffset = offset;
      }
      if (display) {
        let current = 0;
        const target = result.threatScore;
        const step = () => { if (current < target) { current = Math.min(current + 2, target); display.textContent = current; requestAnimationFrame(step); } };
        requestAnimationFrame(step);
      }
      // Animate factor bars
      document.querySelectorAll('.factor-bar-fill').forEach(el => {
        setTimeout(() => { el.style.width = el.dataset.width; }, 100);
      });
    }, 100);
  }

  _authCard(protocol, result) {
    const colors = { pass: 'var(--low)', fail: 'var(--critical)', softfail: 'var(--medium)', none: 'var(--text-muted)', unknown: 'var(--text-muted)' };
    const icons = { pass: '✓', fail: '✗', softfail: '~', none: '?', unknown: '?' };
    const c = colors[result] || 'var(--text-muted)';
    const desc = { pass: 'Pass', fail: 'FAIL', softfail: 'Soft-Fail', none: 'None', unknown: 'Unknown' };
    return `<div class="auth-card" style="border-color:${c}40">
      <div class="auth-protocol">${protocol}</div>
      <div class="auth-result" style="color:${c}">${icons[result] || '?'}</div>
      <span class="badge badge-${result}">${desc[result] || result}</span>
    </div>`;
  }

  _ipRisk(ip) {
    const { GEO_DB, THREAT_INTEL_DB } = window.MAILFORENSICS_DATA;
    if (THREAT_INTEL_DB.maliciousIPs.includes(ip)) return 'critical';
    if (GEO_DB[ip]) return GEO_DB[ip].risk;
    return 'low';
  }

  _colorizeHeaders(raw) {
    return raw.replace(/^([A-Za-z0-9\-]+):/gm, '<span style="color:#00d4ff;font-weight:600">$1:</span>');
  }

  switchTab(tabId) {
    document.querySelectorAll('.result-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tabId));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === `tab-${tabId}`));

    if (tabId === 'graph' && this.currentResult) {
      setTimeout(() => {
        const graph = new window.ThreatGraph('threat-graph', this.currentResult);
        graph.build();
      }, 50);
    }
  }

  downloadReport() {
    if (!this.currentResult) { this.showToast('No analysis to export', 'error', '⚠️'); return; }
    const gen = new window.ForensicReportGenerator(this.currentResult);
    gen.download();
    this.showToast('Forensic report downloaded!', 'success', '📄');
  }

  exportIOCs() {
    if (!this.currentResult) return;
    const text = this.currentResult.iocs.map(ioc => `${ioc.type}|${ioc.value}|${ioc.risk}|${ioc.source}`).join('\n');
    const blob = new Blob([`# MailForensics IOC Export — ${this.currentResult.caseId}\n# Type|Value|Risk|Source\n${text}`], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `MF-IOCs-${this.currentResult.caseId}.txt`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
    this.showToast('IOCs exported!', 'success', '📤');
  }

  // ─── Investigations Page ──────────────────────────────────
  renderInvestigations() {
    const content = document.getElementById('page-content');
    content.innerHTML = `
      <div class="flex-center gap-12 mb-24" style="flex-wrap:wrap">
        <input type="search" placeholder="Search investigations..." style="width:280px" oninput="app.filterInvestigations(this.value)">
        <div style="display:flex;gap:8px;margin-left:auto">
          <select id="risk-filter" style="background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius-md);padding:8px 12px;color:var(--text-primary);font-size:13px;outline:none" onchange="app.filterInvestigations('')">
            <option value="">All Risks</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select id="status-filter" style="background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius-md);padding:8px 12px;color:var(--text-primary);font-size:13px;outline:none" onchange="app.filterInvestigations('')">
            <option value="">All Statuses</option>
            <option value="confirmed">Confirmed</option>
            <option value="review">Under Review</option>
            <option value="cleared">Cleared</option>
          </select>
        </div>
      </div>
      <div class="card animate-in">
        <div class="card-header">
          <div class="card-title">📁 All Investigations (${this.investigations.length})</div>
        </div>
        <div class="data-table-wrap" id="investigations-table-wrap">
          ${this._renderInvestigationsTable(this.investigations)}
        </div>
      </div>
    `;
  }

  filterInvestigations(query) {
    const riskFilter = document.getElementById('risk-filter')?.value || '';
    const statusFilter = document.getElementById('status-filter')?.value || '';
    const filtered = this.investigations.filter(i => {
      const matchQ = !query || i.email.includes(query) || i.subject.includes(query) || i.id.includes(query);
      const matchR = !riskFilter || i.risk === riskFilter;
      const matchS = !statusFilter || i.status === statusFilter;
      return matchQ && matchR && matchS;
    });
    const wrap = document.getElementById('investigations-table-wrap');
    if (wrap) wrap.innerHTML = this._renderInvestigationsTable(filtered);
  }

  openInvestigation(id) {
    this.showToast(`Loading case ${id}...`, 'info', '📁');
  }

  // ─── Threat Intel Page ────────────────────────────────────
  renderThreatIntel() {
    const content = document.getElementById('page-content');
    const { THREAT_INTEL_DB, GEO_DB, DOMAIN_INTEL } = window.MAILFORENSICS_DATA;
    content.innerHTML = `
      <div class="ti-grid animate-in">
        <div class="ti-card">
          <div class="ti-card-title">🔴 Malicious IPs (${THREAT_INTEL_DB.maliciousIPs.length})</div>
          <div class="ti-ioc-list">
            ${THREAT_INTEL_DB.maliciousIPs.map(ip => {
              const geo = GEO_DB[ip];
              return `<div class="ti-ioc-row">
                <span class="badge badge-critical">IP</span>
                <span style="flex:1">${ip}</span>
                <span style="font-size:10px;color:var(--text-muted)">${geo ? geo.flag+' '+geo.country : ''}</span>
              </div>`;
            }).join('')}
          </div>
        </div>
        <div class="ti-card">
          <div class="ti-card-title">🌐 Malicious Domains (${THREAT_INTEL_DB.maliciousDomains.length})</div>
          <div class="ti-ioc-list">
            ${THREAT_INTEL_DB.maliciousDomains.map(d => {
              const info = DOMAIN_INTEL[d];
              return `<div class="ti-ioc-row">
                <span class="badge badge-critical">Domain</span>
                <span style="flex:1">${d}</span>
                <span style="font-size:10px;color:var(--text-muted)">${info ? info.age_days+'d' : ''}</span>
              </div>`;
            }).join('')}
          </div>
        </div>
        <div class="ti-card">
          <div class="ti-card-title">⚠️ Suspicious Patterns (${THREAT_INTEL_DB.suspiciousPatterns.length})</div>
          <div class="ti-ioc-list">
            ${THREAT_INTEL_DB.suspiciousPatterns.map(p => `
              <div class="ti-ioc-row">
                <span class="badge badge-high">Pattern</span>
                <span style="flex:1">"${p}"</span>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
      <div class="card animate-in animate-in-delay-1">
        <div class="card-header"><div class="card-title">📡 Active Threat Intelligence Feeds</div></div>
        <div class="data-table-wrap">
          <table class="data-table">
            <thead><tr><th>Feed Name</th><th>Provider</th><th>Last Updated</th><th>IOCs</th><th>Status</th></tr></thead>
            <tbody>
              ${[
                ['PhishTank Database','OpenPhish','2026-09-03 20:00','12,847','active'],
                ['MISP Threat Sharing','MailForensics Network','2026-09-03 19:30','8,234','active'],
                ['AlienVault OTX','AT&T Cybersecurity','2026-09-03 18:00','45,621','active'],
                ['CERT-In Advisory','Govt. of India','2026-09-03 12:00','1,205','active'],
                ['NCIIPC Indicators','NCIIPC India','2026-09-02 22:00','654','active'],
                ['Emerging Threats','ProofPoint','2026-09-03 20:45','28,190','active'],
              ].map(([name,provider,updated,iocs,status]) => `
                <tr>
                  <td style="font-weight:600">${name}</td>
                  <td style="color:var(--text-secondary)">${provider}</td>
                  <td class="mono" style="font-size:11px;color:var(--text-muted)">${updated}</td>
                  <td class="mono text-cyan">${iocs}</td>
                  <td><span class="badge badge-pass">● ${status.toUpperCase()}</span></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  // ─── Indicators Page ──────────────────────────────────────
  renderIndicators() {
    const content = document.getElementById('page-content');
    const allIocs = this.investigations.reduce((acc, inv) => {
      const types = ['IP', 'Domain', 'URL', 'File Hash', 'Email'];
      const risks = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' };
      if (inv.risk !== 'low') {
        acc.push({ type: types[Math.floor(Math.random() * 3)], value: inv.email, risk: risks[inv.risk] || 'medium', date: inv.date, case: inv.id, source: 'MailForensics Analysis' });
      }
      return acc;
    }, []);

    content.innerHTML = `
      <div class="stats-grid mb-24" style="grid-template-columns:repeat(4,1fr)">
        ${[['Total IOCs','47','var(--cyan)','🚩'],['Critical','18','var(--critical)','🔴'],['IPs','12','var(--purple)','🌐'],['Domains','15','var(--high)','🔗']].map(([l,v,c,i]) =>
          `<div class="stat-card" style="--accent-color:${c}"><div class="stat-icon">${i}</div><div class="stat-value" style="color:${c}">${v}</div><div class="stat-label">${l}</div></div>`
        ).join('')}
      </div>
      <div class="card animate-in">
        <div class="card-header">
          <div class="card-title">🚨 All Indicators of Compromise</div>
          <button class="btn btn-secondary btn-sm">📤 Export All</button>
        </div>
        <div class="data-table-wrap">
          <table class="data-table">
            <thead><tr><th>Type</th><th>Indicator</th><th>Risk</th><th>Source</th><th>Case</th><th>Date</th></tr></thead>
            <tbody>
              ${allIocs.map(ioc => `
                <tr>
                  <td><span class="badge badge-${ioc.risk}">${ioc.type}</span></td>
                  <td class="mono" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${ioc.value}</td>
                  <td><span class="badge badge-${ioc.risk}">${ioc.risk.toUpperCase()}</span></td>
                  <td style="font-size:12px;color:var(--text-secondary)">${ioc.source}</td>
                  <td class="case-id-cell">${ioc.case}</td>
                  <td class="mono" style="font-size:11px;color:var(--text-muted)">${ioc.date}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  // ─── Reports Page ─────────────────────────────────────────
  renderReports() {
    const content = document.getElementById('page-content');
    content.innerHTML = `
      <div class="card animate-in">
        <div class="card-header">
          <div class="card-title">📋 Generated Forensic Reports</div>
          ${this.currentResult ? `<button class="btn btn-primary btn-sm" onclick="app.downloadReport()">📄 Generate Latest Report</button>` : ''}
        </div>
        <div class="data-table-wrap">
          <table class="data-table">
            <thead><tr><th>Report ID</th><th>Case</th><th>Threat Type</th><th>Risk</th><th>Score</th><th>Generated</th><th>Actions</th></tr></thead>
            <tbody>
              ${this.investigations.slice(0,5).map(inv => `
                <tr>
                  <td class="case-id-cell">RPT-${inv.id.split('-')[2]}</td>
                  <td class="font-mono" style="font-size:12px">${inv.id}</td>
                  <td style="font-size:12px;color:var(--text-secondary)">${inv.type}</td>
                  <td><span class="badge badge-${inv.risk}">${inv.risk.toUpperCase()}</span></td>
                  <td class="score-cell text-${inv.score >= 80 ? 'critical' : inv.score >= 60 ? 'high' : 'medium'}">${inv.score}</td>
                  <td class="mono" style="font-size:11px;color:var(--text-muted)">${inv.date}</td>
                  <td>
                    <div style="display:flex;gap:6px">
                      <button class="btn btn-secondary btn-sm" onclick="app.showToast('Report opened','info','📋')">View</button>
                      <button class="btn btn-secondary btn-sm" onclick="app.showToast('Downloading...','success','⬇️')">⬇</button>
                    </div>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
        ${!this.currentResult ? `<div class="empty-state" style="padding:40px"><div class="empty-icon">📋</div><div class="empty-title">Run an Analysis First</div><div class="empty-text">Reports are generated after email analysis. <a href="#" onclick="app.navigateTo('analyze')" style="color:var(--cyan)">Analyze an email</a> to generate a report.</div></div>` : ''}
      </div>
    `;
  }

  // ─── Settings Page ────────────────────────────────────────
  renderSettings() {
    const content = document.getElementById('page-content');
    const toggle = (id) => { const el = document.getElementById(id); if (el) el.classList.toggle('on'); };
    content.innerHTML = `
      <div class="grid-2 animate-in">
        <div class="card">
          <div class="card-body">
            <div class="settings-title">🔍 Analysis Settings</div>
            <div class="settings-section">
              ${[['Auto-analyze on upload','Automatically start analysis when a file is uploaded','s1',true],['NLP threat detection','Use natural language processing for body analysis','s2',true],['IP Geolocation','Look up geolocation data for all extracted IPs','s3',true],['Domain intelligence','Check domain registration and reputation','s4',true],['Attachment scanning','Analyze attachment metadata and file hashes','s5',true]].map(([l,d,id,on]) => `
                <div class="setting-row">
                  <div><div class="setting-label">${l}</div><div class="setting-desc">${d}</div></div>
                  <div class="toggle ${on ? 'on' : ''}" id="${id}" onclick="this.classList.toggle('on')"></div>
                </div>
              `).join('')}
            </div>
          </div>
        </div>
        <div class="card">
          <div class="card-body">
            <div class="settings-title">🚨 Alert & Notification Settings</div>
            <div class="settings-section">
              ${[['Critical threat alerts','Show notifications for critical threats','s6',true],['New IOC notifications','Alert when new IOCs are extracted','s7',true],['Report auto-generation','Auto-generate PDF report after analysis','s8',false],['Email alerts','Send email alerts to SOC team','s9',false]].map(([l,d,id,on]) => `
                <div class="setting-row">
                  <div><div class="setting-label">${l}</div><div class="setting-desc">${d}</div></div>
                  <div class="toggle ${on ? 'on' : ''}" id="${id}" onclick="this.classList.toggle('on')"></div>
                </div>
              `).join('')}
            </div>
            <div class="settings-title mt-16" style="margin-top:24px">📡 Threat Intelligence Feeds</div>
            <div class="settings-section">
              ${[['PhishTank','s10',true],['AlienVault OTX','s11',true],['CERT-In Advisory','s12',true],['NCIIPC Indicators','s13',true]].map(([l,id,on]) => `
                <div class="setting-row">
                  <div><div class="setting-label">${l}</div></div>
                  <div class="toggle ${on ? 'on' : ''}" id="${id}" onclick="this.classList.toggle('on')"></div>
                </div>
              `).join('')}
            </div>
          </div>
        </div>
      </div>
      <div class="card mt-16 animate-in animate-in-delay-1" style="margin-top:16px">
        <div class="card-body">
          <div class="settings-title">🏛️ About MailForensics</div>
          <div class="grid-2">
            ${[['Platform','MailForensics — Advanced Email Forensics & Intelligence System'],['Version','v2.6.0 (SIH 2026)'],['Problem Statement','SIH26106'],['Organization','AICTE'],['AI Engine','MailForensics Forensics Engine v2.6'],['Analysis Modules','Header Forensics, NLP, GeoIP, Domain Intel, Attachment Analysis']].map(([k,v]) =>
              `<div style="padding:10px;background:var(--bg-input);border-radius:var(--radius-sm);border:1px solid var(--border)">
                <div style="font-size:10px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">${k}</div>
                <div style="font-size:12px;color:var(--text-primary)">${v}</div>
              </div>`
            ).join('')}
          </div>
        </div>
      </div>
    `;
  }
}

// Bootstrap
document.addEventListener('DOMContentLoaded', () => {
  window.app = new MailForensicsApp();
  window.app.init();
});
