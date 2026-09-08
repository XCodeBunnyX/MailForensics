// ============================================================
// GmailGuard — Forensic Report Generator
// Problem Statement: SIH26106
// Binds strictly against ThreatReportNormalizer view model
// Enforces observational taxonomy and forensic integrity
// ============================================================

class ForensicReportGenerator {
  constructor(result) {
    this.result = result;
    this.generatedAt = new Date().toLocaleString('en-IN', {
      timeZone: 'Asia/Kolkata',
      dateStyle: 'full',
      timeStyle: 'medium'
    });
  }

  generateHTML() {
    const r = this.result;
    const severityColors = {
      critical: '#ff2d55',
      high: '#ff6b35',
      medium: '#ffd60a',
      low: '#34d399'
    };
    const color = severityColors[r.severity] || '#00d4ff';

    const escapeHtml = (str) => {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    };

    const getAuthBadge = (status) => {
      const s = (status || 'UNKNOWN').toUpperCase();
      if (s === 'PASS') return '<span class="badge badge-pass">PASS</span>';
      if (s === 'FAIL' || s === 'PERMERROR') return '<span class="badge badge-fail">FAIL</span>';
      if (s === 'SOFTFAIL' || s === 'NEUTRAL') return '<span class="badge badge-medium">SOFTFAIL</span>';
      return `<span class="badge badge-unknown">${s}</span>`;
    };

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GmailGuard Forensic Investigation Report — ${escapeHtml(r.caseId)}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Inter', -apple-system, sans-serif; background: #060b16; color: #e2e8f0; line-height: 1.6; }
  .report { max-width: 960px; margin: 0 auto; padding: 40px 30px; }
  .header { text-align: center; border-bottom: 2px solid #1e293b; padding-bottom: 28px; margin-bottom: 28px; }
  .logo { font-size: 28px; font-weight: 800; color: #00d4ff; letter-spacing: 4px; display: inline-flex; align-items: center; gap: 8px; }
  .logo-sub { font-size: 11px; color: #64748b; letter-spacing: 2px; text-transform: uppercase; margin-top: 4px; }
  .report-title { font-size: 18px; color: #94a3b8; margin-top: 14px; font-weight: 600; }
  .case-id { font-family: 'JetBrains Mono', monospace; color: #00d4ff; font-size: 14px; margin-top: 6px; }
  .meta { display: flex; justify-content: center; gap: 30px; margin-top: 16px; font-size: 12px; color: #64748b; flex-wrap: wrap; }
  .section { margin-bottom: 28px; background: #0d1527; border: 1px solid #1e293b; border-radius: 8px; padding: 20px; }
  .section-title { font-size: 13px; font-weight: 700; color: #00d4ff; text-transform: uppercase; letter-spacing: 2px; border-left: 3px solid #00d4ff; padding-left: 10px; margin-bottom: 16px; display: flex; align-items: center; justify-content: space-between; }
  .verdict-box { background: ${color}12; border: 2px solid ${color}; border-radius: 12px; padding: 24px; text-align: center; margin-bottom: 28px; }
  .score-big { font-size: 68px; font-weight: 800; color: ${color}; line-height: 1; }
  .risk-label { font-size: 22px; font-weight: 800; color: ${color}; letter-spacing: 3px; margin-top: 8px; text-transform: uppercase; }
  .verdict-meta { display: flex; justify-content: center; gap: 32px; margin-top: 16px; flex-wrap: wrap; }
  .verdict-item { text-align: center; }
  .verdict-item-label { font-size: 10px; color: #64748b; text-transform: uppercase; letter-spacing: 1px; }
  .verdict-item-value { font-size: 14px; font-weight: 600; color: #e2e8f0; margin-top: 3px; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 8px; }
  th { background: #080e1c; color: #64748b; font-weight: 600; text-transform: uppercase; font-size: 10px; letter-spacing: 1px; padding: 10px 12px; text-align: left; border-bottom: 1px solid #1e293b; }
  td { padding: 10px 12px; border-bottom: 1px solid #1e293b; vertical-align: top; font-family: 'JetBrains Mono', monospace; font-size: 11px; }
  tr:last-child td { border-bottom: none; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; font-family: 'Inter', sans-serif; }
  .badge-critical { background: #ff2d5520; color: #ff2d55; border: 1px solid #ff2d5550; }
  .badge-high { background: #ff6b3520; color: #ff6b35; border: 1px solid #ff6b3550; }
  .badge-medium { background: #ffd60a20; color: #ffd60a; border: 1px solid #ffd60a50; }
  .badge-low { background: #34d39920; color: #34d399; border: 1px solid #34d39950; }
  .badge-pass { background: #34d39925; color: #34d399; border: 1px solid #34d39960; }
  .badge-fail { background: #ff2d5525; color: #ff2d55; border: 1px solid #ff2d5560; }
  .badge-unknown { background: #64748b20; color: #94a3b8; border: 1px solid #64748b40; }
  .badge-tier1 { background: #34d39920; color: #34d399; border: 1px solid #34d39940; }
  .badge-tier2 { background: #00d4ff20; color: #00d4ff; border: 1px solid #00d4ff40; }
  .badge-tier3 { background: #ffd60a20; color: #ffd60a; border: 1px solid #ffd60a40; }
  .badge-tier4 { background: #ff6b3520; color: #ff6b35; border: 1px solid #ff6b3540; }
  .finding-item { padding: 12px 14px; background: #080e1c; border-radius: 6px; margin-bottom: 10px; border-left: 3px solid; }
  .finding-title { font-weight: 600; font-size: 13px; font-family: 'Inter', sans-serif; }
  .finding-detail { font-size: 12px; color: #94a3b8; margin-top: 4px; font-family: 'Inter', sans-serif; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
  .info-card { background: #080e1c; border-radius: 6px; padding: 12px; border: 1px solid #1e293b; }
  .info-label { font-size: 10px; color: #64748b; text-transform: uppercase; letter-spacing: 1px; }
  .info-value { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #e2e8f0; margin-top: 4px; word-break: break-all; }
  .scope-box { background: #080e1c; border-left: 4px solid #00d4ff; padding: 14px 18px; border-radius: 6px; margin-bottom: 24px; font-size: 12px; color: #94a3b8; line-height: 1.5; }
  pre { font-family: 'JetBrains Mono', monospace; font-size: 10px; background: #080e1c; padding: 16px; border-radius: 6px; overflow-x: auto; color: #94a3b8; white-space: pre-wrap; word-break: break-all; max-height: 400px; border: 1px solid #1e293b; }
  .footer { text-align: center; padding-top: 28px; border-top: 1px solid #1e293b; color: #64748b; font-size: 11px; margin-top: 30px; }
  @media print {
    body { background: #fff; color: #000; }
    .section, .info-card, .finding-item, pre, .scope-box { background: #fff !important; border-color: #ccc !important; color: #000 !important; }
    .logo, .section-title, .case-id { color: #000 !important; }
    th { background: #eee !important; color: #000 !important; }
    td { color: #000 !important; }
    .badge { border: 1px solid #000 !important; }
  }
</style>
</head>
<body>
<div class="report">
  <!-- Header -->
  <div class="header">
    <div class="logo">⬡ GmailGuard</div>
    <div class="logo-sub">AI-Powered Email Threat Detection, GeoLocation, and Forensic Intelligence Platform</div>
    <div class="report-title">Digital Forensic Investigation Report</div>
    <div class="case-id">Case ID: ${escapeHtml(r.caseId)}</div>
    <div class="meta">
      <span>📅 Generated: ${this.generatedAt}</span>
      <span>🔒 Classification: SOC RESTRICTED</span>
      <span>⚡ Engine: FastAPI Forensics v2.6</span>
      <span>🎯 Problem Statement: SIH26106</span>
    </div>
  </div>

  <!-- Observational Taxonomy Scope Disclaimer -->
  <div class="scope-box">
    <strong style="color:#00d4ff;text-transform:uppercase;letter-spacing:1px;display:block;margin-bottom:4px;">⚖️ Forensic Scope & Observational Taxonomy</strong>
    ${escapeHtml(r.forensicScope || 'Physical attribution is outside the scope of email-header analysis and may require additional evidence and lawful investigative processes. Observable infrastructure metrics represent transit routing points, not verified physical sender coordinates.')}
  </div>

  <!-- Threat Assessment -->
  <div class="verdict-box">
    <div class="score-big">${r.threatScore}</div>
    <div style="font-size:12px;color:#64748b;margin-top:4px;letter-spacing:1px;text-transform:uppercase">Correlated Threat Score / 100</div>
    <div class="risk-label">${escapeHtml(r.verdict)}</div>
    <div class="verdict-meta">
      <div class="verdict-item">
        <div class="verdict-item-label">ML Hyperplane Decision</div>
        <div class="verdict-item-value">${r.ml?.decisionScore != null ? (r.ml.decisionScore > 0 ? '+' : '') + r.ml.decisionScore.toFixed(3) : 'Model Available'}</div>
      </div>
      <div class="verdict-item">
        <div class="verdict-item-label">Observable IPs</div>
        <div class="verdict-item-value">${r.geolocation?.length || 0} Nodes</div>
      </div>
      <div class="verdict-item">
        <div class="verdict-item-label">Extracted URLs</div>
        <div class="verdict-item-value">${r.urls?.length || 0} URLs</div>
      </div>
      <div class="verdict-item">
        <div class="verdict-item-label">Date Evaluated</div>
        <div class="verdict-item-value">${escapeHtml(r.email?.date || 'N/A')}</div>
      </div>
    </div>
  </div>

  <!-- Why was this email classified this way? -->
  <div class="section">
    <div class="section-title">
      <span>🔍 Why Was This Email Classified This Way? (Evidence Findings: ${r.evidence?.length || 0})</span>
    </div>
    <div style="font-size:12px;color:#94a3b8;margin-bottom:14px;">
      GmailGuard correlates multiple independent forensic signals across email envelope, infrastructure, URLs, and linguistic models. No single indicator alone dictates maliciousness.
    </div>
    ${(r.evidence && r.evidence.length > 0) ? r.evidence.map(e => {
      const impColor = (e.impact || 0) >= 20 ? '#ff2d55' : (e.impact || 0) >= 10 ? '#ff6b35' : '#ffd60a';
      return `
        <div class="finding-item" style="border-color:${impColor}">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <div class="finding-title" style="color:#e2e8f0">${escapeHtml(e.signal)}</div>
            <span class="badge" style="background:${impColor}20;color:${impColor};border:1px solid ${impColor}50">+${e.impact || 0} pts</span>
          </div>
          <div class="finding-detail">${escapeHtml(e.explanation)}</div>
        </div>
      `;
    }).join('') : '<div style="font-size:12px;color:#64748b">No adverse risk signals identified.</div>'}
  </div>

  <!-- Mitigating / Positive Signals -->
  ${(r.positiveEvidence && r.positiveEvidence.length > 0) ? `
  <div class="section">
    <div class="section-title" style="color:#34d399;border-color:#34d399;">
      <span>🛡️ Mitigating & Positive Indicators (${r.positiveEvidence.length})</span>
    </div>
    <table>
      <thead>
        <tr><th>Signal</th><th>Explanation</th><th>Risk Adjustment</th></tr>
      </thead>
      <tbody>
        ${r.positiveEvidence.map(p => `
          <tr>
            <td style="color:#34d399;font-weight:600">${escapeHtml(p.signal)}</td>
            <td style="font-family:'Inter',sans-serif">${escapeHtml(p.explanation)}</td>
            <td style="color:#34d399">${p.impact ? '-' + Math.abs(p.impact) + ' pts' : 'Mitigating Factor'}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  </div>` : ''}

  <!-- Email Envelope Metadata -->
  <div class="section">
    <div class="section-title"><span>📧 Email Envelope Metadata</span></div>
    <div class="grid-2">
      <div class="info-card"><div class="info-label">From</div><div class="info-value">${escapeHtml(r.email?.from || 'Not available')}</div></div>
      <div class="info-card"><div class="info-label">To</div><div class="info-value">${escapeHtml(r.email?.to || 'Not available')}</div></div>
      <div class="info-card"><div class="info-label">Subject</div><div class="info-value">${escapeHtml(r.email?.subject || 'Not available')}</div></div>
      <div class="info-card"><div class="info-label">Date</div><div class="info-value">${escapeHtml(r.email?.date || 'Not available')}</div></div>
      <div class="info-card"><div class="info-label">Sender Domain</div><div class="info-value">${escapeHtml(r.email?.senderDomain || 'Not available')}</div></div>
      <div class="info-card"><div class="info-label">Reply-To</div><div class="info-value">${escapeHtml(r.email?.replyTo || 'Not available')} ${r.email?.replyToDiffers ? '<span class="badge badge-fail" style="margin-left:6px">Differs from From</span>' : ''}</div></div>
      <div class="info-card"><div class="info-label">Return-Path</div><div class="info-value">${escapeHtml(r.email?.returnPath || 'Not available')}</div></div>
      <div class="info-card"><div class="info-label">Message-ID</div><div class="info-value">${escapeHtml(r.email?.messageId || 'Not available')}</div></div>
    </div>
    <!-- Sender IP Observability Card -->
    <div class="info-card" style="margin-top:12px;border-left:3px solid ${r.senderIp?.isObservable ? '#ffd60a' : '#00d4ff'}">
      <div class="info-label">Sender Originating Device IP Observability</div>
      <div class="info-value" style="color:${r.senderIp?.isObservable ? '#ffd60a' : '#00d4ff'};font-weight:700">
        ${escapeHtml(r.senderIp?.value || 'Not Observable')}
      </div>
      <div style="font-size:11px;color:#94a3b8;margin-top:4px;font-family:'Inter',sans-serif">
        ${escapeHtml(r.senderIp?.reason || 'The available email headers do not expose the sender’s originating device IP.')}
      </div>
    </div>
  </div>

  <!-- Email Authentication -->
  <div class="section">
    <div class="section-title"><span>🛡️ Email Authentication Analysis</span></div>
    <table>
      <thead>
        <tr><th>Protocol</th><th>Status</th><th>Technical Details</th></tr>
      </thead>
      <tbody>
        <tr>
          <td style="font-weight:700">SPF</td>
          <td>${getAuthBadge(r.authentication?.spf)}</td>
          <td style="font-family:'Inter',sans-serif">${escapeHtml(r.authentication?.spfDetail || 'Sender Policy Framework verification.')}</td>
        </tr>
        <tr>
          <td style="font-weight:700">DKIM</td>
          <td>${getAuthBadge(r.authentication?.dkim)}</td>
          <td style="font-family:'Inter',sans-serif">${escapeHtml(r.authentication?.dkimDetail || 'DomainKeys Identified Mail cryptographic signature.')}</td>
        </tr>
        <tr>
          <td style="font-weight:700">DMARC</td>
          <td>${getAuthBadge(r.authentication?.dmarc)}</td>
          <td style="font-family:'Inter',sans-serif">${escapeHtml(r.authentication?.dmarcDetail || 'Domain-based Message Authentication alignment policy.')}</td>
        </tr>
      </tbody>
    </table>
    <div style="background:#080e1c;border-radius:4px;padding:10px 14px;margin-top:12px;font-size:11px;color:#ffd60a;border:1px solid #ffd60a30;font-family:'Inter',sans-serif;">
      ⚠️ <strong>Forensic Caveat:</strong> ${escapeHtml(r.authentication?.caveat || 'Authentication PASS confirms domain alignment and transmission integrity; it does NOT verify sender intent.')}
    </div>
  </div>

  <!-- Candidate Relays (4-Tier Taxonomy) -->
  ${(r.candidateRelays && r.candidateRelays.length > 0) ? `
  <div class="section">
    <div class="section-title"><span>🎯 Candidate Mail Relays (4-Tier Forensic Taxonomy)</span></div>
    <table>
      <thead>
        <tr><th>Tier</th><th>Provenance</th><th>Relay IP</th><th>Provider</th><th>Confidence</th><th>Evidence Class</th><th>Trust Rationale</th></tr>
      </thead>
      <tbody>
        ${r.candidateRelays.map(c => `
          <tr>
            <td><span class="badge badge-tier${c.tier || 1}">Tier ${c.tier}</span></td>
            <td><span class="badge badge-unknown">${escapeHtml(c.tierName)}</span></td>
            <td><strong>${escapeHtml(c.ip)}</strong></td>
            <td>${escapeHtml(c.provider)}</td>
            <td><span class="badge badge-${c.confidence === 'high' ? 'pass' : c.confidence === 'medium' ? 'medium' : 'low'}">${(c.confidence || 'medium').toUpperCase()}</span></td>
            <td><code>${escapeHtml(c.evidenceClass)}</code></td>
            <td style="font-family:'Inter',sans-serif;font-size:10px;color:#94a3b8">${escapeHtml(c.rankingDisclaimer)}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  </div>` : ''}

  <!-- Mail Hop Timeline & Clock Skew -->
  ${(r.timelineAnalysis && r.timelineAnalysis.hopDiffs && r.timelineAnalysis.hopDiffs.length > 0) ? `
  <div class="section">
    <div class="section-title"><span>⏱️ Mail Server Hop Timeline & Clock Skew Analysis</span></div>
    <table>
      <thead>
        <tr><th>Transition</th><th>Hop Delay</th><th>Normal Tolerance (±120s)</th><th>Anomaly Note</th></tr>
      </thead>
      <tbody>
        ${r.timelineAnalysis.hopDiffs.map(d => `
          <tr>
            <td>Hop ${d.fromHop} → Hop ${d.toHop}</td>
            <td><strong>${d.deltaSeconds}s</strong></td>
            <td><span class="badge badge-${d.withinTolerance ? 'pass' : 'fail'}">${d.withinTolerance ? 'NORMAL' : 'CLOCK SKEW'}</span></td>
            <td style="color:${d.anomaly ? '#ff2d55' : '#34d399'};font-family:'Inter',sans-serif">${escapeHtml(d.anomaly || 'Timing consistent across MTAs')}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  </div>` : ''}

  <!-- Observable Mail Infrastructure Geolocation -->
  ${(r.geolocation && r.geolocation.length > 0) ? `
  <div class="section">
    <div class="section-title"><span>🌍 Observable Mail Infrastructure Geolocation</span></div>
    <table>
      <thead>
        <tr><th>Observable Transit IP</th><th>Location</th><th>ASN / ISP</th><th>Timezone</th><th>Forensic Context</th></tr>
      </thead>
      <tbody>
        ${r.geolocation.map(g => `
          <tr>
            <td><strong>${escapeHtml(g.ip)}</strong></td>
            <td>${g.flag || '🌐'} ${escapeHtml(g.city)}, ${escapeHtml(g.country)}</td>
            <td>${escapeHtml(g.asn)} • ${escapeHtml(g.isp || g.org)}</td>
            <td>${escapeHtml(g.timezone)}</td>
            <td style="font-family:'Inter',sans-serif;font-size:10px;color:#94a3b8">${escapeHtml(g.forensicNote)}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  </div>` : ''}

  <!-- Domain Intelligence -->
  <div class="section">
    <div class="section-title"><span>🔍 Domain Intelligence</span></div>
    <div class="grid-2">
      <div class="info-card"><div class="info-label">Domain Name</div><div class="info-value">${escapeHtml(r.domain?.domain || 'Not available')}</div></div>
      <div class="info-card"><div class="info-label">Domain Age</div><div class="info-value">${r.domain?.ageDays != null ? r.domain.ageDays + ' days' : 'Not available'} ${r.domain?.ageDays != null && r.domain.ageDays < 30 ? '<span class="badge badge-fail" style="margin-left:6px">Newly Registered</span>' : ''}</div></div>
      <div class="info-card"><div class="info-label">Registrar</div><div class="info-value">${escapeHtml(r.domain?.registrar || 'Not available')}</div></div>
      <div class="info-card"><div class="info-label">Typosquatting Target</div><div class="info-value">${r.domain?.isTyposquat ? '<span class="badge badge-fail">TYPOSQUAT TARGET: ' + escapeHtml(r.domain.typosquatTarget) + '</span>' : 'None detected'}</div></div>
    </div>
  </div>

  <!-- URL Intelligence -->
  ${(r.urls && r.urls.length > 0) ? `
  <div class="section">
    <div class="section-title"><span>🔗 URL Intelligence & PhishTank Verification (${r.urls.length})</span></div>
    <table>
      <thead>
        <tr><th>Extracted URL</th><th>Domain</th><th>Threat Status</th><th>Verification</th></tr>
      </thead>
      <tbody>
        ${r.urls.map(u => `
          <tr>
            <td style="word-break:break-all;max-width:380px;">${escapeHtml(u.url)}</td>
            <td>${escapeHtml(u.domain)}</td>
            <td>
              ${u.isPhishTankVerified ? '<span class="badge badge-critical">VERIFIED PHISH</span>' : u.isIpUrl ? '<span class="badge badge-critical">IP-BASED URL</span>' : u.riskScore >= 40 ? '<span class="badge badge-high">SUSPICIOUS</span>' : '<span class="badge badge-low">ANALYZED</span>'}
            </td>
            <td style="font-family:'Inter',sans-serif;font-size:10px;color:#94a3b8">
              ${u.isPhishTankVerified ? 'PhishTank ID #' + escapeHtml(u.phishTankId) + ' (Target: ' + escapeHtml(u.phishTankTarget) + ')' : (u.reasons || []).join('; ') || 'Heuristic check'}
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  </div>` : ''}

  <!-- Attachment Analysis -->
  <div class="section">
    <div class="section-title"><span>📎 Attachment Analysis</span></div>
    <div style="font-size:11px;color:#00d4ff;margin-bottom:12px;font-family:'Inter',sans-serif">
      ℹ️ Files are analyzed statically. Suspicious files are NOT executed.
    </div>
    ${(r.attachments && r.attachments.length > 0) ? `
    <table>
      <thead>
        <tr><th>Filename</th><th>Size</th><th>Type</th><th>Risk Assessment</th><th>Static Findings</th></tr>
      </thead>
      <tbody>
        ${r.attachments.map(a => `
          <tr>
            <td><strong>${escapeHtml(a.filename)}</strong></td>
            <td>${a.sizeMb} MB</td>
            <td>${escapeHtml(a.contentType)}</td>
            <td>
              <span class="badge badge-${a.riskScore >= 60 ? 'critical' : a.riskScore >= 30 ? 'high' : 'low'}">
                ${a.riskScore >= 60 ? 'DANGEROUS' : a.riskScore >= 30 ? 'SUSPICIOUS' : 'LOW RISK'}
              </span>
            </td>
            <td style="font-family:'Inter',sans-serif;font-size:10px;color:#94a3b8">${(a.reasons || []).join('; ') || 'No static anomalies'}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>` : '<div style="font-size:12px;color:#64748b">No attachments detected in email.</div>'}
  </div>

  <!-- AI Content Analysis -->
  <div class="section">
    <div class="section-title"><span>🤖 AI Content Analysis (Linear Support Vector Machine)</span></div>
    <div class="grid-2">
      <div class="info-card">
        <div class="info-label">Classifier Verdict</div>
        <div class="info-value" style="color:${r.ml?.isMalicious ? '#ff2d55' : '#34d399'};font-weight:700">
          ${r.ml?.prediction === 1 ? 'PHISHING LURE DETECTED' : r.ml?.prediction === 0 ? 'LEGITIMATE CONTENT PATTERN' : 'MODEL NOT EVALUATED'}
        </div>
      </div>
      <div class="info-card">
        <div class="info-label">SVM Hyperplane Distance Score</div>
        <div class="info-value" style="color:#00d4ff;font-weight:700">
          ${r.ml?.decisionScore != null ? (r.ml.decisionScore > 0 ? '+' : '') + r.ml.decisionScore.toFixed(3) : 'Not available'}
        </div>
      </div>
    </div>
    <div style="font-size:11px;color:#94a3b8;margin-top:10px;font-family:'Inter',sans-serif">
      ${escapeHtml(r.ml?.note || 'Linear SVM decision score evaluates distance from the decision boundary. Positive values indicate phishing patterns; negative values indicate normal content.')}
      The ML model serves as one component within GmailGuard\'s overall multi-vector correlation.
    </div>
  </div>

  <!-- Extracted IOCs -->
  ${(r.iocs && r.iocs.length > 0) ? `
  <div class="section">
    <div class="section-title"><span>🚨 Extracted Indicators of Compromise (IOCs: ${r.iocs.length})</span></div>
    <table>
      <thead>
        <tr><th>Type</th><th>Indicator Value</th><th>Category</th><th>Classification</th></tr>
      </thead>
      <tbody>
        ${r.iocs.map(ioc => `
          <tr>
            <td><span class="badge badge-unknown">${escapeHtml(ioc.type)}</span></td>
            <td style="word-break:break-all"><strong>${escapeHtml(ioc.value)}</strong></td>
            <td style="font-family:'Inter',sans-serif">${escapeHtml(ioc.category)}</td>
            <td><span class="badge badge-${ioc.risk === 'CRITICAL' ? 'critical' : 'low'}">${escapeHtml(ioc.risk)}</span></td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  </div>` : ''}

  <!-- Investigative Limitations -->
  ${(r.limitations && r.limitations.length > 0) ? `
  <div class="section">
    <div class="section-title"><span>⚠️ Investigative Limitations</span></div>
    <ul style="padding-left:20px;font-size:12px;color:#94a3b8;font-family:'Inter',sans-serif;">
      ${r.limitations.map(lim => `<li style="margin-bottom:6px">${escapeHtml(lim)}</li>`).join('')}
    </ul>
  </div>` : ''}

  <!-- Raw Headers -->
  <div class="section">
    <div class="section-title"><span>🔬 Raw RFC 5322 Headers (Forensic Evidence)</span></div>
    <pre>${escapeHtml(r.rawHeaders || 'No raw header source available.')}</pre>
  </div>

  <!-- Footer -->
  <div class="footer">
    <p><strong>GmailGuard — AI-Powered Email Threat Detection & Forensic Intelligence Platform</strong></p>
    <p>SIH 2026 | Problem Statement SIH26106 | AICTE</p>
    <p style="margin-top:8px">This report was synthesized from the GmailGuard FastAPI forensic engine. Findings should be corroborated by SOC Tier-2/3 analysts before executing containment. Classification: RESTRICTED.</p>
    <p style="margin-top:8px">Report ID: ${escapeHtml(r.caseId)} | Generated: ${this.generatedAt}</p>
  </div>
</div>
</body>
</html>`;
  }

  download() {
    const html = this.generateHTML();
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `GmailGuard-Report-${this.result.caseId}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  print() {
    const win = window.open('', '_blank');
    if (!win) {
      alert('Popup blocked. Please allow popups to print the report.');
      return;
    }
    win.document.write(this.generateHTML());
    win.document.close();
    win.focus();
    setTimeout(() => { win.print(); }, 500);
  }
}

window.ForensicReportGenerator = ForensicReportGenerator;
