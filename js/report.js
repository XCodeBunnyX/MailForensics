// ============================================================
// MailForensics — Forensic Report Generator
// ============================================================

class ForensicReportGenerator {
  constructor(result) {
    this.result = result;
    this.generatedAt = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', dateStyle: 'full', timeStyle: 'medium' });
  }

  generateHTML() {
    const r = this.result;
    const riskColor = { CRITICAL: '#ff2d55', HIGH: '#ff6b35', MEDIUM: '#ffd60a', LOW: '#34d399' };
    const color = riskColor[r.riskLevel] || '#888';

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MailForensics Forensic Report — ${r.caseId}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap');
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Inter', sans-serif; background: #0a0e1a; color: #e2e8f0; line-height: 1.6; }
  .report { max-width: 900px; margin: 0 auto; padding: 40px 30px; }
  .header { text-align: center; border-bottom: 2px solid #1e293b; padding-bottom: 30px; margin-bottom: 30px; }
  .logo { font-size: 28px; font-weight: 700; color: #00d4ff; letter-spacing: 4px; }
  .logo-sub { font-size: 11px; color: #64748b; letter-spacing: 2px; text-transform: uppercase; margin-top: 4px; }
  .report-title { font-size: 20px; color: #94a3b8; margin-top: 16px; }
  .case-id { font-family: 'JetBrains Mono', monospace; color: #00d4ff; font-size: 14px; margin-top: 8px; }
  .meta { display: flex; justify-content: center; gap: 40px; margin-top: 16px; font-size: 12px; color: #64748b; }
  .section { margin-bottom: 30px; }
  .section-title { font-size: 13px; font-weight: 700; color: #00d4ff; text-transform: uppercase; letter-spacing: 2px; border-left: 3px solid #00d4ff; padding-left: 10px; margin-bottom: 14px; }
  .verdict-box { background: ${color}15; border: 2px solid ${color}; border-radius: 12px; padding: 24px; text-align: center; margin-bottom: 30px; }
  .score-big { font-size: 72px; font-weight: 700; color: ${color}; line-height: 1; }
  .risk-label { font-size: 24px; font-weight: 700; color: ${color}; letter-spacing: 4px; margin-top: 8px; }
  .verdict-meta { display: flex; justify-content: center; gap: 40px; margin-top: 16px; }
  .verdict-item { text-align: center; }
  .verdict-item-label { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 1px; }
  .verdict-item-value { font-size: 16px; font-weight: 600; color: #e2e8f0; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { background: #0f172a; color: #64748b; font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 1px; padding: 10px 12px; text-align: left; border-bottom: 1px solid #1e293b; }
  td { padding: 10px 12px; border-bottom: 1px solid #1e293b; vertical-align: top; font-family: 'JetBrains Mono', monospace; font-size: 12px; }
  tr:last-child td { border-bottom: none; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; }
  .badge-critical { background: #ff2d5520; color: #ff2d55; border: 1px solid #ff2d5540; }
  .badge-high { background: #ff6b3520; color: #ff6b35; border: 1px solid #ff6b3540; }
  .badge-medium { background: #ffd60a20; color: #ffd60a; border: 1px solid #ffd60a40; }
  .badge-low { background: #34d39920; color: #34d399; border: 1px solid #34d39940; }
  .badge-pass { background: #34d39920; color: #34d399; }
  .badge-fail { background: #ff2d5520; color: #ff2d55; }
  .badge-unknown { background: #64748b20; color: #94a3b8; }
  .factor-row { display: flex; align-items: center; gap: 12px; padding: 10px 0; border-bottom: 1px solid #1e293b; }
  .factor-name { flex: 1; font-size: 13px; color: #e2e8f0; }
  .factor-bar { flex: 2; background: #1e293b; border-radius: 4px; height: 8px; overflow: hidden; }
  .factor-fill { height: 100%; border-radius: 4px; }
  .factor-score { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #94a3b8; min-width: 40px; text-align: right; }
  .finding-item { padding: 12px; background: #0f172a; border-radius: 8px; margin-bottom: 8px; border-left: 3px solid; }
  .finding-title { font-weight: 600; font-size: 13px; }
  .finding-detail { font-size: 12px; color: #94a3b8; margin-top: 4px; }
  .ioc-item { display: flex; align-items: center; gap: 12px; padding: 8px 0; border-bottom: 1px solid #1e293b; font-family: 'JetBrains Mono', monospace; font-size: 11px; }
  .footer { text-align: center; padding-top: 30px; border-top: 1px solid #1e293b; color: #64748b; font-size: 11px; }
  .watermark { color: #1e293b; font-size: 48px; font-weight: 700; position: fixed; bottom: 80px; right: 40px; transform: rotate(-30deg); pointer-events: none; letter-spacing: 8px; }
  pre { font-family: 'JetBrains Mono', monospace; font-size: 11px; background: #0f172a; padding: 16px; border-radius: 8px; overflow-x: auto; color: #94a3b8; white-space: pre-wrap; word-break: break-all; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .info-card { background: #0f172a; border-radius: 8px; padding: 14px; border: 1px solid #1e293b; }
  .info-label { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 1px; }
  .info-value { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #e2e8f0; margin-top: 4px; word-break: break-all; }
  @media print { body { background: #000; } .watermark { display: block; } }
</style>
</head>
<body>
<div class="report">
  <div class="watermark">MailForensics</div>

  <div class="header">
    <div class="logo">⬡ MailForensics</div>
    <div class="logo-sub">Advanced Email Guardian & Intelligence System</div>
    <div class="report-title">Digital Forensic Investigation Report</div>
    <div class="case-id">${r.caseId}</div>
    <div class="meta">
      <span>📅 Generated: ${this.generatedAt}</span>
      <span>🔒 Classification: RESTRICTED</span>
      <span>👤 Analyst: AI Forensics Engine v2.6</span>
    </div>
  </div>

  <!-- VERDICT -->
  <div class="verdict-box">
    <div class="score-big">${r.threatScore}</div>
    <div style="font-size:14px;color:#64748b;margin-top:4px;">THREAT SCORE / 100</div>
    <div class="risk-label">${r.riskLevel} RISK</div>
    <div class="verdict-meta">
      <div class="verdict-item"><div class="verdict-item-label">Threat Type</div><div class="verdict-item-value">${r.threatType}</div></div>
      <div class="verdict-item"><div class="verdict-item-label">AI Confidence</div><div class="verdict-item-value">${r.confidence}</div></div>
      <div class="verdict-item"><div class="verdict-item-label">IOCs Found</div><div class="verdict-item-value">${r.iocs.length}</div></div>
      <div class="verdict-item"><div class="verdict-item-label">Timestamp</div><div class="verdict-item-value">${r.date || 'N/A'}</div></div>
    </div>
  </div>

  <!-- THREAT SCORE BREAKDOWN -->
  <div class="section">
    <div class="section-title">📊 Threat Score Breakdown</div>
    ${r.factors.filter(f => f.score > 0).map(f => {
      const fc = f.severity === 'critical' ? '#ff2d55' : f.severity === 'high' ? '#ff6b35' : f.severity === 'medium' ? '#ffd60a' : '#34d399';
      return `<div class="factor-row">
        <div class="factor-name">${f.name}</div>
        <div class="factor-bar"><div class="factor-fill" style="width:${(f.score/20)*100}%;background:${fc};"></div></div>
        <div class="factor-score">+${f.score}/20</div>
      </div>
      <div style="font-size:11px;color:#64748b;padding:4px 0 8px 0;border-bottom:1px solid #0f172a;">${f.detail}</div>`;
    }).join('')}
  </div>

  <!-- EMAIL METADATA -->
  <div class="section">
    <div class="section-title">📧 Email Metadata</div>
    <div class="grid-2">
      <div class="info-card"><div class="info-label">From</div><div class="info-value">${r.sender.from}</div></div>
      <div class="info-card"><div class="info-label">To</div><div class="info-value">${r.recipient.to}</div></div>
      <div class="info-card"><div class="info-label">Subject</div><div class="info-value">${r.subject}</div></div>
      <div class="info-card"><div class="info-label">Date</div><div class="info-value">${r.date}</div></div>
      <div class="info-card"><div class="info-label">Reply-To</div><div class="info-value">${r.sender.replyTo}</div></div>
      <div class="info-card"><div class="info-label">X-Originating-IP</div><div class="info-value">${r.sender.xOriginatingIP}</div></div>
      <div class="info-card"><div class="info-label">Message-ID</div><div class="info-value">${r.messageId}</div></div>
      <div class="info-card"><div class="info-label">X-Mailer</div><div class="info-value">${r.sender.xMailer}</div></div>
    </div>
  </div>

  <!-- AUTH RESULTS -->
  <div class="section">
    <div class="section-title">🛡️ Email Authentication</div>
    <table>
      <tr><th>Protocol</th><th>Result</th><th>Implication</th></tr>
      <tr><td>SPF (Sender Policy Framework)</td><td><span class="badge badge-${r.auth.spf === 'pass' ? 'pass' : 'fail'}">${r.auth.spf.toUpperCase()}</span></td><td>${r.auth.spf === 'pass' ? 'Authorized sender' : 'Sender not authorized — possible spoofing'}</td></tr>
      <tr><td>DKIM (DomainKeys Identified Mail)</td><td><span class="badge badge-${r.auth.dkim === 'pass' ? 'pass' : 'fail'}">${r.auth.dkim.toUpperCase()}</span></td><td>${r.auth.dkim === 'pass' ? 'Valid cryptographic signature' : 'No valid signature — email integrity unverified'}</td></tr>
      <tr><td>DMARC (Domain-based Message Auth)</td><td><span class="badge badge-${r.auth.dmarc === 'pass' ? 'pass' : 'fail'}">${r.auth.dmarc.toUpperCase()}</span></td><td>${r.auth.dmarc === 'pass' ? 'Policy aligned' : 'Policy violation — high spoofing risk'}</td></tr>
    </table>
  </div>

  <!-- MAIL HOP CHAIN -->
  ${r.hops.length > 0 ? `<div class="section">
    <div class="section-title">🔗 Mail Server Hop Chain</div>
    <table>
      <tr><th>Hop</th><th>From</th><th>By</th><th>IP</th><th>Timestamp</th></tr>
      ${r.hops.map(h => `<tr><td>${h.hop}</td><td>${h.from}</td><td>${h.by}</td><td>${h.ip || 'N/A'}</td><td style="font-size:11px;">${h.timestamp || 'N/A'}</td></tr>`).join('')}
    </table>
  </div>` : ''}

  <!-- IP GEOLOCATION -->
  ${r.geoResults.length > 0 ? `<div class="section">
    <div class="section-title">🌍 IP Geolocation Analysis</div>
    <table>
      <tr><th>IP Address</th><th>Location</th><th>ASN</th><th>Organization</th><th>Risk</th></tr>
      ${r.geoResults.map(g => `<tr><td>${g.ip}</td><td>${g.flag || ''} ${g.city || 'Unknown'}, ${g.country || 'Unknown'}</td><td>${g.asn || 'N/A'}</td><td>${g.org || 'N/A'}</td><td><span class="badge badge-${g.risk}">${(g.risk||'unknown').toUpperCase()}</span></td></tr>`).join('')}
    </table>
  </div>` : ''}

  <!-- DOMAIN INTEL -->
  ${r.domainResults.filter(d => d.age_days !== null || d.categories?.length > 0).length > 0 ? `<div class="section">
    <div class="section-title">🔍 Domain Intelligence</div>
    <table>
      <tr><th>Domain</th><th>Age (Days)</th><th>Risk</th><th>Categories</th><th>Similar To</th></tr>
      ${r.domainResults.map(d => `<tr><td>${d.domain}</td><td>${d.age_days ?? 'N/A'}</td><td><span class="badge badge-${d.risk||'unknown'}">${(d.risk||'unknown').toUpperCase()}</span></td><td>${(d.categories||[]).join(', ')||'—'}</td><td>${d.similar_to||'—'}</td></tr>`).join('')}
    </table>
  </div>` : ''}

  <!-- URLS -->
  ${r.urls.length > 0 ? `<div class="section">
    <div class="section-title">🔗 Extracted URLs</div>
    <table>
      <tr><th>#</th><th>URL</th><th>Risk Indicator</th></tr>
      ${r.urls.map((u, i) => `<tr><td>${i+1}</td><td style="word-break:break-all;max-width:500px;">${u}</td><td>${u.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) ? '<span class="badge badge-critical">IP-BASED URL</span>' : '<span class="badge badge-medium">EXTERNAL LINK</span>'}</td></tr>`).join('')}
    </table>
  </div>` : ''}

  <!-- ATTACHMENTS -->
  ${r.attachments.length > 0 ? `<div class="section">
    <div class="section-title">📎 Attachment Forensics</div>
    <table>
      <tr><th>Filename</th><th>Size</th><th>Type</th><th>MD5</th><th>SHA-256</th><th>Risk</th></tr>
      ${r.attachments.map(a => `<tr><td>${a.name}</td><td>${a.size}</td><td>${a.type}</td><td style="font-size:10px;">${a.hash_md5}</td><td style="font-size:10px;word-break:break-all;">${a.hash_sha256}</td><td><span class="badge badge-${a.risk}">${a.risk.toUpperCase()}</span></td></tr>`).join('')}
    </table>
  </div>` : ''}

  <!-- ML FINDINGS -->
  <div class="section">
    <div class="section-title">🤖 AI/ML Threat Assessment</div>
    ${r.mlFindings.map(f => `<div class="finding-item" style="border-color:${f.label==='MALICIOUS'?'#ff2d55':f.label==='SUSPICIOUS'?'#ff6b35':'#34d399'}">
      <div class="finding-title">${f.icon} ${f.model} — <span style="font-family:'JetBrains Mono',monospace;font-size:12px;">${f.label}</span> (${f.confidence} confidence)</div>
      <div class="finding-detail">${f.finding}</div>
    </div>`).join('')}
  </div>

  <!-- IOC LIST -->
  ${r.iocs.length > 0 ? `<div class="section">
    <div class="section-title">🚨 Indicators of Compromise (IOCs)</div>
    <table>
      <tr><th>Type</th><th>Indicator</th><th>Risk</th><th>Source</th></tr>
      ${r.iocs.map(ioc => `<tr><td><span class="badge badge-${ioc.risk}">${ioc.type}</span></td><td style="word-break:break-all;">${ioc.value}${ioc.name ? ' ('+ioc.name+')' : ''}</td><td><span class="badge badge-${ioc.risk}">${ioc.risk.toUpperCase()}</span></td><td>${ioc.source}</td></tr>`).join('')}
    </table>
  </div>` : ''}

  <!-- RAW HEADERS -->
  <div class="section">
    <div class="section-title">🔬 Raw Email Headers (Forensic Evidence)</div>
    <pre>${r.rawHeaders.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</pre>
  </div>

  <!-- FOOTER -->
  <div class="footer">
    <p><strong>MailForensics — Advanced Email Forensics & Intelligence System</strong></p>
    <p>SIH 2026 | Problem Statement SIH26106 | AICTE</p>
    <p style="margin-top:8px;">This report was generated automatically by the MailForensics AI forensics engine. All findings should be validated by a qualified security analyst before taking action. Classification: RESTRICTED — For authorized personnel only.</p>
    <p style="margin-top:8px;">Report ID: ${r.caseId} | Generated: ${this.generatedAt}</p>
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
    a.download = `MF-Report-${this.result.caseId}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
}

window.ForensicReportGenerator = ForensicReportGenerator;
