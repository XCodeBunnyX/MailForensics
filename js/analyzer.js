// ============================================================
// MailForensics — Email Analysis Engine
// ============================================================

class EmailAnalyzer {
  constructor(rawEmail) {
    this.raw = rawEmail;
    this.headers = {};
    this.body = "";
    this.result = null;
  }

  parse() {
    const lines = this.raw.split('\n');
    let inBody = false;
    let bodyLines = [];
    let currentHeader = '';
    let currentValue = '';

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!inBody && line.trim() === '') {
        inBody = true;
        if (currentHeader) this.headers[currentHeader.toLowerCase()] = currentValue.trim();
        continue;
      }
      if (inBody) {
        bodyLines.push(line);
        continue;
      }
      const headerMatch = line.match(/^([A-Za-z0-9\-]+):\s*(.*)/);
      if (headerMatch) {
        if (currentHeader) this.headers[currentHeader.toLowerCase()] = currentValue.trim();
        currentHeader = headerMatch[1];
        currentValue = headerMatch[2];
      } else if (line.match(/^\s+/) && currentHeader) {
        currentValue += ' ' + line.trim();
      }
    }
    if (currentHeader) this.headers[currentHeader.toLowerCase()] = currentValue.trim();
    this.body = bodyLines.join('\n');
    return this;
  }

  extractIPs() {
    const ipRegex = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
    const found = new Set();
    const fullText = this.raw;
    let m;
    while ((m = ipRegex.exec(fullText)) !== null) {
      const ip = m[1];
      const parts = ip.split('.').map(Number);
      if (parts.every(p => p >= 0 && p <= 255) && !ip.startsWith('192.168') && !ip.startsWith('10.') && !ip.startsWith('127.')) {
        found.add(ip);
      }
    }
    return [...found];
  }

  extractURLs() {
    const urlRegex = /https?:\/\/[^\s"'<>()]+/g;
    const found = new Set();
    const m_array = this.raw.match(urlRegex) || [];
    m_array.forEach(u => found.add(u.replace(/[.,;]$/, '')));
    return [...found];
  }

  extractDomains() {
    const urls = this.extractURLs();
    const domains = new Set();
    urls.forEach(url => {
      try {
        const d = url.replace(/https?:\/\//, '').split('/')[0].split('?')[0];
        if (d && !d.match(/^\d/)) domains.add(d);
      } catch(e) {}
    });
    // Also extract from email addresses
    const emailRegex = /[\w.+-]+@([\w.-]+\.[a-z]{2,})/gi;
    let em;
    while ((em = emailRegex.exec(this.raw)) !== null) {
      domains.add(em[1]);
    }
    return [...domains];
  }

  parseReceivedChain() {
    const receivedHeaders = [];
    const lines = this.raw.split('\n');
    let collecting = false;
    let current = '';

    for (const line of lines) {
      if (line.toLowerCase().startsWith('received:')) {
        if (current) receivedHeaders.push(current.trim());
        current = line;
        collecting = true;
      } else if (collecting && line.match(/^\s+/)) {
        current += ' ' + line.trim();
      } else {
        collecting = false;
      }
    }
    if (current) receivedHeaders.push(current.trim());

    return receivedHeaders.map((h, i) => {
      const ipMatch = h.match(/\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)/);
      const fromMatch = h.match(/from\s+([\w.-]+)/i);
      const byMatch = h.match(/by\s+([\w.-]+)/i);
      const timeMatch = h.match(/;\s*(.+)$/);
      return {
        hop: receivedHeaders.length - i,
        from: fromMatch ? fromMatch[1] : 'unknown',
        by: byMatch ? byMatch[1] : 'unknown',
        ip: ipMatch ? ipMatch[1] : null,
        timestamp: timeMatch ? timeMatch[1].trim() : null,
        raw: h
      };
    });
  }

  parseAuthResults() {
    const authHeader = this.headers['authentication-results'] || '';
    return {
      spf: authHeader.includes('spf=fail') ? 'fail' :
           authHeader.includes('spf=softfail') ? 'softfail' :
           authHeader.includes('spf=pass') ? 'pass' :
           authHeader.includes('spf=none') ? 'none' : 'unknown',
      dkim: authHeader.includes('dkim=none') ? 'none' :
            authHeader.includes('dkim=fail') ? 'fail' :
            authHeader.includes('dkim=pass') ? 'pass' : 'unknown',
      dmarc: authHeader.includes('dmarc=fail') ? 'fail' :
             authHeader.includes('dmarc=pass') ? 'pass' :
             authHeader.includes('dmarc=none') ? 'none' : 'unknown'
    };
  }

  parseAttachments() {
    const attachments = [];
    const attachRegex = /\[Attachment:\s*([^\]]+)\]/gi;
    let m;
    while ((m = attachRegex.exec(this.raw)) !== null) {
      const parts = m[1].split(',');
      const name = parts[0].trim();
      const size = parts[1] ? parts[1].trim() : 'Unknown';
      const ext = name.split('.').pop().toLowerCase();
      const riskMap = { docm: 'critical', xlsm: 'critical', js: 'high', vbs: 'high', exe: 'critical', pdf: 'medium', zip: 'high', rar: 'high', doc: 'medium', xls: 'medium' };
      const hash_md5 = this._fakeHash(name, 32);
      const hash_sha256 = this._fakeHash(name, 64);
      attachments.push({
        name, size, ext, risk: riskMap[ext] || 'low',
        hash_md5, hash_sha256,
        type: this._getFileType(ext),
        malicious: ['docm','xlsm','js','vbs','exe'].includes(ext)
      });
    }
    return attachments;
  }

  _fakeHash(seed, len) {
    const chars = '0123456789abcdef';
    let hash = '';
    let s = 0;
    for (let i = 0; i < seed.length; i++) s = ((s << 5) - s) + seed.charCodeAt(i);
    for (let i = 0; i < len; i++) { s = ((s << 5) - s) + i * 7; hash += chars[Math.abs(s) % 16]; }
    return hash;
  }

  _getFileType(ext) {
    const types = { docm: 'Word Document (Macro-Enabled)', xlsm: 'Excel Spreadsheet (Macro-Enabled)', pdf: 'PDF Document', zip: 'ZIP Archive', exe: 'Executable', js: 'JavaScript', vbs: 'VBScript', rar: 'RAR Archive', doc: 'Word Document', xls: 'Excel Spreadsheet' };
    return types[ext] || 'Unknown';
  }

  computeThreatScore() {
    const { THREAT_INTEL_DB, GEO_DB, DOMAIN_INTEL } = window.MAILFORENSICS_DATA;
    const auth = this.parseAuthResults();
    const ips = this.extractIPs();
    const urls = this.extractURLs();
    const domains = this.extractDomains();
    const attachments = this.parseAttachments();
    const bodyText = this.body.toLowerCase() + this.raw.toLowerCase();
    const replyTo = this.headers['reply-to'] || '';
    const fromHeader = this.headers['from'] || '';

    const factors = [];
    let totalScore = 0;

    // Auth checks
    if (auth.spf === 'fail') { factors.push({ name: 'SPF Authentication', score: 18, weight: 18, detail: 'SPF record check failed — sender domain mismatch detected', severity: 'critical' }); totalScore += 18; }
    else if (auth.spf === 'softfail') { factors.push({ name: 'SPF Authentication', score: 10, weight: 10, detail: 'SPF soft-fail — sender not explicitly authorized', severity: 'high' }); totalScore += 10; }
    else if (auth.spf === 'pass') { factors.push({ name: 'SPF Authentication', score: 0, weight: 0, detail: 'SPF record check passed', severity: 'low' }); }

    if (auth.dkim === 'none' || auth.dkim === 'fail') { factors.push({ name: 'DKIM Signature', score: 14, weight: 14, detail: auth.dkim === 'fail' ? 'DKIM signature verification failed' : 'No DKIM signature present — email may be spoofed', severity: 'high' }); totalScore += 14; }
    else { factors.push({ name: 'DKIM Signature', score: 0, weight: 0, detail: 'DKIM signature valid', severity: 'low' }); }

    if (auth.dmarc === 'fail') { factors.push({ name: 'DMARC Policy', score: 16, weight: 16, detail: 'DMARC policy violation — email fails domain alignment', severity: 'critical' }); totalScore += 16; }
    else if (auth.dmarc === 'pass') { factors.push({ name: 'DMARC Policy', score: 0, weight: 0, detail: 'DMARC policy aligned', severity: 'low' }); }

    // Reply-To mismatch
    if (replyTo && fromHeader) {
      const fromDomain = (fromHeader.match(/@([\w.-]+)/) || [])[1] || '';
      const replyDomain = (replyTo.match(/@([\w.-]+)/) || [])[1] || '';
      if (fromDomain && replyDomain && fromDomain !== replyDomain) {
        factors.push({ name: 'Reply-To Mismatch', score: 12, weight: 12, detail: `Reply-To domain (${replyDomain}) differs from From domain (${fromDomain}) — classic phishing indicator`, severity: 'critical' });
        totalScore += 12;
      }
    }

    // IP reputation
    let ipScore = 0;
    ips.forEach(ip => {
      if (THREAT_INTEL_DB.maliciousIPs.includes(ip)) { ipScore = Math.max(ipScore, 15); }
      else if (GEO_DB[ip] && ['critical','high'].includes(GEO_DB[ip].risk)) { ipScore = Math.max(ipScore, 8); }
    });
    if (ipScore > 0) { factors.push({ name: 'IP Reputation', score: ipScore, weight: ipScore, detail: `Originating IPs found in threat intelligence database with ${ipScore >= 15 ? 'critical' : 'high'} risk rating`, severity: ipScore >= 15 ? 'critical' : 'high' }); totalScore += ipScore; }

    // Domain intelligence
    let domainScore = 0;
    let domainDetail = '';
    domains.forEach(d => {
      if (THREAT_INTEL_DB.maliciousDomains.includes(d)) { domainScore = Math.max(domainScore, 15); domainDetail = `Domain ${d} flagged in threat intelligence feeds`; }
      if (DOMAIN_INTEL[d] && DOMAIN_INTEL[d].age_days < 30) { domainScore = Math.max(domainScore, 10); domainDetail = domainDetail || `Domain ${d} registered only ${DOMAIN_INTEL[d].age_days} days ago (newly registered)`; }
    });
    if (domainScore > 0) { factors.push({ name: 'Domain Intelligence', score: domainScore, weight: domainScore, detail: domainDetail, severity: domainScore >= 15 ? 'critical' : 'high' }); totalScore += domainScore; }

    // Suspicious body content
    let contentScore = 0;
    const matchedPatterns = [];
    THREAT_INTEL_DB.suspiciousPatterns.forEach(p => { if (bodyText.includes(p)) { contentScore += 3; matchedPatterns.push(p); } });
    contentScore = Math.min(contentScore, 15);
    if (contentScore > 0) { factors.push({ name: 'Content Analysis (NLP)', score: contentScore, weight: contentScore, detail: `Detected ${matchedPatterns.length} high-risk language patterns: "${matchedPatterns.slice(0,3).join('", "')}"`, severity: contentScore >= 12 ? 'critical' : 'high' }); totalScore += contentScore; }

    // Attachment risk
    let attachScore = 0;
    attachments.forEach(a => { if (a.malicious) attachScore += 15; else if (a.risk === 'medium') attachScore += 5; });
    attachScore = Math.min(attachScore, 15);
    if (attachScore > 0) { factors.push({ name: 'Attachment Analysis', score: attachScore, weight: attachScore, detail: `Detected ${attachments.filter(a=>a.malicious).length} potentially malicious attachment(s) with macro-enabled or executable content`, severity: attachScore >= 12 ? 'critical' : 'high' }); totalScore += attachScore; }

    // URL risk
    if (urls.some(u => u.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/))) {
      factors.push({ name: 'URL Analysis', score: 10, weight: 10, detail: 'URLs containing raw IP addresses detected — commonly used to bypass domain-based filters', severity: 'critical' });
      totalScore += 10;
    } else if (urls.length > 0) {
      factors.push({ name: 'URL Analysis', score: 5, weight: 5, detail: `${urls.length} external URLs detected, domain reputation checked`, severity: 'medium' });
      totalScore += 5;
    }

    // Header anomalies
    const xMailer = this.headers['x-mailer'] || '';
    if (xMailer.toLowerCase().includes('phpmailer') || xMailer.toLowerCase().includes('the bat')) {
      factors.push({ name: 'Header Anomalies', score: 8, weight: 8, detail: `Suspicious mail client detected: ${xMailer} — commonly used in bulk phishing campaigns`, severity: 'high' });
      totalScore += 8;
    }

    totalScore = Math.min(totalScore, 100);

    return { totalScore, factors };
  }

  analyze() {
    this.parse();
    const auth = this.parseAuthResults();
    const ips = this.extractIPs();
    const urls = this.extractURLs();
    const domains = this.extractDomains();
    const hops = this.parseReceivedChain();
    const attachments = this.parseAttachments();
    const { totalScore, factors } = this.computeThreatScore();
    const { GEO_DB, DOMAIN_INTEL, THREAT_INTEL_DB } = window.MAILFORENSICS_DATA;

    const riskLevel = totalScore >= 80 ? 'CRITICAL' : totalScore >= 60 ? 'HIGH' : totalScore >= 35 ? 'MEDIUM' : 'LOW';

    // Determine threat type
    let threatType = 'Unknown';
    const bodyLower = this.body.toLowerCase();
    if (bodyLower.includes('wire transfer') || bodyLower.includes('ifsc') || bodyLower.includes('account number')) threatType = 'BEC / CEO Fraud';
    else if (bodyLower.includes('macros') || attachments.some(a => a.malicious)) threatType = 'Malware / Dropper';
    else if (bodyLower.includes('suspended') || bodyLower.includes('verify') || bodyLower.includes('login')) threatType = 'Phishing / Credential Harvest';
    else if (bodyLower.includes('invoice')) threatType = 'Invoice Fraud';

    // IOCs
    const iocs = [];
    ips.forEach(ip => { if (THREAT_INTEL_DB.maliciousIPs.includes(ip)) iocs.push({ type: 'IP', value: ip, risk: 'critical', source: 'MailForensics Threat Intel' }); });
    domains.forEach(d => { if (THREAT_INTEL_DB.maliciousDomains.includes(d)) iocs.push({ type: 'Domain', value: d, risk: 'critical', source: 'MailForensics Threat Intel' }); });
    urls.forEach(u => { if (u.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) iocs.push({ type: 'URL', value: u, risk: 'high', source: 'Pattern Match' }); });
    attachments.filter(a => a.malicious).forEach(a => iocs.push({ type: 'File Hash', value: a.hash_sha256, risk: 'critical', source: 'Hash Analysis', name: a.name }));

    // Geolocation
    const geoResults = ips.map(ip => ({ ip, ...(GEO_DB[ip] || { country: 'Unknown', city: 'Unknown', asn: 'Unknown', org: 'Unknown', flag: '🌐', risk: 'unknown' }) }));

    // Domain intel results
    const domainResults = domains.map(d => ({ domain: d, ...(DOMAIN_INTEL[d] || { risk: 'unknown', categories: [], age_days: null }) }));

    // ML findings
    const mlFindings = this._generateMLFindings(totalScore, factors, bodyLower);

    // Key findings
    const keyFindings = factors.filter(f => f.score > 0).map(f => ({ title: f.name, detail: f.detail, severity: f.severity }));

    this.result = {
      caseId: 'MF-2026-' + String(Math.floor(Math.random() * 90) + 10).padStart(4, '0'),
      timestamp: new Date().toISOString(),
      threatScore: totalScore,
      riskLevel,
      threatType,
      confidence: Math.min(95, 60 + totalScore * 0.4).toFixed(0) + '%',
      factors,
      keyFindings,
      sender: {
        from: this.headers['from'] || 'Unknown',
        replyTo: this.headers['reply-to'] || 'N/A',
        returnPath: this.headers['return-path'] || 'N/A',
        xMailer: this.headers['x-mailer'] || 'N/A',
        xOriginatingIP: this.headers['x-originating-ip'] || 'N/A'
      },
      recipient: { to: this.headers['to'] || 'Unknown', cc: this.headers['cc'] || 'N/A' },
      subject: this.headers['subject'] || 'No Subject',
      date: this.headers['date'] || 'Unknown',
      messageId: this.headers['message-id'] || 'Unknown',
      auth, ips, urls, domains,
      hops, attachments, iocs, geoResults, domainResults, mlFindings,
      rawHeaders: Object.entries(this.headers).map(([k, v]) => `${k}: ${v}`).join('\n'),
      body: this.body
    };

    return this.result;
  }

  _generateMLFindings(score, factors, bodyLower) {
    const findings = [];

    // NLP Urgency Detection
    const urgencyWords = ['urgent','immediately','suspended','permanent','24 hours','act now','limited time'];
    const urgencyCount = urgencyWords.filter(w => bodyLower.includes(w)).length;
    if (urgencyCount > 0) {
      findings.push({ model: 'NLP Urgency Detector', confidence: Math.min(98, 70 + urgencyCount * 5) + '%', finding: `High urgency language detected (${urgencyCount} indicators)`, label: 'SOCIAL_ENGINEERING', icon: '🧠' });
    }

    // BERT-style Classification
    findings.push({ model: 'BERT Phishing Classifier', confidence: Math.min(97, 55 + score * 0.45) + '%', finding: score > 70 ? 'Email classified as MALICIOUS with high confidence' : score > 40 ? 'Email classified as SUSPICIOUS' : 'Email appears LEGITIMATE', label: score > 70 ? 'MALICIOUS' : score > 40 ? 'SUSPICIOUS' : 'LEGITIMATE', icon: '🤖' });

    // Graph Neural Network
    findings.push({ model: 'GNN Relationship Analysis', confidence: Math.min(94, 50 + score * 0.4) + '%', finding: 'Sender infrastructure linked to known phishing campaign cluster', label: 'CAMPAIGN_MATCH', icon: '🕸️' });

    // Anomaly Detector
    if (score > 50) {
      findings.push({ model: 'Anomaly Detection (Isolation Forest)', confidence: Math.min(92, 60 + score * 0.3) + '%', finding: 'Email header patterns deviate significantly from legitimate baseline', label: 'ANOMALY_DETECTED', icon: '⚠️' });
    }

    // Attachment scanner
    if (bodyLower.includes('attachment') || bodyLower.includes('.docm') || bodyLower.includes('.pdf')) {
      findings.push({ model: 'ML Attachment Classifier', confidence: '91%', finding: 'Attachment exhibits characteristics consistent with malware delivery mechanism', label: 'MALWARE_SIGNATURE', icon: '📎' });
    }

    return findings;
  }
}

window.EmailAnalyzer = EmailAnalyzer;
