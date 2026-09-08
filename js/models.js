// ============================================================
// GmailGuard — Response Normalizer & Forensic View Models
// Enforces strict data fidelity against the FastAPI backend
// Does NOT invent fields, confidence percentages, or locations
// ============================================================

class ThreatReportNormalizer {
  /**
   * Normalizes raw backend report JSON into an analyst view model
   * @param {object} r Raw report dict from backend
   * @param {string} rawEmail Full RFC 5322 raw text
   * @returns {object} Canonical view model
   */
  static normalize(r, rawEmail = '') {
    if (!r || typeof r !== 'object') {
      throw new Error('Invalid report structure returned by analysis engine.');
    }

    // ── 1. Case Identifier & Timestamp ────────────────────────
    let caseId = 'GG-' + new Date().toISOString().slice(0, 10).replace(/-/g, '') + '-' + Math.floor(1000 + Math.random() * 9000);
    if (r.email && r.email.message_id) {
      let hash = 0;
      for (let i = 0; i < r.email.message_id.length; i++) {
        hash = ((hash << 5) - hash) + r.email.message_id.charCodeAt(i);
        hash |= 0;
      }
      caseId = 'GG-' + Math.abs(hash).toString(16).toUpperCase().padStart(8, '0');
    }

    // ── 2. Threat Score & Verdict ─────────────────────────────
    const threatScore = typeof r.threat_score === 'number' ? Math.round(r.threat_score) : 0;
    const rawVerdict = (r.verdict || 'SUSPICIOUS').toUpperCase();
    
    // Canonical verdict definitions based on config.VERDICT_THRESHOLDS
    const verdictMap = {
      CRITICAL: { label: 'CRITICAL THREAT', severity: 'critical', badge: 'CRITICAL' },
      HIGH_RISK: { label: 'HIGH RISK', severity: 'high', badge: 'HIGH RISK' },
      MALICIOUS: { label: 'HIGH RISK', severity: 'high', badge: 'HIGH RISK' },
      MEDIUM_RISK: { label: 'SUSPICIOUS', severity: 'medium', badge: 'SUSPICIOUS' },
      SUSPICIOUS: { label: 'SUSPICIOUS', severity: 'medium', badge: 'SUSPICIOUS' },
      LOW_RISK: { label: 'LOW RISK', severity: 'low', badge: 'LOW RISK' },
      CLEAN: { label: 'CLEAN / BENIGN', severity: 'low', badge: 'CLEAN' },
      BENIGN: { label: 'CLEAN / BENIGN', severity: 'low', badge: 'CLEAN' },
    };
    const verdictInfo = verdictMap[rawVerdict] || { label: rawVerdict, severity: 'medium', badge: rawVerdict };

    // ── 3. Email Envelope Metadata ────────────────────────────
    const emailData = r.email || {};
    const toField = Array.isArray(emailData.to) ? emailData.to.join(', ') : (emailData.to || 'Not available');

    const email = {
      from: emailData.from || 'Not available',
      senderEmail: emailData.sender_email || 'Not available',
      senderName: emailData.sender_name || 'Not available',
      senderDomain: emailData.sender_domain || 'Not available',
      to: toField,
      subject: emailData.subject || '(No Subject)',
      date: emailData.date || 'Not available',
      messageId: emailData.message_id || 'Not available',
      replyTo: emailData.reply_to || (r.infrastructure && r.infrastructure.reply_to) || 'Not available',
      returnPath: emailData.return_path || 'Not available',
      replyToDiffers: Boolean(r.infrastructure?.reply_to_differs),
    };

    // ── 4. Sender Originating IP vs Observability ─────────────
    // Observational Rule: Never claim an MTA IP is the sender's physical device
    const xOriginatingIp = r.infrastructure?.x_originating_ip || null;
    const senderIp = {
      isObservable: Boolean(xOriginatingIp),
      value: xOriginatingIp || 'Not Observable',
      source: xOriginatingIp ? 'X-Originating-IP Header (Client-Reported / Untrusted)' : 'None',
      reason: xOriginatingIp
        ? 'Reported in non-standard X-Originating-IP header. Note: Header is not cryptographically signed and may be spoofed by upstream clients.'
        : 'The available email headers do not expose the sender’s originating device IP. Typical for webmail providers (Gmail, Outlook 365) and privacy-preserving MTAs.'
    };

    // ── 5. Authentication Analysis ───────────────────────────
    const authData = r.authentication || {};
    const normalizeAuthStatus = (val) => {
      const v = (val || 'NONE').toUpperCase();
      if (['PASS', 'FAIL', 'SOFTFAIL', 'NEUTRAL', 'NONE', 'UNKNOWN', 'TEMPERROR', 'PERMERROR'].includes(v)) {
        return v;
      }
      return 'UNKNOWN';
    };

    const authentication = {
      spf: normalizeAuthStatus(authData.spf),
      dkim: normalizeAuthStatus(authData.dkim),
      dmarc: normalizeAuthStatus(authData.dmarc),
      spfDetail: authData.spf_detail || 'No SPF evaluation detail provided.',
      dkimDetail: authData.dkim_detail || 'No DKIM signature detail provided.',
      dmarcDetail: authData.dmarc_detail || 'No DMARC policy alignment detail provided.',
      summary: authData.summary || 'Email authentication status evaluated.',
      caveat: 'CRITICAL SECURITY CONTEXT: Authentication PASS confirms domain alignment and transmission integrity; it does NOT verify sender intent. Legitimate domains can be compromised, and free webmail providers frequently achieve PASS while sending phishing lures.'
    };

    // ── 6. 4-Tier Candidate Relays Hierarchy ─────────────────
    const rawCandidates = r.infrastructure?.candidate_relays || [];
    const candidateRelays = rawCandidates.map((c, idx) => {
      const tierNum = c.tier || (idx + 1);
      const tierName = c.tier_name || (tierNum === 1 ? 'RECIPIENT_MTA_OBSERVED' : tierNum === 2 ? 'UPSTREAM_MTA_RECORDED' : tierNum === 3 ? 'UPSTREAM_RELAY' : 'CLIENT_OR_HEADER_SUPPLIED');
      const confidence = (c.confidence || (tierNum === 1 ? 'high' : tierNum <= 3 ? 'medium' : 'low')).toLowerCase();
      const evidenceClass = c.evidence_class || (tierNum === 1 ? 'OBSERVED' : 'DERIVED');
      return {
        tier: tierNum,
        tierName,
        ip: c.ip || 'Not available',
        provider: c.provider || 'Unknown Provider',
        sourceHeader: c.source_header || 'Received',
        hopNumber: c.hop_number != null ? c.hop_number : null,
        confidence,
        evidenceClass,
        rankingDisclaimer: c.ranking_disclaimer || 'Ranking reflects observational proximity to recipient trust boundary.'
      };
    });

    // ── 7. Hop Chain & Timeline Skew ─────────────────────────
    const chronologicalHops = (r.infrastructure?.chronological_hops || []).map((h, i) => ({
      hopNumber: h.hop_number || (i + 1),
      fromHost: h.from_host || 'Unknown',
      byHost: h.by_host || 'Unknown',
      ip: h.ip || null,
      provider: h.provider || 'Unknown',
      timestampRaw: h.timestamp_raw || 'Not available',
      timestampUtc: h.timestamp_utc || null,
      provenance: h.provenance || 'UNKNOWN',
      confidence: h.confidence || 'medium',
      evidenceClass: h.evidence_class || 'DERIVED'
    }));

    const timelineData = r.infrastructure?.timeline_analysis || {};
    const timelineAnalysis = {
      hopsEvaluated: timelineData.hops_evaluated || 0,
      maxHopDelaySec: timelineData.max_hop_delay_sec != null ? timelineData.max_hop_delay_sec : null,
      anomalies: Array.isArray(timelineData.anomalies) ? timelineData.anomalies : [],
      hopDiffs: (timelineData.hop_diffs || []).map(d => ({
        fromHop: d.from_hop,
        toHop: d.to_hop,
        deltaSeconds: d.delta_seconds,
        withinTolerance: Math.abs(d.delta_seconds || 0) <= 120,
        anomaly: d.anomaly || null
      }))
    };

    // ── 8. Observable Infrastructure & Geolocation ───────────
    const rawGeo = r.infrastructure?.geolocation || [];
    const geolocation = rawGeo.map(g => {
      const getFlag = (cc) => {
        if (!cc || cc.length !== 2) return '🌐';
        try {
          const codePoints = cc.toUpperCase().split('').map(char => 127397 + char.charCodeAt(0));
          return String.fromCodePoint(...codePoints);
        } catch (_) { return '🌐'; }
      };

      return {
        ip: g.ip || 'Unknown',
        flag: getFlag(g.country),
        city: g.city || 'Not available',
        region: g.region || 'Not available',
        country: g.country || 'Not available',
        asn: g.asn || 'Not available',
        isp: g.isp || 'Not available',
        org: g.org || g.organization || g.isp || 'Not available',
        timezone: g.timezone || 'Not available',
        latitude: g.lat != null ? g.lat : g.latitude,
        longitude: g.lon != null ? g.lon : g.longitude,
        locationType: 'Observable Mail Infrastructure (Transit Hop)',
        forensicNote: g.forensic_note || g.location_note || 'Observable mail routing hop. Does NOT pinpoint physical sender location.'
      };
    });

    // ── 9. Timezone Divergence ────────────────────────────────
    const tzData = r.infrastructure?.timezone_correlation || null;
    const timezoneCorrelation = tzData ? {
      headerTz: tzData.header_tz_str || 'Not available',
      geoTz: tzData.geo_tz_str || 'Not available',
      divergenceHours: typeof tzData.divergence_hours === 'number' ? tzData.divergence_hours : 0,
      divergenceNote: tzData.divergence_note || 'Header Date and infrastructure timezone offsets evaluated.'
    } : null;

    // ── 10. Client Fingerprint ────────────────────────────────
    const clientData = r.infrastructure?.client_fingerprint || null;
    const clientFingerprint = clientData ? {
      userAgent: clientData.user_agent || clientData.client_name || 'Not available',
      operatingSystem: clientData.operating_system || clientData.platform || 'Not available',
      headerOrderEntropy: clientData.header_order_entropy != null ? clientData.header_order_entropy : 'Not available',
      isAnomalous: Boolean(clientData.is_anomalous),
      anomalies: clientData.anomalies || []
    } : null;

    // ── 11. URLs & PhishTank Verification ─────────────────────
    const urlsSection = r.urls || {};
    const phishTankData = r.forensics?.phishtank || null;
    const phishMatches = phishTankData?.matches || [];

    const urls = (urlsSection.findings || []).map(f => {
      const ptMatch = phishMatches.find(m => m.url === f.url);
      return {
        url: f.url,
        domain: f.domain || 'Unknown',
        tld: f.tld || '',
        riskScore: f.risk_score || 0,
        isIpUrl: Boolean(f.is_ip_url),
        isUrlShortener: Boolean(f.is_url_shortener),
        hasSuspiciousTld: Boolean(f.has_suspicious_tld),
        excessiveSubdomains: Boolean(f.excessive_subdomains),
        hasSuspiciousChars: Boolean(f.has_suspicious_chars),
        usesHttps: Boolean(f.uses_https),
        displayHrefMismatch: Boolean(f.display_href_mismatch),
        domainReputation: f.domain_reputation || 'unknown',
        reasons: Array.isArray(f.reasons) ? f.reasons : [],
        isPhishTankVerified: Boolean(ptMatch),
        phishTankId: ptMatch?.phish_id || null,
        phishTankTarget: ptMatch?.target || null
      };
    });

    // ── 12. Domain Intelligence ───────────────────────────────
    const domainData = r.domain || {};
    const domain = {
      domain: domainData.domain || email.senderDomain || 'Not available',
      reputation: domainData.reputation || 'unknown',
      reputationScore: domainData.reputation_score != null ? domainData.reputation_score : 'Not available',
      ageDays: domainData.age_days != null ? domainData.age_days : null,
      registrar: domainData.registrar || 'Not available',
      virustotalFlags: domainData.virustotal_flags != null ? domainData.virustotal_flags : 0,
      isSuspiciousTld: Boolean(domainData.is_suspicious_tld),
      isTyposquat: Boolean(domainData.is_typosquat),
      typosquatTarget: domainData.typosquat_target || null,
      riskScore: domainData.risk_score != null ? domainData.risk_score : 0,
      reasons: domainData.reasons || []
    };

    // ── 13. Attachment Static Analysis ────────────────────────
    const attSection = r.attachments || {};
    const attachments = (attSection.findings || []).map(a => ({
      filename: a.filename || 'Unnamed attachment',
      extension: a.extension || '',
      contentType: a.content_type || 'application/octet-stream',
      sizeBytes: a.size_bytes || 0,
      sizeMb: a.size_mb != null ? a.size_mb : (a.size_bytes / (1024 * 1024)).toFixed(2),
      riskScore: a.risk_score || 0,
      isDangerousExtension: Boolean(a.is_dangerous_extension),
      isMacroEnabled: Boolean(a.is_macro_enabled),
      isArchive: Boolean(a.is_archive),
      hasDoubleExtension: Boolean(a.has_double_extension),
      suspiciousKeywords: a.suspicious_filename_keywords || [],
      reasons: a.reasons || [],
      staticNotice: 'Files are analyzed statically. Suspicious files are NOT executed.'
    }));

    // ── 14. ML Content Analysis (No fake confidence %) ────────
    const mlData = r.ml || {};
    const ml = {
      available: Boolean(mlData.model_available),
      prediction: mlData.prediction,
      isMalicious: mlData.prediction === 1,
      decisionScore: mlData.decision_score != null ? mlData.decision_score : null,
      modelType: 'Linear Support Vector Machine (TF-IDF & Metadata)',
      note: mlData.note || 'Linear SVM decision score evaluates distance from the decision boundary. Positive values indicate phishing patterns; negative values indicate normal content.'
    };

    // ── 15. Contributing Risk Evidence & Positive Signals ─────
    const evidence = (r.evidence || []).map(e => ({
      signal: e.signal || 'Signal',
      status: e.status || 'DETECTED',
      impact: e.impact != null ? e.impact : 0,
      explanation: e.explanation || 'Signal detected by analyzer.'
    }));

    const positiveEvidence = (r.positive_evidence || []).map(p => ({
      signal: p.signal || 'Mitigating Factor',
      status: p.status || 'VERIFIED',
      impact: p.impact != null ? p.impact : 0,
      explanation: p.explanation || 'Signal reduces overall risk assessment.'
    }));

    // Sub-scores
    const subScores = r.sub_scores || {};

    // Correlated cross-vector findings
    const correlatedEvidence = r.correlated_evidence || [];

    // Forensic Scope Disclaimer
    const forensicScope = r.infrastructure?.forensic_scope || 'Physical attribution is outside the scope of email-header analysis and may require additional evidence and lawful investigative processes. Observable infrastructure metrics represent transit routing points, not verified physical sender coordinates.';

    // Deduplicated IOCs
    const iocs = [];
    (r.infrastructure?.public_ips || []).forEach(ip => {
      const geo = geolocation.find(g => g.ip === ip);
      iocs.push({
        type: 'IPv4 Address',
        value: ip,
        category: 'Transit Hop Infrastructure',
        risk: 'Observable'
      });
    });

    (r.urls?.all_urls || []).forEach(url => {
      const isPhish = phishMatches.some(m => m.url === url);
      iocs.push({
        type: 'URL',
        value: url,
        category: isPhish ? 'PhishTank Verified Phishing' : 'Extracted URL',
        risk: isPhish ? 'CRITICAL' : 'EVALUATED'
      });
    });

    if (domain.domain && domain.domain !== 'Not available') {
      iocs.push({
        type: 'Domain',
        value: domain.domain,
        category: 'Sender Domain',
        risk: domain.isTyposquat ? 'TYPOSQUAT' : 'EVALUATED'
      });
    }

    return {
      caseId,
      threatScore,
      verdict: verdictInfo.label,
      severity: verdictInfo.severity,
      badgeText: verdictInfo.badge,
      rawVerdict,
      email,
      senderIp,
      authentication,
      candidateRelays,
      chronologicalHops,
      timelineAnalysis,
      geolocation,
      timezoneCorrelation,
      clientFingerprint,
      urls,
      domain,
      attachments,
      ml,
      evidence,
      positiveEvidence,
      subScores,
      correlatedEvidence,
      forensicScope,
      iocs,
      limitations: r.limitations || [],
      rawHeaders: rawEmail,
      rawResult: r
    };
  }
}

// Global exposure
window.ThreatReportNormalizer = ThreatReportNormalizer;
