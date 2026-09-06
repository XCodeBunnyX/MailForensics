// ============================================================
// MailForensics — Demo Data & IOC Database
// ============================================================

const DEMO_EMAILS = {
  phishing_bank: {
    label: "🎣 Banking Phishing — HDFC Credential Harvest",
    risk: "critical",
    raw: `From: "HDFC Bank Security" <security-alert@hdfcbank-secure.co.in>
To: victim@example.com
Subject: [URGENT] Your HDFC NetBanking Account Has Been Suspended
Date: Thu, 03 Sep 2026 08:14:22 +0000
Message-ID: <20260903081422.7A3F2@hdfcbank-secure.co.in>
Reply-To: noreply@hdfcbank-secure.co.in
MIME-Version: 1.0
X-Mailer: Microsoft Outlook 16.0
X-Originating-IP: 185.234.219.47
Content-Type: multipart/mixed; boundary="----=_Part_1234_5678"
Received: from mail.hdfcbank-secure.co.in (185.234.219.47) by mx.example.com
 (8.15.2/8.15.2) with ESMTP id 3038E4K7063821; Thu, 03 Sep 2026 08:14:22 GMT
Received: from [192.168.1.105] (unknown [103.21.244.0]) by hdfcbank-secure.co.in
 (Postfix) with ESMTP; Thu, 03 Sep 2026 08:12:11 +0000
Authentication-Results: mx.example.com; spf=fail (sender IP is 185.234.219.47)
 smtp.mailfrom=security@hdfcbank-secure.co.in; dkim=none; dmarc=fail

Dear Valued Customer,

Your HDFC NetBanking account has been SUSPENDED due to multiple failed login attempts.
To restore access, please verify your account within 24 hours:

http://hdfc-secure-verify.co.in/login?redirect=account&token=eyJhbGciOiJSUzI1NiJ9
https://185.234.219.47/phish/hdfc/login.php

If you do not verify, your account will be permanently closed.

[Attachment: AccountSuspensionNotice.pdf, 284KB]`
  },
  ceo_fraud: {
    label: "👔 BEC — CEO Impersonation Wire Transfer",
    risk: "critical",
    raw: `From: "Rajesh Kumar (CEO)" <rajesh.kumar@company-corp.net>
To: finance@targetcompany.com
Subject: Urgent Wire Transfer Required - Confidential
Date: Thu, 03 Sep 2026 14:32:10 +0530
Message-ID: <rand-9283.BEC.CEO@company-corp.net>
Reply-To: ceo-urgent@protonmail.com
MIME-Version: 1.0
X-Mailer: The Bat! 10.3
X-Priority: 1 (Highest)
X-Originating-IP: 45.141.86.100
Content-Type: text/plain; charset=UTF-8
Received: from company-corp.net (45.141.86.100) by mx.targetcompany.com
 with ESMTP; Thu, 03 Sep 2026 14:32:10 +0530
Authentication-Results: mx.targetcompany.com; spf=softfail smtp.mailfrom=rajesh@company-corp.net;
 dkim=none; dmarc=fail (p=reject; dis=none)

Hi,

I need you to process an urgent wire transfer of INR 47,50,000 to a vendor account.
This is time-sensitive and needs to be done today before 5pm.

Beneficiary: Global Trade Solutions Pvt Ltd
Account: 9823456701
IFSC: HDFC0002341
Reference: Project Aurora - Confidential

Please process immediately and confirm. Do NOT discuss this with anyone else.
This is a board-level confidential acquisition matter.

Regards,
Rajesh Kumar
CEO`
  },
  malware_dropper: {
    label: "🦠 Malware Dropper — Invoice with Macro",
    risk: "high",
    raw: `From: billing@invoices-portal.xyz
To: accounts@victim-company.com
Subject: Invoice #INV-2026-8821 - Payment Required
Date: Wed, 02 Sep 2026 22:45:00 +0000
Message-ID: <INV8821.20260902@invoices-portal.xyz>
MIME-Version: 1.0
X-Mailer: PHPMailer 6.1
X-Originating-IP: 91.219.236.14
Content-Type: multipart/mixed; boundary="=_NextPart_000_0074"
Received: from invoices-portal.xyz (91.219.236.14) by mx.victim-company.com
 with SMTP; Wed, 02 Sep 2026 22:45:00 +0000
Authentication-Results: mx.victim-company.com; spf=pass smtp.mailfrom=billing@invoices-portal.xyz;
 dkim=pass header.d=invoices-portal.xyz; dmarc=pass

Please find attached invoice INV-2026-8821 for services rendered.
Total Amount Due: INR 1,25,000
Due Date: 10 Sep 2026

Please enable macros when opening the document to view the full invoice.
Download also from: http://91.219.236.14/malware/invoice_macro.docm

[Attachment: Invoice_INV2026-8821.docm, 1.2MB]`
  }
};

const DEMO_INVESTIGATIONS = [
  { id: "MF-2026-0089", email: "security-alert@hdfcbank-secure.co.in", subject: "[URGENT] Your HDFC NetBanking Account Has Been Suspended", risk: "critical", type: "Phishing / Credential Harvest", date: "2026-09-03 08:14", status: "confirmed", score: 94 },
  { id: "MF-2026-0088", email: "rajesh.kumar@company-corp.net", subject: "Urgent Wire Transfer Required - Confidential", risk: "critical", type: "BEC / CEO Fraud", date: "2026-09-03 14:32", status: "confirmed", score: 91 },
  { id: "MF-2026-0087", email: "billing@invoices-portal.xyz", subject: "Invoice #INV-2026-8821 - Payment Required", risk: "high", type: "Malware / Dropper", date: "2026-09-02 22:45", status: "confirmed", score: 78 },
  { id: "MF-2026-0086", email: "noreply@paypal-update.support", subject: "Action Required: Verify Your PayPal Account", risk: "high", type: "Brand Impersonation", date: "2026-09-02 11:20", status: "review", score: 72 },
  { id: "MF-2026-0085", email: "hr@company.com", subject: "Updated Benefits Package - Please Review", risk: "medium", type: "Spear Phishing", date: "2026-09-01 16:05", status: "review", score: 48 },
  { id: "MF-2026-0084", email: "newsletter@legitimatestore.com", subject: "Your Weekly Newsletter - September 2026", risk: "low", type: "Spam", date: "2026-09-01 09:00", status: "cleared", score: 12 },
  { id: "MF-2026-0083", email: "support@microsoft-helpdesk.info", subject: "Critical Windows Security Update Required", risk: "critical", type: "Tech Support Scam", date: "2026-08-31 14:22", status: "confirmed", score: 88 },
  { id: "MF-2026-0082", email: "amazon-orders@amzon-shipping.net", subject: "Your Amazon Order Has Been Delayed", risk: "high", type: "Brand Impersonation", date: "2026-08-30 19:44", status: "confirmed", score: 76 }
];

const THREAT_INTEL_DB = {
  maliciousDomains: ["hdfcbank-secure.co.in","company-corp.net","invoices-portal.xyz","paypal-update.support","microsoft-helpdesk.info","amzon-shipping.net","hdfc-secure-verify.co.in","secure-banklogin.net","verify-account.xyz"],
  maliciousIPs: ["185.234.219.47","45.141.86.100","91.219.236.14","103.21.244.0","194.165.16.78","5.188.206.14"],
  suspiciousPatterns: ["enable macros","urgent wire transfer","account suspended","verify immediately","do not discuss","confidential acquisition","click here to verify","permanent closure","limited time","act now"]
};

const GEO_DB = {
  "185.234.219.47": { country: "Russia", city: "Moscow", lat: 55.7558, lon: 37.6173, asn: "AS206728", org: "Media Land LLC", flag: "🇷🇺", risk: "critical" },
  "45.141.86.100":  { country: "Netherlands", city: "Amsterdam", lat: 52.3676, lon: 4.9041, asn: "AS9009", org: "M247 Ltd", flag: "🇳🇱", risk: "high" },
  "91.219.236.14":  { country: "Ukraine", city: "Kyiv", lat: 50.4501, lon: 30.5234, asn: "AS196695", org: "OOO Network of data-centers", flag: "🇺🇦", risk: "critical" },
  "103.21.244.0":   { country: "India", city: "Mumbai", lat: 19.0760, lon: 72.8777, asn: "AS13335", org: "Cloudflare India", flag: "🇮🇳", risk: "medium" },
  "194.165.16.78":  { country: "Moldova", city: "Chisinau", lat: 47.0105, lon: 28.8638, asn: "AS198385", org: "AlexHost SRL", flag: "🇲🇩", risk: "critical" },
  "8.8.8.8":        { country: "United States", city: "Mountain View", lat: 37.3861, lon: -122.0839, asn: "AS15169", org: "Google LLC", flag: "🇺🇸", risk: "low" }
};

const DOMAIN_INTEL = {
  "hdfcbank-secure.co.in": { registrar: "GoDaddy LLC", created: "2026-08-15", expires: "2027-08-15", age_days: 19, nameservers: ["ns1.freenom.com","ns2.freenom.com"], risk: "critical", categories: ["Typosquatting","Brand Impersonation"], similar_to: "hdfcbank.com", virustotal_detections: "41/87" },
  "company-corp.net":      { registrar: "Namecheap Inc", created: "2026-07-22", expires: "2027-07-22", age_days: 43, nameservers: ["dns1.registrar-servers.com"], risk: "high", categories: ["Newly Registered","BEC Infrastructure"], similar_to: null, virustotal_detections: "18/87" },
  "invoices-portal.xyz":   { registrar: "Tucows Inc", created: "2026-06-10", expires: "2027-06-10", age_days: 85, nameservers: ["ns1.parkingcrew.net"], risk: "high", categories: ["Generic Name","Malware Hosting"], similar_to: null, virustotal_detections: "22/87" },
  "hdfc-secure-verify.co.in": { registrar: "BigRock", created: "2026-08-20", expires: "2027-08-20", age_days: 14, nameservers: ["ns1.bigrock.in"], risk: "critical", categories: ["Typosquatting","Phishing"], similar_to: "hdfcbank.com", virustotal_detections: "38/87" }
};

const CHART_DATA = {
  threatTrend: {
    labels: ["Aug 27","Aug 28","Aug 29","Aug 30","Aug 31","Sep 1","Sep 2","Sep 3"],
    critical: [2,4,1,5,3,2,4,3],
    high:     [5,3,7,4,6,8,5,4],
    medium:   [8,10,6,9,7,5,9,7],
    low:      [3,5,4,2,6,3,4,5]
  },
  typeBreakdown: {
    labels: ["Phishing","BEC","Malware","Brand Impersonation","Spam","Tech Scam"],
    values: [35,18,22,15,7,3]
  }
};

window.MAILFORENSICS_DATA = { DEMO_EMAILS, DEMO_INVESTIGATIONS, THREAT_INTEL_DB, GEO_DB, DOMAIN_INTEL, CHART_DATA };
