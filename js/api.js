// ============================================================
// GmailGuard — Centralized Frontend API Client
// Handles baseURL resolution, HTTP requests, timeouts, and errors
// ============================================================

class GmailGuardAPIClient {
  constructor() {
    this.baseUrl = this._resolveBaseUrl();
    this.timeoutMs = 120000; // 2-minutes timeout for multi-step forensic analysis
  }

  _resolveBaseUrl() {
    // 1. Explicit window override if provided by host environment
    if (window.GMAILGUARD_API_URL) {
      return window.GMAILGUARD_API_URL.replace(/\/+$/, '');
    }

    // 2. If served directly by FastAPI (e.g. http://localhost:8000/)
    if (window.location.port === '8000' || window.location.pathname.startsWith('/api')) {
      return '';
    }

    // 3. If served by static dev server (e.g. port 3000 or 5173 on localhost)
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
      return 'http://127.0.0.1:8000';
    }

    // 4. Default to relative root
    return '';
  }

  async _fetchWithTimeout(url, options = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeoutMs || this.timeoutMs);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal
      });
      clearTimeout(timeout);
      return response;
    } catch (err) {
      clearTimeout(timeout);
      if (err.name === 'AbortError') {
        throw new Error('Analysis request timed out after 2 minutes. The backend may be processing heavy external intelligence.');
      }
      throw new Error(`Network error: Unable to connect to GmailGuard backend at ${this.baseUrl || 'local server'}.`);
    }
  }

  /**
   * Service health check
   * @returns {Promise<{ ok: boolean, data?: object, error?: string }>}
   */
  async checkHealth() {
    try {
      const res = await this._fetchWithTimeout(`${this.baseUrl}/health`, {
        method: 'GET',
        timeoutMs: 12000
      });
      if (res.ok) {
        const data = await res.json();
        return { ok: true, data };
      }
      return { ok: false, error: `Health check returned HTTP ${res.status}` };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  /**
   * Upload and analyze a raw .eml file
   * @param {File} file
   * @returns {Promise<object>} Threat Report JSON
   */
  async analyzeEmailFile(file) {
    if (!file) {
      throw new Error('No email file provided.');
    }
    if (file.size === 0) {
      throw new Error('Uploaded email file is empty (0 bytes).');
    }
    if (file.size > 25 * 1024 * 1024) {
      throw new Error('Uploaded file exceeds the maximum 25 MB size limit.');
    }

    const formData = new FormData();
    formData.append('file', file);

    const res = await this._fetchWithTimeout(`${this.baseUrl}/analyze`, {
      method: 'POST',
      body: formData
    });

    return this._handleResponse(res);
  }

  /**
   * Analyze raw RFC 5322 email string
   * @param {string} rawEmail
   * @returns {Promise<object>} Threat Report JSON
   */
  async analyzeEmailText(rawEmail) {
    if (!rawEmail || !rawEmail.trim()) {
      throw new Error('Email content is empty. Please provide RFC 5322 email text with headers.');
    }
    if (rawEmail.length < 15) {
      throw new Error('Provided email text is too short to constitute a valid RFC 5322 message.');
    }

    const res = await this._fetchWithTimeout(`${this.baseUrl}/analyze-text`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        raw_email: rawEmail,
        email_text: rawEmail
      })
    });

    return this._handleResponse(res);
  }

  async _handleResponse(response) {
    if (response.ok) {
      return await response.json();
    }

    let detail = `HTTP ${response.status} ${response.statusText}`;
    try {
      const errJson = await response.json();
      if (errJson.detail) {
        if (typeof errJson.detail === 'string') {
          detail = errJson.detail;
        } else if (Array.isArray(errJson.detail)) {
          detail = errJson.detail.map(d => d.msg || JSON.stringify(d)).join('; ');
        }
      }
    } catch (_) {
      // Body was not JSON
    }

    if (response.status === 413) {
      throw new Error(`Payload Too Large: ${detail}`);
    } else if (response.status === 422) {
      throw new Error(`Validation Error: ${detail}`);
    } else if (response.status === 400) {
      throw new Error(`Bad Request: ${detail}`);
    } else if (response.status === 500) {
      throw new Error(`Backend Pipeline Error: ${detail}`);
    }

    throw new Error(`Analysis Failed (${response.status}): ${detail}`);
  }

  /**
   * Check Gemini AI service readiness
   * @returns {Promise<{ configured: boolean, available: boolean, candidate_models: string[] }>}
   */
  async checkGeminiStatus() {
    try {
      const res = await this._fetchWithTimeout(`${this.baseUrl}/api/gemini/status`, {
        method: 'GET',
        timeoutMs: 8000
      });
      if (res.ok) {
        return await res.json();
      }
      return { configured: false, available: false, candidate_models: [] };
    } catch (_) {
      return { configured: false, available: false, candidate_models: [] };
    }
  }

  /**
   * On-demand Gemini AI contextual security analysis
   * @param {string} rawEmail
   * @param {object} report
   * @returns {Promise<object>} Gemini AI analysis result
   */
  async analyzeWithGemini(rawEmail = '', report = null) {
    const res = await this._fetchWithTimeout(`${this.baseUrl}/api/gemini/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        raw_email: rawEmail || '',
        report: report || null
      }),
      timeoutMs: 45000
    });
    return this._handleResponse(res);
  }

  /**
   * Get aggregate Gemini mailbox security overview
   * @returns {Promise<object>} Overview statistics
   */
  async getGeminiOverview() {
    const res = await this._fetchWithTimeout(`${this.baseUrl}/api/gemini/overview`, {
      method: 'GET',
      timeoutMs: 15000
    });
    return this._handleResponse(res);
  }

  /**
   * Get Gmail connection status
   * @returns {Promise<object>} Connection status
   */
  async getGmailStatus() {
    const res = await this._fetchWithTimeout(`${this.baseUrl}/api/gmail/status`, {
      method: 'GET',
      timeoutMs: 10000
    });
    return this._handleResponse(res);
  }

  /**
   * Get Google OAuth 2.0 Authorization URL
   * @param {string} [redirectUri]
   * @returns {Promise<{ auth_url: string, state: string }>}
   */
  async getGmailAuthUrl(redirectUri = '') {
    const url = redirectUri
      ? `${this.baseUrl}/api/gmail/auth-url?redirect_uri=${encodeURIComponent(redirectUri)}`
      : `${this.baseUrl}/api/gmail/auth-url`;
    const res = await this._fetchWithTimeout(url, {
      method: 'GET',
      timeoutMs: 10000
    });
    return this._handleResponse(res);
  }

  /**
   * Disconnect Gmail account
   * @returns {Promise<object>}
   */
  async disconnectGmail() {
    const res = await this._fetchWithTimeout(`${this.baseUrl}/api/gmail/disconnect`, {
      method: 'POST',
      timeoutMs: 10000
    });
    return this._handleResponse(res);
  }

  /**
   * Fetch user messages from Gmail inbox
   * @param {number} [maxResults=25]
   * @param {string} [query='']
   * @param {string} [pageToken='']
   * @returns {Promise<object>} Messages list
   */
  async getGmailMessages(maxResults = 25, query = '', pageToken = '') {
    const params = new URLSearchParams();
    if (maxResults) params.set('max_results', String(maxResults));
    if (query) params.set('query', query);
    if (pageToken) params.set('page_token', pageToken);

    const res = await this._fetchWithTimeout(`${this.baseUrl}/api/gmail/messages?${params.toString()}`, {
      method: 'GET',
      timeoutMs: 25000
    });
    return this._handleResponse(res);
  }

  /**
   * Run full forensic pipeline + Gemini analysis on specific Gmail message
   * @param {string} messageId
   * @param {boolean} [reanalyze=false]
   * @returns {Promise<object>} Full threat report JSON
   */
  async analyzeGmailMessage(messageId, reanalyze = false) {
    const res = await this._fetchWithTimeout(
      `${this.baseUrl}/api/gmail/analyze/${encodeURIComponent(messageId)}?reanalyze=${reanalyze}`,
      {
        method: 'POST',
        timeoutMs: 120000
      }
    );
    return this._handleResponse(res);
  }

  /**
   * Get cached analysis for Gmail message
   * @param {string} messageId
   * @returns {Promise<object>} Cached report
   */
  async getGmailAnalysis(messageId) {
    const res = await this._fetchWithTimeout(
      `${this.baseUrl}/api/gmail/analysis/${encodeURIComponent(messageId)}`,
      {
        method: 'GET',
        timeoutMs: 15000
      }
    );
    return this._handleResponse(res);
  }
}

// Global singleton instance
window.GmailGuardAPI = new GmailGuardAPIClient();
