// ============================================================
// GmailGuard — Centralized Frontend API Client
// Handles baseURL resolution, HTTP requests, timeouts, and errors
// ============================================================

class GmailGuardAPIClient {
  constructor() {
    this.baseUrl = this._resolveBaseUrl();
    this.timeoutMs = 20000; // 20-second timeout for multi-step forensic analysis
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
        throw new Error('Analysis request timed out after 20 seconds. The backend may be processing heavy external intelligence.');
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
        timeoutMs: 4000
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
}

// Global singleton instance
window.GmailGuardAPI = new GmailGuardAPIClient();
