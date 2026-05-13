/**
 * IA-Seguridad — Popup Script
 */
(function() {
  'use strict';

  const API_BASE = 'http://localhost:8000';

  // State
  let sessionId = null;
  let emails = [];
  let analysisResults = {};
  let pkceVerifier = null;

  // DOM elements
  const loginSection = document.getElementById('loginSection');
  const mainSection = document.getElementById('mainSection');
  const errorSection = document.getElementById('errorSection');
  const errorMessage = document.getElementById('errorMessage');
  const userInfo = document.getElementById('userInfo');
  const userEmail = document.getElementById('userEmail');
  const emailList = document.getElementById('emailList');
  const loginBtn = document.getElementById('loginBtn');
  const logoutBtn = document.getElementById('logoutBtn');
  const refreshBtn = document.getElementById('refreshBtn');

  // Badge counters
  const safeCount = document.getElementById('safeCount');
  const suspiciousCount = document.getElementById('suspiciousCount');
  const phishingCount = document.getElementById('phishingCount');

  // Init
  init();

  async function init() {
    // Check ia_seguridad_session (saved after successful auth)
    const stored = await chrome.storage.local.get('ia_seguridad_session');
    const session = stored.ia_seguridad_session;

    if (session && session.sessionId) {
      // Verify session with backend using session_id
      const sid = session.sessionId;
      try {
        const resp = await fetch(`${API_BASE}/auth/session/${sid}`);
        if (resp.ok) {
          const data = await resp.json();
          if (data.valid) {
            sessionId = sid;
            userEmail.textContent = data.email || sid.substring(0, 8);
            showMainSection();
            loadEmails();
            return;
          }
        }
      } catch(e) {}

      // Session invalid/expired — clear it
      await chrome.storage.local.remove('ia_seguridad_session');
    }

    showLoginSection();
    loginBtn.addEventListener('click', handleLogin);
    logoutBtn.addEventListener('click', handleLogout);
    refreshBtn.addEventListener('click', loadEmails);
  }

  function showLoginSection() {
    loginSection.style.display = 'block';
    mainSection.style.display = 'none';
    errorSection.style.display = 'none';
    userInfo.style.display = 'none';
  }

  function showMainSection() {
    loginSection.style.display = 'none';
    mainSection.style.display = 'block';
    errorSection.style.display = 'none';
    userInfo.style.display = 'flex';
  }

  function showError(msg) {
    loginSection.style.display = 'none';
    mainSection.style.display = 'none';
    errorSection.style.display = 'block';
    errorMessage.textContent = msg;
  }

  function updateStats() {
    var results = Object.values(analysisResults);
    var safe = 0, suspicious = 0, phishing = 0;
    results.forEach(function(r) {
      if (r.verdict === 'safe') safe++;
      else if (r.verdict === 'suspicious') suspicious++;
      else if (r.verdict === 'phishing') phishing++;
    });
    safeCount.textContent = safe;
    suspiciousCount.textContent = suspicious;
    phishingCount.textContent = phishing;
  }

  async function loadEmails() {
    emailList.innerHTML = '<div class="loading">Cargando emails...</div>';

    const resp = await chrome.runtime.sendMessage({ type: 'GET_EMAILS' });

    if (!resp) {
      showError('Error de conexión con el service worker');
      return;
    }

    if (resp.error) {
      if (resp.error.includes('autenticado') || resp.error.includes('No autenticado')) {
        sessionId = null;
        showLoginSection();
        return;
      }
      showError(resp.error);
      return;
    }

    if (!Array.isArray(resp)) {
      // Backend may return { emails: [...] }
      if (resp && Array.isArray(resp.emails)) {
        emails = resp.emails;
        renderEmailList();
        return;
      }
      showError('Error inesperado: respuesta inválida del servidor');
      return;
    }

    emails = resp;
    renderEmailList();
  }

  function renderEmailList() {
    emailList.innerHTML = '';

    if (!emails) {
      emailList.innerHTML = '<div class="loading">No hay emails</div>';
      return;
    }

    const emailArray = Array.isArray(emails) ? emails : (emails.emails || []);
    if (emailArray.length === 0) {
      emailList.innerHTML = '<div class="loading">No hay emails</div>';
      return;
    }

    emailArray.forEach(function(email) {
      const result = analysisResults[email.id];
      const verdictClass = result?.verdict || 'not-analyzed';

      const item = document.createElement('div');
      item.className = `email-item ${verdictClass}`;
      item.dataset.emailId = email.id;

      var indicatorsList = (result && result.indicators && result.indicators.length)
        ? result.indicators.map(function(i) { return '<li>' + escapeHtml(i) + '</li>'; }).join('')
        : '';
      var indicatorsBlock = indicatorsList
        ? '<div class="indicators-list"><strong>Indicadores:</strong><ul>' + indicatorsList + '</ul></div>'
        : '';

      var urlsBlock = '';
      if (result && result.urls_analyzed && result.urls_analyzed.length) {
        var maliciousUrls = result.urls_analyzed.filter(function(u) { return u.malicious; });
        urlsBlock = '<div style="margin-top:6px;font-size:10px;"><strong>URLs verificadas:</strong> ' + result.urls_analyzed.length + ' ' +
          maliciousUrls.map(function(u) {
            return '<span style="color:#dc3545;"> ⚠️ ' + escapeHtml(u.url) + '</span>';
          }).join('') + '</div>';
      }

      item.innerHTML =
        '<div class="email-from">' + escapeHtml(email.from || email.fromEmail || 'Desconocido') + '</div>' +
        '<div class="email-subject">' + escapeHtml(email.subject || '(Sin asunto)') + '</div>' +
        '<div class="email-snippet">' + escapeHtml(email.snippet || '') + '</div>' +
        '<div class="email-badge ' + verdictClass + '">' + getBadgeIcon(result && result.verdict) + '</div>' +
        '<div class="email-detail" id="detail-' + email.id + '">' +
          '<div class="email-detail-header">' +
            '<span class="verdict-badge ' + verdictClass + '">' + getVerdictLabel(result && result.verdict) + '</span>' +
          '</div>' +
          (result ? (
            '<div class="analysis-result ' + result.verdict + '">' +
              '<div>' + escapeHtml(result.reason || '') + '</div>' +
              (result.confidence > 0 ? (
                '<div style="font-size:10px;color:#6c757d;margin-top:4px;">' +
                  'Confianza: ' + (result.confidence * 100).toFixed(0) + '%' +
                '</div>' +
                '<div class="confidence-bar">' +
                  '<div class="confidence-fill" style="width:' + (result.confidence * 100) + '%"></div>' +
                '</div>'
              ) : '') +
              indicatorsBlock +
              urlsBlock +
            '</div>'
          ) : '') +
          '<button class="analyze-btn" data-id="' + email.id + '" data-subject="' + escapeAttr(email.subject || '') + '" data-from="' + escapeAttr(email.from || email.fromEmail || '') + '" data-body="' + escapeAttr(email.body || email.body_plain || '') + '">' +
            (result ? '↻ Analizar de nuevo' : '🔍 Analizar') +
          '</button>' +
        '</div>';

      // Toggle detail on click
      item.addEventListener('click', function(e) {
        if (e.target.tagName === 'BUTTON') return;
        var detail = document.getElementById('detail-' + email.id);
        if (detail) detail.classList.toggle('open');
      });

      // Analyze button
      var analyzeBtn = item.querySelector('.analyze-btn');
      analyzeBtn.addEventListener('click', function(e) {
        e.stopPropagation();
        handleAnalyze(email, analyzeBtn);
      });

      emailList.appendChild(item);
    });
  }

  async function handleAnalyze(email, btn) {
    btn.disabled = true;
    btn.textContent = '🔄 Analizando...';

    var badge = btn.closest('.email-item').querySelector('.email-badge');
    badge.className = 'email-badge analyzing';
    badge.textContent = '⏳';

    try {
      var result = await chrome.runtime.sendMessage({
        type: 'ANALYZE',
        emailId: email.id,
        emailSubject: email.subject,
        emailSender: email.from,
        emailBody: email.body || email.body_plain || ''
      });

      if (!result || result.error) {
        btn.textContent = '⚠️ Error';
        badge.className = 'email-badge review_needed';
        badge.textContent = '?';
        return;
      }

      analysisResults[email.id] = result;
      updateStats();
      renderEmailList();

      // Re-open the detail
      var detail = document.getElementById('detail-' + email.id);
      if (detail) detail.classList.add('open');

    } catch (e) {
      btn.textContent = '⚠️ Error';
      btn.disabled = false;
      badge.className = 'email-badge review_needed';
      badge.textContent = '?';
    }
  }

  async function handleLogin() {
    loginBtn.disabled = true;
    loginBtn.textContent = 'Abriendo Google...';

    try {
      const resp = await fetch(`${API_BASE}/auth/gmail/login`);
      if (!resp.ok) throw new Error('No se pudo iniciar auth');

      const data = await resp.json();

      // Save session ID — will be verified when user reopens popup
      await chrome.storage.local.set({
        ia_seguridad_session: { sessionId: data.session_id, email: '' }
      });

      window.open(data.auth_url, 'gmail_auth', 'width=500,height=600,left=100,top=100');
      loginBtn.textContent = '✅ Autorizado — cerrá esta pestaña';

    } catch (e) {
      loginBtn.disabled = false;
      loginBtn.textContent = 'Conectar con Gmail';
      showError(e.message);
    }
  }

  async function handleLogout() {
    await chrome.runtime.sendMessage({ type: 'LOGOUT' });
    sessionId = null;
    emails = [];
    analysisResults = {};
    updateStats();
    showLoginSection();
  }

  // Helpers
  function getBadgeIcon(verdict) {
    switch (verdict) {
      case 'safe': return '✓';
      case 'suspicious': return '⚠';
      case 'phishing': return '✕';
      default: return '?';
    }
  }

  function getVerdictLabel(verdict) {
    switch (verdict) {
      case 'safe': return '✓ Seguro';
      case 'suspicious': return '⚠ Sospechoso';
      case 'phishing': return '✕ Phishing';
      default: return '? Sin analizar';
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function escapeAttr(str) {
    if (!str) return '';
    return str.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

})();