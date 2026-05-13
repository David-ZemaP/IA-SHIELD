/**
 * IA-Seguridad — Chrome Extension Service Worker (MV3)
 * - Poll Gmail API cada 60 segundos
 * - Actualiza badge con count de amenazas
 * - Maneja mensajes del popup
 * - Token refresh via backend
 */

// Config
const API_BASE = 'http://localhost:8000';
const POLL_INTERVAL_MS = 60 * 1000; // 60 segundos
const SESSION_KEY = 'ia_seguridad_session';

// Badge colors
const BADGE_COLORS = {
  phishing: '#dc3545',    // rojo
  suspicious: '#ffc107',  // amarillo
  safe: '#28a745',        // verde
  review_needed: '#6c757d' // gris
};

// Estado en memoria
let currentSession = null;
let lastAnalysisResults = {};

/**
 * Inicialización del service worker
 */
chrome.runtime.onInstalled.addListener(() => {
  console.log('[IA-Seg] Extensión instalada');
  chrome.alarms.create('pollGmail', { periodInMinutes: 1 });
});

/**
 * Manejar alarmas (polling)
 */
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'pollGmail') {
    refreshEmails();
  }
});

/**
 * Refresh emails y actualizar badge
 */
async function refreshEmails() {
  if (!currentSession) return;

  try {
    const emails = await fetchEmails(currentSession.sessionId);

    // Contar amenazas
    const threats = emails.filter(e =>
      lastAnalysisResults[e.id]?.verdict === 'phishing' ||
      lastAnalysisResults[e.id]?.verdict === 'suspicious'
    ).length;

    // Actualizar badge
    chrome.action.setBadgeText({ text: threats > 0 ? String(threats) : '' });
    chrome.action.setBadgeBackgroundColor({
      color: threats > 0 ? BADGE_COLORS.suspicious : '#28a745'
    });
  } catch (e) {
    console.error('[IA-Seg] Error en polling:', e);
  }
}

/**
 * Fetch emails desde backend
 */
async function fetchEmails(sessionId) {
  const response = await fetch(`${API_BASE}/emails`, {
    headers: { 'X-Session-ID': sessionId }
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

/**
 * Actualizar badge según resultados
 */
function updateBadge() {
  const verdicts = Object.values(lastAnalysisResults);
  const phishing = verdicts.filter(v => v.verdict === 'phishing').length;
  const suspicious = verdicts.filter(v => v.verdict === 'suspicious').length;
  const total = phishing + suspicious;

  chrome.action.setBadgeText({ text: total > 0 ? String(total) : '' });
  chrome.action.setBadgeBackgroundColor({
    color: phishing > 0 ? BADGE_COLORS.phishing :
           suspicious > 0 ? BADGE_COLORS.suspicious :
           BADGE_COLORS.safe
  });
}

/**
 * Mensajes desde popup
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sendResponse);
  return true; // async response
});

async function handleMessage(message, sendResponse) {
  switch (message.type) {
    case 'GET_SESSION': {
      const stored = await chrome.storage.local.get('ia_seguridad_session');
      if (stored.ia_seguridad_session) {
        currentSession = stored.ia_seguridad_session;
      }
      sendResponse({ sessionId: currentSession?.sessionId || null, email: currentSession?.email || null });
      break;
    }
    case 'LOGOUT':
      handleLogout();
      sendResponse({ ok: true });
      break;
    case 'GET_EMAILS': {
      // Read fresh session from storage every time
      const stored = await chrome.storage.local.get('ia_seguridad_session');
      if (!stored.ia_seguridad_session?.sessionId) {
        sendResponse({ error: 'No autenticado' });
        return;
      }
      currentSession = stored.ia_seguridad_session;
      try {
        const emails = await fetchEmails(currentSession.sessionId);
        sendResponse(emails);
      } catch (e) {
        sendResponse({ error: e.message });
      }
      break;
    }
    case 'ANALYZE': {
      // Read fresh session from storage every time
      const stored = await chrome.storage.local.get('ia_seguridad_session');
      if (!stored.ia_seguridad_session || !stored.ia_seguridad_session.sessionId) {
        sendResponse({ error: 'No autenticado' });
        return;
      }
      currentSession = stored.ia_seguridad_session;
      try {
        // Fetch full email body before analyzing
        var emailBody = message.emailBody || '';
        if (!emailBody && message.emailId) {
          try {
            var emailResp = await fetch(`${API_BASE}/emails/${message.emailId}`, {
              headers: { 'X-Session-ID': currentSession.sessionId }
            });
            if (emailResp.ok) {
              var emailData = await emailResp.json();
              emailBody = emailData.body_plain || emailData.body_html || emailData.snippet || '';
            } else {
              console.log('[IA-Seg] Could not fetch email detail:', emailResp.status);
            }
          } catch(e) {
            console.log('[IA-Seg] Error fetching email detail:', e.message);
          }
        }

        var analysisResult = await analyzeEmail(
          message.emailId,
          message.emailSubject,
          message.emailSender,
          emailBody
        );
        lastAnalysisResults[message.emailId] = analysisResult;
        updateBadge();
        sendResponse(analysisResult);
      } catch (e) {
        console.log('[IA-Seg] Analyze error:', e.message);
        sendResponse({ error: 'Error en análisis: ' + e.message });
      }
      break;
    }
    case 'GET_AUTH_URL':
      try {
        const data = await fetchAuthUrl();
        sendResponse(data);
      } catch (e) {
        sendResponse({ error: e.message });
      }
      break;
    default:
      sendResponse({ error: 'Unknown message type' });
  }
}

/**
 * Login — the popup handles the OAuth flow.
 * This just opens the callback page which communicates via storage.
 */
async function handleLogin() {
  const callbackUrl = chrome.runtime.getURL('auth-callback.html');
  window.open(callbackUrl, 'ia_auth', 'width=500,height=600,left=100,top=100');
  return { message: 'popup_opened' };
}

/**
 * Logout
 */
async function handleLogout() {
  currentSession = null;
  lastAnalysisResults = {};
  await chrome.storage.local.remove([SESSION_KEY, 'pkce_verifier']);
  chrome.action.setBadgeText({ text: '' });
}

/**
 * Obtener URL de autorización
 */
async function fetchAuthUrl() {
  const response = await fetch(`${API_BASE}/auth/gmail/login`);
  if (!response.ok) throw new Error('No se pudo obtener URL de auth');
  return response.json();
}

/**
 * Analizar email
 */
async function analyzeEmail(emailId, subject, sender, body) {
  const response = await fetch(`${API_BASE}/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Session-ID': currentSession?.sessionId || ''
    },
    body: JSON.stringify({
      email_id: emailId,
      email_subject: subject,
      email_sender: sender,
      email_body: body,
      check_urls: true
    })
  });

  if (!response.ok) {
    const err = await response.json();
    throw new Error(err.detail || 'Análisis falló');
  }

  return response.json();
}