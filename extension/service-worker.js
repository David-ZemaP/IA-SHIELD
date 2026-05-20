/**
 * IA-Seguridad — Chrome Extension Service Worker (MV3)
 * - Poll Gmail API cada 60 segundos
 * - Actualiza badge con count de amenazas
 * - Maneja mensajes del popup
 * - Token refresh via backend
 * - Análisis automático con Gemini
 **/

// Cargar resultados previos desde storage al iniciar
chrome.storage.local.get('ia_seguridad_results').then(stored => {
  if (stored.ia_seguridad_results) {
    console.log('[IA-Seg] Loaded previous results from storage:', Object.keys(stored.ia_seguridad_results).length, 'emails');
    lastAnalysisResults = stored.ia_seguridad_results;
    updateBadge();
  }
}).catch(e => console.log('[IA-Seg] Could not load previous results:', e));

// Ejecutar análisis automáticamente al cargar
console.log(
  "[IA-Seg] Service worker cargado, iniciando análisis automático...",
);
setTimeout(() => {
  refreshEmails().catch(e => {
    console.error('[IA-Seg] Initial refresh error:', e.message, e.stack);
  });
}, 2000); // Esperar 2 segundos a que cargue todo

// Config
const API_BASE = "http://localhost:8000";
const POLL_INTERVAL_MS = 60 * 1000; // 60 segundos
const SESSION_KEY = "ia_seguridad_session";

// Badge colors
const BADGE_COLORS = {
  phishing: "#dc3545", // rojo
  suspicious: "#ffc107", // amarillo
  safe: "#28a745", // verde
  review_needed: "#6c757d", // gris
};

// Estado en memoria
let currentSession = null;
let lastAnalysisResults = {};

/**
 * Inicialización del service worker
 */
chrome.runtime.onInstalled.addListener(() => {
  console.log("[IA-Seg] Extensión instalada");
  chrome.alarms.create("pollGmail", { periodInMinutes: 1 });
});

// También ejecutar cuando se rearranca el service worker (cada vez que se recarga)
chrome.runtime.onStartup.addListener(() => {
  console.log("[IA-Seg] Extensión iniciada");
  // Ejecutar análisis inmediatamente
  refreshEmails().catch(e => {
    console.error('[IA-Seg] Startup refresh error:', e.message, e.stack);
  });
  // Crear alarm si no existe
  chrome.alarms.get("pollGmail", (alarm) => {
    if (!alarm) {
      chrome.alarms.create("pollGmail", { periodInMinutes: 1 });
    }
  });
});

/**
 * Manejar alarmas (polling)
 */
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "pollGmail") {
    console.log('[IA-Seg] Alarm triggered, starting polling...');
    refreshEmails().catch(e => {
      console.error('[IA-Seg] Alarm handler error:', e.message, e.stack);
    });
  }
});

/**
 * Refresh emails y actualizar badge — ANÁLISIS AUTOMÁTICO
 * Compara emails nuevos vs analizados y los envía a Gemini automáticamente
 **/
async function refreshEmails() {
  // Read fresh session from storage every time
  const stored = await chrome.storage.local.get("ia_seguridad_session");
  if (!stored.ia_seguridad_session?.sessionId) {
    console.log("[IA-Seg] No session found");
    return;
  }
  currentSession = stored.ia_seguridad_session;

  if (!currentSession.sessionId) {
    console.log("[IA-Seg] Session ID missing");
    return;
  }

  try {
    let emails;
    try {
      emails = await fetchEmails(currentSession.sessionId);
    } catch (e) {
      console.error("[IA-Seg] Error fetching emails:", e.message);
      return;
    }

    // Handle error response or missing emails
    if (!emails || emails.error) {
      console.log("[IA-Seg] No emails or error:", emails?.error);
      return;
    }

    const emailList = emails.emails || [];
    console.log(`[IA-Seg] Polling: ${emailList.length} emails received`);

    // Get already analyzed email IDs from storage
    const storedResults = await chrome.storage.local.get(
      "ia_seguridad_analyzed",
    );
    const analyzedIds = new Set(storedResults.ia_seguridad_analyzed || []);

    // Find NEW emails that haven't been analyzed yet
    const newEmails = emailList.filter(
      (e) => e && e.id && !analyzedIds.has(e.id),
    );

    console.log(
      `[IA-Seg] ${newEmails.length} new emails to analyze automatically`,
    );

    // Analyze new emails automatically
    const analysisResults = [];
    const emailsToAnalyze = newEmails.slice(0, 10); // Max 10 per cycle

    for (const email of emailsToAnalyze) {
      if (!email || !email.id) {
        console.log("[IA-Seg] Skipping invalid email:", email);
        continue;
      }
      try {
        // Fetch full email body for analysis
        let emailBody = email.snippet || "";
        try {
          const emailDetail = await fetchEmailDetail(email.id);
          if (emailDetail) {
            emailBody =
              emailDetail.body_plain ||
              emailDetail.body_html ||
              email.snippet ||
              "";
          }
        } catch (e) {
          console.log(
            `[IA-Seg] Could not fetch detail for ${email.id}:`,
            e.message,
          );
        }

        // Analyze with Gemini
        let result;
        try {
          result = await analyzeEmail(
            email.id,
            email.subject,
            email.from,
            emailBody,
          );
        } catch (e) {
          console.error(`[IA-Seg] analyzeEmail failed for ${email.id}:`, e);
          continue;
        }

        if (!result || !result.verdict) {
          console.error(`[IA-Seg] Invalid result for ${email.id}:`, result);
          continue;
        }

        lastAnalysisResults[email.id] = result;
        analysisResults.push({ id: email.id, verdict: result.verdict });
        
        // Enviar notificación si es phishing de alta confianza
        await sendPhishingNotification({
          email_id: email.id,
          email_subject: email.subject,
          email_sender: email.from,
          verdict: result.verdict,
          confidence: result.confidence
        });

        // Persist results to storage
        try {
          const storedResults = await chrome.storage.local.get('ia_seguridad_results') || {};
          const allResults = storedResults.ia_seguridad_results || {};
          allResults[email.id] = result;
          await chrome.storage.local.set({ ia_seguridad_results: allResults });
        } catch (e) {
          console.log('[IA-Seg] Could not save results to storage:', e.message);
        }

        // Add to analyzed set
        analyzedIds.add(email.id);

        // Rate limiting: wait 500ms between analyses
        await new Promise((r) => setTimeout(r, 500));
      } catch (e) {
        console.log(
          `[IA-Seg] Auto-analysis failed for ${email.id}:`,
          e.message,
        );
      }
    }

    // Save updated analyzed set
    if (analysisResults.length > 0) {
      await chrome.storage.local.set({
        ia_seguridad_analyzed: Array.from(analyzedIds),
      });
      console.log(`[IA-Seg] Analyzed ${analysisResults.length} new emails`);
    }

    // Update badge with current threats
    updateBadge();
  } catch (e) {
    console.error("[IA-Seg] Error en polling:", e.message, e.stack);
  }
}

/**
 * Fetch full email detail
 **/
async function fetchEmailDetail(emailId) {
  const response = await fetch(`${API_BASE}/emails/${emailId}`, {
    headers: { "X-Session-ID": currentSession?.sessionId || "" },
  });
  if (!response.ok) return null;
  return response.json();
}

/**
 * Fetch emails desde backend
 **/
async function fetchEmails(sessionId) {
  console.log(`[IA-Seg] Fetching emails from ${API_BASE}/emails`);
  try {
    const response = await fetch(`${API_BASE}/emails`, {
      headers: { "X-Session-ID": sessionId },
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`[IA-Seg] Email fetch failed: HTTP ${response.status} - ${errorText}`);

      // Si es 401, la sesión expiró
      if (response.status === 401) {
        console.log('[IA-Seg] Session expired, user needs to re-authenticate');
        // Limpiar sesión
        await chrome.storage.local.remove('ia_seguridad_session');
        currentSession = null;
      }

      throw new Error(`HTTP ${response.status}`);
    }

    return response.json();
  } catch (e) {
    console.error('[IA-Seg] fetchEmails exception:', e.message);
    throw e;
  }
}

/**
 * Enviar notificación cuando se detecta phishing de alta confianza
 **/
async function sendPhishingNotification(email) {
  if (email.verdict === "phishing" && email.confidence > 0.8) {
    try {
      // Extraer email del sender para la notificación
      const senderMatch = email.email_sender?.match(/<(.+?)>/) || [null, email.email_sender];
      const senderEmail = senderMatch[1] || email.email_sender || "desconocido";
      
      await chrome.notifications.create({
        type: "basic",
        iconUrl: chrome.runtime.getURL("icons/icon-128.png"),
        title: "🚨 Phishing detectado",
        message: `Email suspicious de: ${senderEmail}\nAsunto: ${email.email_subject?.substring(0, 50)}...`,
        priority: 1
      });
    } catch (e) {
      console.log("[IA-Seg] Notification error:", e.message);
    }
  }
}

/**
 * Actualizar badge según resultados
 **/
function updateBadge() {
  const verdicts = Object.values(lastAnalysisResults);
  const phishing = verdicts.filter((v) => v.verdict === "phishing").length;
  const suspicious = verdicts.filter((v) => v.verdict === "suspicious").length;
  const total = phishing + suspicious;

  chrome.action.setBadgeText({ text: total > 0 ? String(total) : "" });
  chrome.action.setBadgeBackgroundColor({
    color:
      phishing > 0
        ? BADGE_COLORS.phishing
        : suspicious > 0
          ? BADGE_COLORS.suspicious
          : BADGE_COLORS.safe,
  });
}

/**
 * Mensajes desde popup
 **/
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sendResponse);
  return true; // async response
});

async function handleMessage(message, sendResponse) {
  switch (message.type) {
    case "GET_SESSION": {
      const stored = await chrome.storage.local.get("ia_seguridad_session");
      if (stored.ia_seguridad_session) {
        currentSession = stored.ia_seguridad_session;
      }
      sendResponse({
        sessionId: currentSession?.sessionId || null,
        email: currentSession?.email || null,
      });
      break;
    }
    case "LOGOUT":
      handleLogout();
      sendResponse({ ok: true });
      break;
    case "GET_EMAILS": {
      // Read fresh session from storage every time
      const stored = await chrome.storage.local.get("ia_seguridad_session");
      if (!stored.ia_seguridad_session?.sessionId) {
        sendResponse({ error: "No autenticado" });
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
    case "ANALYZE": {
      // Read fresh session from storage every time
      const stored = await chrome.storage.local.get("ia_seguridad_session");
      if (
        !stored.ia_seguridad_session ||
        !stored.ia_seguridad_session.sessionId
      ) {
        sendResponse({ error: "No autenticado" });
        return;
      }
      currentSession = stored.ia_seguridad_session;
      try {
        // Fetch full email body before analyzing
        var emailBody = message.emailBody || "";
        if (!emailBody && message.emailId) {
          try {
            var emailResp = await fetch(
              `${API_BASE}/emails/${message.emailId}`,
              {
                headers: { "X-Session-ID": currentSession.sessionId },
              },
            );
            if (emailResp.ok) {
              var emailData = await emailResp.json();
              emailBody =
                emailData.body_plain ||
                emailData.body_html ||
                emailData.snippet ||
                "";
            } else {
              console.log(
                "[IA-Seg] Could not fetch email detail:",
                emailResp.status,
              );
            }
          } catch (e) {
            console.log("[IA-Seg] Error fetching email detail:", e.message);
          }
        }

        var analysisResult = await analyzeEmail(
          message.emailId,
          message.emailSubject,
          message.emailSender,
          emailBody,
        );
        lastAnalysisResults[message.emailId] = analysisResult;
        updateBadge();
        sendResponse(analysisResult);
      } catch (e) {
        console.log("[IA-Seg] Analyze error:", e.message);
        sendResponse({ error: "Error en análisis: " + e.message });
      }
      break;
    }
    case "GET_AUTH_URL":
      try {
        const data = await fetchAuthUrl();
        sendResponse(data);
      } catch (e) {
        sendResponse({ error: e.message });
      }
      break;
    default:
      sendResponse({ error: "Unknown message type" });
  }
}

/**
 * Login — the popup handles the OAuth flow.
 * This just opens the callback page which communicates via storage.
 **/
async function handleLogin() {
  const callbackUrl = chrome.runtime.getURL("auth-callback.html");
  window.open(callbackUrl, "ia_auth", "width=500,height=600,left=100,top=100");
  return { message: "popup_opened" };
}

/**
 * Logout
 **/
async function handleLogout() {
  currentSession = null;
  lastAnalysisResults = {};
  await chrome.storage.local.remove([SESSION_KEY, "pkce_verifier"]);
  chrome.action.setBadgeText({ text: "" });
}

/**
 * Obtener URL de autorización
 **/
async function fetchAuthUrl() {
  const response = await fetch(`${API_BASE}/auth/gmail/login`);
  if (!response.ok) throw new Error("No se pudo obtener URL de auth");
  return response.json();
}

/**
 * URL BLOCKING - Verifica URLs antes de permitir navegación
 **/
const BLOCKED_URLS_KEY = "ia_seguridad_blocked_domains";

// Listener para interceptar navegación ( clicks en emails)
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only intercept main frame navigations (not iframes)
  if (details.frameId !== 0) return;

  // Get the URL being navigated to
  const targetUrl = details.url;

  // Skip our own extension pages and localhost
  if (
    targetUrl.startsWith("chrome-extension://") ||
    targetUrl.startsWith("http://localhost") ||
    targetUrl.startsWith("about:")
  ) {
    return;
  }

  console.log("[IA-Seg] URL navigation detected:", targetUrl);

  // Check if URL domain is already blocked
  try {
    const stored = await chrome.storage.local.get(BLOCKED_URLS_KEY);
    const blockedDomains = stored.ia_seguridad_blocked_domains || [];

    const urlObj = new URL(targetUrl);
    const domain = urlObj.hostname;

    if (blockedDomains.includes(domain)) {
      console.log("[IA-Seg] Domain already blocked:", domain);
      // Navigate to blocked page instead
      const blockedPageUrl =
        chrome.runtime.getURL("blocked.html") +
        `?url=${encodeURIComponent(targetUrl)}&reason=already_blocked`;
      await chrome.tabs.update(details.tabId, { url: blockedPageUrl });
      return;
    }
  } catch (e) {
    console.log("[IA-Seg] Error checking blocked domains:", e.message);
  }

  // Verify URL with MCP/Safe Browsing (async, doesn't block for now)
  verifyAndBlockUrl(targetUrl, details.tabId).catch((e) => {
    console.log("[IA-Seg] URL verification error:", e.message);
  });
});

/**
 * Verify URL with MCP and add to blocklist if malicious
 **/
async function verifyAndBlockUrl(url, tabId) {
  try {
    // Verify URL via backend MCP
    const response = await fetch(`${API_BASE}/mcp/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url }),
    });

    if (!response.ok) {
      console.log("[IA-Seg] MCP verify failed:", response.status);
      return;
    }

    const result = await response.json();
    console.log("[IA-Seg] URL check result:", result);

    // If malicious, add to blocklist and block navigation
    if (result.malicious) {
      const urlObj = new URL(url);
      const domain = urlObj.hostname;

      // Add to blocked domains
      const stored = await chrome.storage.local.get(BLOCKED_URLS_KEY);
      const blockedDomains = stored.ia_seguridad_blocked_domains || [];

      if (!blockedDomains.includes(domain)) {
        blockedDomains.push(domain);
        await chrome.storage.local.set({
          [BLOCKED_URLS_KEY]: blockedDomains,
        });
      }

      // Add declarativeNetRequest rule to block
      await addBlockingRule(domain, result.threat_type);

      // Redirect to blocked page
      const blockedPageUrl =
        chrome.runtime.getURL("blocked.html") +
        `?url=${encodeURIComponent(url)}` +
        `&threat=${encodeURIComponent(result.threat_type || "MALICIOUS")}` +
        `&domain=${encodeURIComponent(domain)}`;

      await chrome.tabs.update(tabId, { url: blockedPageUrl });
      console.log("[IA-Seg] URL blocked:", domain);
    }
  } catch (e) {
    console.log("[IA-Seg] URL verification error:", e.message);
  }
}

/**
 * Add dynamic rule to block domain
 **/
async function addBlockingRule(domain, threatType) {
  const ruleId = Math.floor(Math.random() * 100000) + 1;

  try {
    await chrome.declarativeNetRequest.updateDynamicRules({
      addRules: [
        {
          id: ruleId,
          priority: 1,
          action: { type: "block" },
          condition: {
            urlFilter: `*://${domain}/*`,
            resourceTypes: ["main_frame"],
          },
        },
      ],
    });
    console.log("[IA-Seg] Added blocking rule for:", domain);
  } catch (e) {
    console.log("[IA-Seg] Failed to add blocking rule:", e.message);
  }
}

/**
 * Analizar email
 **/
async function analyzeEmail(emailId, subject, sender, body) {
  const response = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Session-ID": currentSession?.sessionId || "",
    },
    body: JSON.stringify({
      email_id: emailId,
      email_subject: subject,
      email_sender: sender,
      email_body: body,
      check_urls: true,
    }),
  });

  if (!response.ok) {
    const err = await response.json();
    throw new Error(err.detail || "Análisis falló");
  }

  return response.json();
}
