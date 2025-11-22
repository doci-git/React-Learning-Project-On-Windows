(() => {
  "use strict";

  // =============================================
  // CONFIGURAZIONE E INIZIALIZZAZIONE
  // =============================================
  const firebaseConfig = {
    apiKey: "AIzaSyD8oQsvmn7nyV2nYnExD-xw6gchwRJ0Bog",
    authDomain: "multi-client-77378.firebaseapp.com",
    databaseURL:
      "https://multi-client-77378-default-rtdb.europe-west1.firebasedatabase.app",
    projectId: "multi-client-77378",
    storageBucket: "multi-client-77378.firebasestorage.app",
    messagingSenderId: "654507957917",
    appId: "1:654507957917:web:3be18327d2951774113e74",
  };

  const DOOR_API_URL = "/api/shelly-control";
  const SECRET_KEY = "musart_secret_123_fixed_key";
  const CODE_VERSION_KEY = "code_version";
  const KEEP_TOKEN_IN_URL = true;
  const UNBLOCK_VERSION_KEY = "unblock_version";

  // Configurazione dispositivi Shelly (immutabile)
  const DEVICES = Object.freeze([
    {
      id: "e4b063f0c38c",
      storage_key: "clicks_MainDoor",
      button_id: "MainDoor",
      visible: true,
    },
    {
      id: "34945478d595",
      storage_key: "clicks_AptDoor",
      button_id: "AptDoor",
      visible: true,
    },
    {
      id: "3494547ab161",
      storage_key: "clicks_ExtraDoor1",
      button_id: "ExtraDoor1",
      visible: false,
    },
    {
      id: "placeholder_id_2",
      storage_key: "clicks_ExtraDoor2",
      button_id: "ExtraDoor2",
      visible: false,
    },
  ]);

  // Variabili globali/di stato
  let MAX_CLICKS = parseInt(localStorage.getItem("max_clicks")) || 3;
  let TIME_LIMIT_MINUTES =
    parseInt(localStorage.getItem("time_limit_minutes")) || 50000;
  const TOKEN_LIMIT_MINUTES =
    parseInt(localStorage.getItem("token_time_limit_minutes")) ||
    TIME_LIMIT_MINUTES;
  let CORRECT_CODE = localStorage.getItem("secret_code") || "2245";
  let currentCodeVersion =
    parseInt(localStorage.getItem(CODE_VERSION_KEY)) || 1;

  // Orari di check‑in
  let CHECKIN_START_TIME = "14:00";
  let CHECKIN_END_TIME = "22:00";
  let CHECKIN_TIME_ENABLED = true;

  // Stato runtime
  let isTokenSession = false;
  let currentTokenId = null;
  let currentTokenCustomCode = null;
  let sessionStartTime = null;
  let currentDevice = null;

  // Tentativi errati e lockout
  let MAX_LOGIN_ATTEMPTS =
    parseInt(localStorage.getItem("max_login_attempts")) || 5;
  let LOCKOUT_MINUTES = parseInt(localStorage.getItem("lockout_minutes")) || 1;

  // Intervalli/listener
  let timeCheckInterval = null;
  let codeCheckInterval = null;
  let LINK_CHECK_INTERVAL = null;
  let settingsRef = null;
  let tokenRef = null;

  // =============================================
  // Firebase init
  // =============================================
  if (!firebase.apps || firebase.apps.length === 0) {
    firebase.initializeApp(firebaseConfig);
  }
  const database = firebase.database();

  // =============================================
  // UTILS
  // =============================================
  function qs(id) {
    return document.getElementById(id);
  }

  function on(id, evt, handler) {
    const el = qs(id);
    if (el) el.addEventListener(evt, handler);
  }

  function showNotification(message, type = "info") {
    const existing = document.getElementById("codeChangeNotification");
    if (existing) existing.remove();

    const n = document.createElement("div");
    n.id = "codeChangeNotification";
    n.style.cssText = `
      position: fixed; top: 20px; right: 20px; z-index: 10000;
      background: ${
        type === "warning"
          ? "#FFA500"
          : type === "error"
          ? "#FF5A5F"
          : "#4CAF50"
      };
      color: #fff; padding: 15px 20px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,.12);
      display:flex; gap:10px; align-items:center; max-width:360px;
    `;
    n.innerHTML = `
      <i class="fas fa-info-circle"></i>
      <span>${message}</span>
      <button onclick="this.parentElement.remove()" style="background:none;border:none;color:#fff;cursor:pointer">
        <i class="fas fa-times"></i>
      </button>`;
    document.body.appendChild(n);
    setTimeout(() => n.parentElement && n.remove(), 5000);
  }

  function formatTime(timeString) {
    const [h, m] = String(timeString || "").split(":");
    return `${h?.padStart(2, "0")}:${m?.padStart(2, "0")}`;
  }

  function fetchWithTimeout(url, options = {}, timeoutMs = 12000) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeoutMs);
    const p = fetch(url, { ...options, signal: controller.signal }).finally(
      () => clearTimeout(id)
    );
    return p;
  }

  // =============================================
  // STORAGE
  // =============================================
  function setStorage(key, value, minutes) {
    try {
      localStorage.setItem(key, value);
      const expirationDate = new Date();
      expirationDate.setTime(expirationDate.getTime() + minutes * 60 * 1000);
      const expires = "expires=" + expirationDate.toUTCString();
      document.cookie = `${key}=${value}; ${expires}; path=/; SameSite=Strict`;
    } catch (error) {
      console.error("Errore nel salvataggio dei dati:", error);
    }
  }

  function getStorage(key) {
    try {
      const localValue = localStorage.getItem(key);
      if (localValue !== null) return localValue;
      const cookies = document.cookie.split(";");
      for (const cookie of cookies) {
        const [name, value] = cookie.trim().split("=");
        if (name === key) return value;
      }
    } catch (error) {
      console.error("Errore nel recupero dei dati:", error);
    }
    return null;
  }

  function clearStorage(key) {
    try {
      localStorage.removeItem(key);
      document.cookie = `${key}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
    } catch (error) {
      console.error("Errore nella rimozione dei dati:", error);
    }
  }

  function clearAllClientStorage() {
    try {
      localStorage.clear();
    } catch (error) {
      console.error("Impossibile svuotare il localStorage:", error);
    }
    try {
      sessionStorage.clear();
    } catch (error) {
      console.warn("Impossibile svuotare la sessionStorage:", error);
    }
    try {
      const cookies = document.cookie.split(";");
      for (const cookie of cookies) {
        const [name] = cookie.trim().split("=");
        if (!name) continue;
        document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
      }
    } catch (error) {
      console.warn("Impossibile rimuovere i cookie di sessione:", error);
    }
  }

  // =============================================
  // CRITTOGRAFIA
  // =============================================
  async function generateHash(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  // =============================================
  // IMPOSTAZIONI (Firebase)
  // =============================================
  async function loadSettingsFromFirebase() {
    try {
      const snapshot = await database.ref("settings").once("value");
      return snapshot.exists() ? snapshot.val() : null;
    } catch (error) {
      console.error(
        "Errore nel caricamento delle impostazioni da Firebase:",
        error
      );
      return null;
    }
  }

  function applyFirebaseSettings(settings) {
    if (settings?.secret_code) {
      CORRECT_CODE = settings.secret_code;
      localStorage.setItem("secret_code", settings.secret_code);
    }
    if (settings?.max_login_attempts) {
      MAX_LOGIN_ATTEMPTS = parseInt(settings.max_login_attempts, 10);
      localStorage.setItem("max_login_attempts", String(MAX_LOGIN_ATTEMPTS));
    }
    if (settings?.lockout_minutes) {
      LOCKOUT_MINUTES = parseInt(settings.lockout_minutes, 10);
      localStorage.setItem("lockout_minutes", String(LOCKOUT_MINUTES));
    }
    if (settings?.max_clicks) {
      MAX_CLICKS = parseInt(settings.max_clicks, 10);
      localStorage.setItem("max_clicks", settings.max_clicks);
    }
    if (settings?.time_limit_minutes) {
      TIME_LIMIT_MINUTES = parseInt(settings.time_limit_minutes, 10);
      localStorage.setItem("time_limit_minutes", settings.time_limit_minutes);
    }
    if (typeof settings?.checkin_start_time === "string")
      CHECKIN_START_TIME = settings.checkin_start_time;
    if (typeof settings?.checkin_end_time === "string")
      CHECKIN_END_TIME = settings.checkin_end_time;
    if (typeof settings?.checkin_time_enabled !== "undefined")
      CHECKIN_TIME_ENABLED = String(settings.checkin_time_enabled) !== "false";

    updateCheckinTimeDisplay();
    DEVICES.forEach(updateButtonState);
    updateStatusBar();
  }

  function setupSettingsListener() {
    if (settingsRef) return;
    settingsRef = database.ref("settings");
    settingsRef.on("value", (snap) => {
      const s = snap.val() || {};
      applyFirebaseSettings(s);

      // Kill-switch: cambio codice globale
      const serverCodeVer = parseInt(s.code_version || 1, 10);
      const localCodeVer = parseInt(
        localStorage.getItem(CODE_VERSION_KEY) || "1",
        10
      );

      // FIXED: Only block existing devices, not new ones
      if (serverCodeVer > localCodeVer) {
        const hadLocalVersion = localStorage.getItem(CODE_VERSION_KEY) !== null;
        localStorage.setItem(CODE_VERSION_KEY, String(serverCodeVer));
        currentCodeVersion = serverCodeVer;

        const msg =
          s.global_block_message ||
          "Codice aggiornato: il link non e' piu' valido";

        if (hadLocalVersion) {
          // Existing device: block and show expired overlay
          blockAccess(msg);
          showSessionExpired();
        } else {
          // New device: just update code and show auth form
          unblockAccess();
          qs("expiredOverlay")?.classList.add("hidden");
          qs("sessionExpired")?.classList.add("hidden");
          qs("controlPanel")?.classList.add("hidden");
          showAuthForm();
          showNotification(
            "Il codice di accesso è stato aggiornato. Inserisci il nuovo codice."
          );
        }
        return;
      }

      // Ripristino globale
      const serverUnblockVer = parseInt(s.session_reset_version || 0, 10);
      const localUnblockVer = parseInt(
        localStorage.getItem(UNBLOCK_VERSION_KEY) || "0",
        10
      );
      if (serverUnblockVer > localUnblockVer) {
        handleRemoteSessionReset({
          message:
            s.global_unblock_message ||
            "Sessione ripristinata. Inserisci il codice per accedere.",
          unblockVersion: serverUnblockVer,
          codeVersion: serverCodeVer,
        });
      }
    });
  }

  function monitorFirebaseConnection() {
    const connectedRef = database.ref(".info/connected");
    connectedRef.on("value", (snap) => {
      if (snap.val() === true) {
        document.body.classList.remove("firebase-offline");
      } else {
        document.body.classList.add("firebase-offline");
        showNotification(
          "Connessione a Firebase persa. Le modifiche potrebbero non essere sincronizzate.",
          "warning"
        );
      }
    });
  }

  // =============================================
  // TEMPO/SESSIONE
  // =============================================
  async function setUsageStartTime() {
    const now = Date.now().toString();
    const hash = await generateHash(now + SECRET_KEY);
    setStorage("usage_start_time", now, TIME_LIMIT_MINUTES);
    setStorage("usage_hash", hash, TIME_LIMIT_MINUTES);
    updateStatusBar();
  }

  async function setTokenUsageStartTime(tokenId) {
    if (!tokenId) return;
    const keyT = `token_ts_${tokenId}`;
    const keyH = `token_th_${tokenId}`;
    try {
      if (localStorage.getItem(keyT)) return;
      const now = Date.now().toString();
      const hash = await generateHash(now + SECRET_KEY + tokenId);
      setStorage(keyT, now, TOKEN_LIMIT_MINUTES);
      setStorage(keyH, hash, TOKEN_LIMIT_MINUTES);
    } catch {}
  }

  function clearTokenUsageStart(tokenId) {
    if (!tokenId) return;
    try {
      localStorage.removeItem(`token_ts_${tokenId}`);
      localStorage.removeItem(`token_th_${tokenId}`);
    } catch {}
  }

  async function checkTimeLimit() {
    // Timer per sessioni token
    if (isTokenSession) {
      const t =
        currentTokenId || new URLSearchParams(location.search).get("token");
      if (!t) return false;
      const keyT = `token_ts_${t}`;
      const keyH = `token_th_${t}`;
      const ts = getStorage(keyT);
      const hs = getStorage(keyH);
      if (ts && hs) {
        const calc = await generateHash(ts + SECRET_KEY + t);
        if (calc !== hs) {
          clearTokenUsageStart(t);
          forceLogoutFromToken("Sessione token non valida");
          return true;
        }
        const mins = (Date.now() - parseInt(ts, 10)) / (1000 * 60);
        if (mins >= TOKEN_LIMIT_MINUTES) {
          clearTokenUsageStart(t);
          forceLogoutFromToken("Sessione token scaduta");
          return true;
        }
      }
      return false;
    }

    if (!sessionStartTime) return false;

    const startTime = getStorage("usage_start_time");
    const storedHash = getStorage("usage_hash");
    if (!startTime || !storedHash) return false;

    const calcHash = await generateHash(startTime + SECRET_KEY);
    if (calcHash !== storedHash) {
      showFatalError("⚠️ Violazione di sicurezza rilevata!");
      return true;
    }

    const now = Date.now();
    const minutesPassed = (now - parseInt(startTime, 10)) / (1000 * 60);
    if (minutesPassed >= TIME_LIMIT_MINUTES) {
      showSessionExpired();
      return true;
    }

    updateStatusBar();
    return false;
  }

  function showFatalError(message) {
    if (timeCheckInterval) clearInterval(timeCheckInterval);
    if (codeCheckInterval) clearInterval(codeCheckInterval);
    document.body.innerHTML = `
      <div style="position:fixed;inset:0;display:flex;justify-content:center;align-items:center;background:#121111;color:#ff6b6b;font-size:24px;text-align:center;padding:20px;z-index:9999;">
        ${message}
      </div>`;
  }

  function showSessionExpired() {
    // FIXED: Show expired overlay for both manual sessions and token sessions when expired
    if (timeCheckInterval) clearInterval(timeCheckInterval);
    if (codeCheckInterval) clearInterval(codeCheckInterval);

    qs("expiredOverlay")?.classList.remove("hidden");
    qs("controlPanel")?.classList.add("hidden");
    qs("sessionExpired")?.classList.remove("hidden");
    qs("test2") && (qs("test2").style.display = "none");

    DEVICES.forEach((device) => {
      const btn = qs(device.button_id);
      if (btn) {
        btn.disabled = true;
        btn.classList.add("btn-error");
      }
    });

    const securityStatus = qs("securityStatus");
    if (securityStatus) {
      securityStatus.textContent = "Scaduta";
      securityStatus.style.color = "var(--error)";
    }

    sessionStartTime = null;
  }

  function isSessionStuck() {
    try {
      const authVerified = localStorage.getItem("auth_verified");
      const authTimestamp = localStorage.getItem("auth_timestamp");
      const usageStartTime = localStorage.getItem("usage_start_time");

      if (authVerified === "true" && authTimestamp) {
        const authTime = parseInt(authTimestamp, 10);
        if (Date.now() - authTime > 24 * 60 * 60 * 1000) return true;
      }
      if (usageStartTime) {
        const startTime = parseInt(usageStartTime, 10);
        const minutesPassed = (Date.now() - startTime) / (1000 * 60);
        if (minutesPassed > TIME_LIMIT_MINUTES + 60) return true;
      }
      return false;
    } catch (e) {
      console.error("Errore nel controllo sessione bloccata:", e);
      return false;
    }
  }

  // =============================================
  // CHECK‑IN TIME
  // =============================================
  function isCheckinTime() {
    if (!CHECKIN_TIME_ENABLED) return true;

    const now = new Date();
    const current = now.getHours() * 60 + now.getMinutes();
    const [sh, sm] = CHECKIN_START_TIME.split(":").map(Number);
    const [eh, em] = CHECKIN_END_TIME.split(":").map(Number);
    const start = sh * 60 + sm;
    const end = eh * 60 + em;
    return current >= start && current <= end;
  }

  function updateCheckinTimeDisplay() {
    const startEl = qs("checkinStartDisplay");
    const endEl = qs("checkinEndDisplay");
    const startPopup = qs("checkinStartPopup");
    const endPopup = qs("checkinEndPopup");
    const currentStart = qs("currentCheckinStartTime");
    const currentEnd = qs("currentCheckinEndTime");
    if (startEl) startEl.textContent = formatTime(CHECKIN_START_TIME);
    if (endEl) endEl.textContent = formatTime(CHECKIN_END_TIME);
    if (startPopup) startPopup.textContent = formatTime(CHECKIN_START_TIME);
    if (endPopup) endPopup.textContent = formatTime(CHECKIN_END_TIME);
    if (currentStart) currentStart.textContent = formatTime(CHECKIN_START_TIME);
    if (currentEnd) currentEnd.textContent = formatTime(CHECKIN_END_TIME);

    const statusElement = qs("currentTimeStatus");
    if (!statusElement) return;

    if (!CHECKIN_TIME_ENABLED) {
      statusElement.innerHTML =
        '<i class="fas fa-power-off" style="color:orange;"></i> Time control disabled — check-in allowed at any time';
      return;
    }

    if (isCheckinTime()) {
      statusElement.innerHTML =
        '<i class="fas fa-check-circle" style="color:green;"></i> Check-in now available';
      return;
    }

    const now = new Date();
    const current = now.getHours() * 60 + now.getMinutes();
    const [sh, sm] = CHECKIN_START_TIME.split(":").map(Number);
    const [eh, em] = CHECKIN_END_TIME.split(":").map(Number);
    const start = sh * 60 + sm;
    const end = eh * 60 + em;

    if (current < start) {
      const diff = start - current;
      const h = Math.floor(diff / 60);
      const m = diff % 60;
      statusElement.innerHTML = `<i class="fas fa-clock" style="color:orange;"></i> Check-in will be available in ${h}h ${m}m`;
    } else {
      const tomorrow = new Date(now);
      tomorrow.setDate(tomorrow.getDate() + 1);
      tomorrow.setHours(sh, sm, 0, 0);
      const diff = tomorrow - now;
      const h = Math.floor(diff / (1000 * 60 * 60));
      const m = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
      statusElement.innerHTML = `<i class="fas fa-clock" style="color:orange;"></i> Check-in will be available tomorrow in ${h}h ${m}m`;
    }
  }

  function showEarlyCheckinPopup() {
    const el = qs("earlyCheckinPopup");
    if (el) el.style.display = "flex";
  }
  function closeEarlyCheckinPopup() {
    const el = qs("earlyCheckinPopup");
    if (el) el.style.display = "none";
  }

  // =============================================
  // INTERFACCIA/STATO
  // =============================================
  function updateStatusBar() {
    const mainDoorCounter = qs("mainDoorCounter");
    const aptDoorCounter = qs("aptDoorCounter");
    const timeRemaining = qs("timeRemaining");

    if (mainDoorCounter) {
      mainDoorCounter.textContent = `${getClicksLeft(
        DEVICES[0].storage_key
      )} click left`;
    }
    if (aptDoorCounter) {
      aptDoorCounter.textContent = `${getClicksLeft(
        DEVICES[1].storage_key
      )} click left`;
    }

    if (!sessionStartTime || !timeRemaining) {
      if (timeRemaining) {
        const minutes = Math.floor(TIME_LIMIT_MINUTES);
        const seconds = Math.floor((TIME_LIMIT_MINUTES % 1) * 60);
        timeRemaining.textContent = `${String(minutes).padStart(
          2,
          "0"
        )}:${String(seconds).padStart(2, "0")}`;
        timeRemaining.style.color = "var(--primary)";
      }
      return;
    }

    const startTime = getStorage("usage_start_time");
    if (!startTime) return;

    const now = Date.now();
    const minutesPassed = (now - parseInt(startTime, 10)) / (1000 * 60);
    const minutesLeft = Math.max(
      0,
      Math.floor(TIME_LIMIT_MINUTES - minutesPassed)
    );
    const secondsLeft = Math.max(0, Math.floor(60 - (minutesPassed % 1) * 60));

    timeRemaining.textContent = `${String(minutesLeft).padStart(
      2,
      "0"
    )}:${String(secondsLeft).padStart(2, "0")}`;
    if (minutesLeft < 1) timeRemaining.style.color = "var(--error)";
    else if (minutesLeft < 5) timeRemaining.style.color = "var(--warning)";
    else timeRemaining.style.color = "var(--primary)";
  }

  function getClicksLeft(key) {
    const stored = getStorage(key);
    return stored === null ? MAX_CLICKS : parseInt(stored, 10);
  }

  function setClicksLeft(key, count) {
    setStorage(key, String(count), TIME_LIMIT_MINUTES);
    updateStatusBar();
  }

  function updateButtonState(device) {
    const btn = qs(device.button_id);
    if (!btn) return;
    const clicksLeft = getClicksLeft(device.storage_key);
    btn.disabled = clicksLeft <= 0 || !isCheckinTime();
    if (clicksLeft <= 0) {
      btn.classList.add("btn-error");
      btn.classList.remove("btn-success");
    } else if (!isCheckinTime()) {
      btn.classList.remove("btn-error", "btn-success");
    } else {
      btn.classList.add("btn-success");
      btn.classList.remove("btn-error");
    }
  }

  function updateDoorVisibility() {
    DEVICES.forEach((device) => {
      const container = qs(`${device.button_id}Container`);
      if (container)
        container.style.display = device.visible ? "block" : "none";
    });
  }

  // =============================================
  // CAMBIAMENTO CODICE
  // =============================================
  function setupCodeChangeListener() {
    if (codeCheckInterval) clearInterval(codeCheckInterval);
    if (LINK_CHECK_INTERVAL) clearInterval(LINK_CHECK_INTERVAL);

    codeCheckInterval = setInterval(checkCodeVersion, 2000);
    LINK_CHECK_INTERVAL = setInterval(checkExpiredLinks, 60000);

    window.addEventListener("storage", (e) => {
      if (e.key === "code_version" || e.key === "last_code_update") {
        checkCodeVersion();
      }
    });
  }

  function checkCodeVersion() {
    database
      .ref("settings/code_version")
      .once("value")
      .then((snap) => {
        if (snap.exists()) {
          const firebaseVersion = parseInt(snap.val());
          const localVersion =
            parseInt(localStorage.getItem("code_version")) || 1;
          const savedVersion = Math.max(firebaseVersion, localVersion);
          if (savedVersion > currentCodeVersion) handleCodeChange(savedVersion);
        }
      })
      .catch(() => {
        const savedVersion =
          parseInt(localStorage.getItem("code_version")) || 1;
        if (savedVersion > currentCodeVersion) handleCodeChange(savedVersion);
      });
  }

  function handleCodeChange(newVersion) {
    currentCodeVersion = newVersion;
    database
      .ref("settings/secret_code")
      .once("value")
      .then((codeSnap) => {
        if (codeSnap.exists()) {
          CORRECT_CODE = codeSnap.val();
          localStorage.setItem("secret_code", CORRECT_CODE);
          const hadLocalVersion =
            localStorage.getItem(CODE_VERSION_KEY) !== null;
          const msg = "Codice aggiornato: il link non e' piu' valido";

          // FIXED: Same logic as in setupSettingsListener
          if (hadLocalVersion) {
            blockAccess(msg);
            showSessionExpired();
          } else {
            unblockAccess();
            qs("expiredOverlay")?.classList.add("hidden");
            qs("sessionExpired")?.classList.add("hidden");
            qs("controlPanel")?.classList.add("hidden");
            showAuthForm();
            showNotification(
              "Il codice di accesso è stato aggiornato. Inserisci il nuovo codice."
            );
          }
        }
      });
  }

  function resetSessionForNewCode() {
    clearStorage("usage_start_time");
    clearStorage("usage_hash");
    DEVICES.forEach((d) => clearStorage(d.storage_key));

    qs("controlPanel") && (qs("controlPanel").style.display = "none");
    qs("authCode") && (qs("authCode").style.display = "block");
    qs("auth-form") && (qs("auth-form").style.display = "block");
    qs("btnCheckCode") && (qs("btnCheckCode").style.display = "block");
    qs("important") && (qs("important").style.display = "block");

    showNotification(
      "Il codice di accesso è stato aggiornato. Inserisci il nuovo codice."
    );
  }

  function checkExpiredLinks() {
    const secureLinks = JSON.parse(
      localStorage.getItem("secure_links") || "{}"
    );
    let updated = false;
    Object.keys(secureLinks).forEach((linkId) => {
      const link = secureLinks[linkId];
      if (link.expiration < Date.now() && link.status === "active") {
        secureLinks[linkId].status = "expired";
        updated = true;
      }
    });
    if (updated)
      localStorage.setItem("secure_links", JSON.stringify(secureLinks));
  }

  // =============================================
  // POPUP
  // =============================================
  function showConfirmationPopup(device) {
    if (!isCheckinTime()) {
      showEarlyCheckinPopup();
      return;
    }
    currentDevice = device;
    const doorName = device.button_id
      .replace(/([A-Z])/g, " $1")
      .replace(/^./, (s) => s.toUpperCase());
    const msg = qs("confirmationMessage");
    if (msg)
      msg.textContent = `Are you sure you want to unlock the ${doorName}?`;
    const pop = qs("confirmationPopup");
    if (pop) pop.style.display = "flex";
  }
  function closeConfirmationPopup() {
    const pop = qs("confirmationPopup");
    if (pop) pop.style.display = "none";
    currentDevice = null;
  }

  function showDevicePopup(device, clicksLeft) {
    const popup = qs(`popup-${device.button_id}`);
    if (!popup) return;
    const text = qs(`popup-text-${device.button_id}`);
    if (text) {
      if (clicksLeft > 0) {
        text.innerHTML = `
          <i class="fas fa-check-circle" style="color:#4CAF50;font-size:2.5rem;margin-bottom:15px;"></i>
          <div><strong>${clicksLeft}</strong> Click Left</div>
          <div style="margin-top:10px;font-size:1rem;">Door Unlocked!</div>`;
      } else {
        text.innerHTML = `
          <i class="fas fa-exclamation-triangle" style="color:#FFC107;font-size:2.5rem;margin-bottom:15px;"></i>
          <div><strong>No more clicks left!</strong></div>
          <div style="margin-top:10px;font-size:1rem;">Contact for Assistance.</div>`;
      }
    }
    popup.style.display = "flex";
    if (clicksLeft > 0) setTimeout(() => closePopup(device.button_id), 3000);
  }

  function closePopup(buttonId) {
    const popup = qs(`popup-${buttonId}`);
    if (popup) popup.style.display = "none";
  }

  // =============================================
  // SHELLY
  // =============================================
  async function activateDevice(device) {
    if (!sessionStartTime) {
      sessionStartTime = Date.now();
      await setUsageStartTime();
    }

    if (await checkTimeLimit()) return;
    if (!isCheckinTime()) {
      showEarlyCheckinPopup();
      return;
    }

    let clicksLeft = getClicksLeft(device.storage_key);
    if (clicksLeft <= 0) {
      showDevicePopup(device, clicksLeft);
      updateButtonState(device);
      return;
    }

    setClicksLeft(device.storage_key, --clicksLeft);
    updateButtonState(device);

    try {
      const response = await fetchWithTimeout(
        DOOR_API_URL,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            deviceId: device.id,
            command: "open",
            payload: { channel: 0 },
          }),
        },
        12000
      );

      const result = await response.json().catch(() => ({}));

      if (response.ok && result && result.success) {
        showDevicePopup(device, clicksLeft);
      } else {
        setClicksLeft(device.storage_key, clicksLeft + 1);
        updateButtonState(device);
        console.error(
          "Errore nell'attivazione del dispositivo:",
          response.status,
          response.statusText,
          result
        );
      }
    } catch (error) {
      console.error("Attivazione dispositivo fallita:", error);
      setClicksLeft(device.storage_key, clicksLeft + 1);
      updateButtonState(device);
    }
  }

  // =============================================
  // TOKEN SICURI
  // =============================================
  function maybeCleanUrl() {
    if (!KEEP_TOKEN_IN_URL) cleanUrl();
  }

  async function handleSecureToken() {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get("token");
    if (!token) {
      isTokenSession = false;
      window.isTokenSession = false;
      currentTokenCustomCode = null;
      return false;
    }

    try {
      const snapshot = await database
        .ref("secure_links/" + token)
        .once("value");
      if (!snapshot.exists()) {
        showTokenError("Invalid token");
        blockTokenOnly("Invalid token", token);
        showAuthForm();
        maybeCleanUrl();
        return false;
      }

      const linkData = snapshot.val();

      if (isTokenDeviceBlocked(token)) {
        const r =
          localStorage.getItem(`token_device_reason_${token}`) ||
          "Sessione token scaduta su questo dispositivo";
        showTokenError(r);
        blockTokenOnly(r, token);
        showAuthForm();
        maybeCleanUrl();
        return false;
      }

      const isValid = validateSecureToken(linkData);
      if (!isValid.valid) {
        showTokenError(isValid.reason);
        blockTokenOnly(isValid.reason || "Access blocked", token);
        showAuthForm();
        maybeCleanUrl();
        return false;
      }

      isTokenSession = true;
      window.isTokenSession = true;
      currentTokenId = token;
      currentTokenCustomCode = linkData.customCode || null;

      localStorage.removeItem("block_manual_login");
      localStorage.removeItem("blocked_token");
      localStorage.removeItem("blocked_reason");
      clearTokenDeviceBlock(token);

      try {
        unblockAccess();
        qs("expiredOverlay")?.classList.add("hidden");
        qs("sessionExpired")?.classList.add("hidden");
      } catch {}

      showTokenNotification(isValid.remainingUses, !!currentTokenCustomCode);
      await incrementTokenUsage(token, linkData);
      maybeCleanUrl();
      startTokenExpirationCheck(linkData.expiration);
      startTokenRealtimeListener(token);

      showAuthForm();
      return true;
    } catch (error) {
      console.error("Token verification error:", error);
      showTokenError("Verification error");
      blockTokenOnly("Verification error", token);
      showAuthForm();
      maybeCleanUrl();
      return false;
    }
  }

  function stopTokenRealtimeListener() {
    if (tokenRef) {
      tokenRef.off();
      tokenRef = null;
    }
  }

  function clearManualSession() {
    try {
      localStorage.removeItem("usage_start_time");
      localStorage.removeItem("usage_hash");
      sessionStartTime = null;
    } catch {}
  }

  function handleRemoteSessionReset({
    message,
    unblockVersion,
    codeVersion,
  } = {}) {
    stopTokenRealtimeListener();
    clearManualSession();
    clearAllClientStorage();
    if (Number.isFinite(codeVersion)) {
      localStorage.setItem(CODE_VERSION_KEY, String(codeVersion));
      currentCodeVersion = codeVersion;
    }
    if (Number.isFinite(unblockVersion)) {
      localStorage.setItem(UNBLOCK_VERSION_KEY, String(unblockVersion));
    }
    isTokenSession = false;
    window.isTokenSession = false;
    currentTokenId = null;
    currentTokenCustomCode = null;
    sessionStartTime = null;
    unblockAccess();
    qs("expiredOverlay")?.classList.add("hidden");
    qs("sessionExpired")?.classList.add("hidden");
    qs("controlPanel")?.classList.add("hidden");
    showAuthForm();
    updateDoorVisibility();
    updateLockUI();
    showNotification(
      message ||
        "Sessione ripristinata dall'amministratore. Inserisci nuovamente il codice."
    );
  }

  function blockAccess(reason = "Accesso bloccato", token = null) {
    try {
      localStorage.setItem("block_manual_login", "1");
      localStorage.setItem("blocked_reason", reason);
      if (token) localStorage.setItem("blocked_token", token);
    } catch (e) {
      console.error("Errore blockAccess:", e);
    }
  }

  function blockTokenOnly(reason = "Accesso bloccato", token = null) {
    try {
      localStorage.setItem("blocked_reason", reason);
      if (token) localStorage.setItem("blocked_token", token);
    } catch (e) {
      console.error("Errore blockTokenOnly:", e);
    }
  }

  function unblockAccess() {
    localStorage.removeItem("block_manual_login");
    localStorage.removeItem("blocked_reason");
    localStorage.removeItem("blocked_token");
  }

  function markTokenDeviceBlocked(token, reason = "") {
    try {
      if (!token) return;
      localStorage.setItem(`token_device_block_${token}`, "1");
      if (reason) localStorage.setItem(`token_device_reason_${token}`, reason);
    } catch (e) {
      console.error("Errore markTokenDeviceBlocked:", e);
    }
  }

  function isTokenDeviceBlocked(token) {
    try {
      if (!token) return false;
      return localStorage.getItem(`token_device_block_${token}`) === "1";
    } catch {
      return false;
    }
  }

  function clearTokenDeviceBlock(token) {
    try {
      if (!token) return;
      localStorage.removeItem(`token_device_block_${token}`);
      localStorage.removeItem(`token_device_reason_${token}`);
    } catch {}
  }

  function hasTokenFootprint() {
    try {
      if (isTokenSession) return true;
      const urlTok = new URLSearchParams(window.location.search).get("token");
      if (urlTok) return true;
      if (localStorage.getItem("blocked_token")) return true;
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k && k.indexOf("token_ok_") === 0) return true;
      }
    } catch (e) {
      console.warn("hasTokenFootprint check failed:", e);
    }
    return false;
  }

  function forceGlobalLogout(reason = "Codice aggiornato: accedi di nuovo") {
    isTokenSession = false;
    window.isTokenSession = false;
    clearManualSession();
    const t =
      currentTokenId ||
      new URLSearchParams(location.search).get("token") ||
      null;
    blockTokenOnly(reason, t);
    try {
      if (t) localStorage.removeItem(`token_ok_${t}`);
    } catch {}
    showTokenError(reason);
    showSessionExpired();
    stopTokenRealtimeListener();
  }

  function forceLogoutFromToken(reason = "Link non più valido") {
    isTokenSession = false;
    window.isTokenSession = false;
    clearManualSession();
    const t =
      currentTokenId ||
      new URLSearchParams(location.search).get("token") ||
      null;
    blockTokenOnly(reason, t);
    if (t) markTokenDeviceBlocked(t, reason || "Sessione token scaduta");
    try {
      if (t) localStorage.removeItem(`token_ok_${t}`);
    } catch {}
    showTokenError(reason);
    showSessionExpired();
    stopTokenRealtimeListener();
  }

  function startTokenRealtimeListener(token) {
    stopTokenRealtimeListener();
    tokenRef = database.ref("secure_links/" + token);
    tokenRef.on("value", (snap) => {
      if (!snap.exists()) {
        forceLogoutFromToken("Link rimosso");
        return;
      }
      const d = snap.val();
      const now = Date.now();
      const exhausted = (d.usedCount || 0) >= (d.maxUsage || 0);
      const expired = (d.expiration || 0) <= now;
      const revoked = d.status !== "active";
      if (revoked || expired || exhausted) {
        const why = revoked
          ? "Link revocato"
          : expired
          ? "Link scaduto"
          : "Utilizzi esauriti";
        forceLogoutFromToken(why);
      }
    });
  }

  function validateSecureToken(linkData) {
    try {
      if (!linkData) return { valid: false, reason: "Token non valido" };
      if (linkData.status !== "active")
        return { valid: false, reason: "Token revocato" };
      if (linkData.expiration < Date.now())
        return { valid: false, reason: "Token scaduto" };
      if ((linkData.usedCount || 0) >= (linkData.maxUsage || 0))
        return { valid: false, reason: "Utilizzi esauriti" };
      const remainingUses =
        (linkData.maxUsage || 0) - (linkData.usedCount || 0);
      return { valid: true, remainingUses };
    } catch {
      return { valid: false, reason: "Errore di verifica" };
    }
  }

  async function incrementTokenUsage(token, linkData) {
    const newUsedCount = (linkData.usedCount || 0) + 1;
    const newStatus =
      newUsedCount >= (linkData.maxUsage || 0) ? "used" : "active";
    try {
      await database
        .ref("secure_links/" + token)
        .update({ usedCount: newUsedCount, status: newStatus });
    } catch (error) {
      console.error("Errore nell'aggiornamento del token:", error);
    }
  }

  function showTokenNotification(remainingUses, hasCustomCode) {
    const n = document.createElement("div");
    n.style.cssText = `
      position:fixed; top:20px; right:20px; background:var(--success); color:#fff;
      padding:15px 20px; border-radius:8px; box-shadow:0 4px 12px rgba(0,0,0,.1);
      z-index:10000; display:flex; gap:10px; align-items:center; max-width:350px;`;
    const custom = hasCustomCode
      ? '<div style="font-size:12px;opacity:.9;">Questo link usa un codice dedicato</div>'
      : '<div style="font-size:12px;opacity:.9;">Questo link usa il codice principale</div>';
    n.innerHTML = `
      <i class="fas fa-check-circle"></i>
      <div>
        <div>Link sicuro riconosciuto</div>
        <div style="font-size:12px;opacity:.9;">Utilizzi rimanenti: ${remainingUses}</div>
        ${custom}
        <div style="font-size:12px;opacity:.9;margin-top:5px;"><i class="fas fa-info-circle"></i> Inserisci il codice qui sotto</div>
      </div>
      <button onclick="this.parentElement.remove()" style="background:none;border:none;color:#fff;margin-left:10px;cursor:pointer">
        <i class="fas fa-times"></i>
      </button>`;
    document.body.appendChild(n);
    setTimeout(() => n.parentElement && n.remove(), 5000);
  }

  function showTokenError(reason) {
    const n = document.createElement("div");
    n.style.cssText = `
      position:fixed; top:20px; right:20px; background:var(--error); color:#fff;
      padding:15px 20px; border-radius:8px; box-shadow:0 4px 12px rgba(0,0,0,.1);
      z-index:10000; display:flex; gap:10px; align-items:center; max-width:320px;`;
    n.innerHTML = `
      <i class="fas fa-exclamation-triangle"></i>
      <div>
        <div>Link non valido</div>
        <div style="font-size:12px;opacity:.9;">Motivo: ${reason}</div>
      </div>
      <button onclick="this.parentElement.remove()" style="background:none;border:none;color:#fff;margin-left:10px;cursor:pointer">
        <i class="fas fa-times"></i>
      </button>`;
    document.body.appendChild(n);
    setTimeout(() => n.parentElement && n.remove(), 5000);
  }

  function cleanUrl() {
    if (window.history.replaceState) {
      const clean = window.location.origin + window.location.pathname;
      window.history.replaceState({}, document.title, clean);
    }
  }

  function startTokenExpirationCheck(expirationTime) {
    const iv = setInterval(() => {
      if (Date.now() > expirationTime) {
        clearInterval(iv);
        isTokenSession = false;
        window.isTokenSession = false;
        const t = currentTokenId || null;
        blockTokenOnly("Link expired", t);
        if (t) markTokenDeviceBlocked(t, "Link expired");
        showSessionExpired();
      }
    }, 1000);
  }

  // =============================================
  // AUTENTICAZIONE
  // =============================================
  function isLoginLocked() {
    try {
      const until = parseInt(
        localStorage.getItem("login_lock_until") || "0",
        10
      );
      if (!Number.isFinite(until) || until <= 0) return false;
      if (Date.now() < until) return true;
      localStorage.removeItem("login_lock_until");
      localStorage.removeItem("login_attempts");
      return false;
    } catch {
      return false;
    }
  }

  function secondsToHhMmSs(sec) {
    const s = Math.max(0, Math.floor(sec));
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const r = s % 60;
    if (h > 0)
      return `${h}h ${String(m).padStart(2, "0")}m ${String(r).padStart(
        2,
        "0"
      )}s`;
    return `${String(m).padStart(2, "0")}m ${String(r).padStart(2, "0")}s`;
  }

  function updateLockUI() {
    const input = qs("authCode");
    const btn = qs("btnCheckCode");
    const existing = document.getElementById("lockNotice");
    const locked = isLoginLocked();
    if (locked) {
      if (input) input.disabled = true;
      if (btn) {
        btn.disabled = true;
        btn.classList.add("btn-error");
      }
      let notice = existing;
      if (!notice && input?.parentElement) {
        notice = document.createElement("div");
        notice.id = "lockNotice";
        notice.style.cssText = "margin-top:10px;color:#ff5a5f;font-weight:600;";
        input.parentElement.insertAdjacentElement("afterend", notice);
      }
      if (notice) {
        const until = parseInt(
          localStorage.getItem("login_lock_until") || "0",
          10
        );
        const remainingSec = Math.max(
          0,
          Math.floor((until - Date.now()) / 1000)
        );
        notice.innerHTML = `<i class="fas fa-lock"></i> Too many incorrect attempts. Try again in ${secondsToHhMmSs(
          remainingSec
        )}.`;
      }
    } else {
      if (input) input.disabled = false;
      if (btn) {
        btn.disabled = false;
        btn.classList.remove("btn-error");
      }
      if (existing) existing.remove();
    }
  }

  function incrementFailedAttempt() {
    try {
      const attempts =
        parseInt(localStorage.getItem("login_attempts") || "0", 10) + 1;
      localStorage.setItem("login_attempts", String(attempts));
      const left = Math.max(0, MAX_LOGIN_ATTEMPTS - attempts);
      if (attempts >= MAX_LOGIN_ATTEMPTS) {
        const until = Date.now() + LOCKOUT_MINUTES * 60 * 1000;
        localStorage.setItem("login_lock_until", String(until));
        showNotification(
          `Too many failed attempts. Page locked for ${LOCKOUT_MINUTES} minutes`,
          "error"
        );
        updateLockUI();
      } else {
        showNotification(`Wrong code. Attempts left: ${left}`, "warning");
      }
    } catch (e) {
      console.warn("Impossibile incrementare i tentativi:", e);
    }
  }

  function resetFailedAttempts() {
    try {
      localStorage.removeItem("login_attempts");
    } catch {}
  }

  async function performManualLogin() {
    isTokenSession = false;
    window.isTokenSession = false;
    sessionStartTime = Date.now();
    await setUsageStartTime();

    if (await checkTimeLimit()) return;

    try {
      qs("expiredOverlay")?.classList.add("hidden");
      qs("sessionExpired")?.classList.add("hidden");
      unblockAccess();
    } catch {}

    showControlPanel();
    qs("checkinTimeInfo") && (qs("checkinTimeInfo").style.display = "block");
    updateCheckinTimeDisplay();
    DEVICES.forEach(updateButtonState);
    updateStatusBar();
  }

  async function handleCodeSubmit() {
    if (isLoginLocked()) {
      updateLockUI();
      return;
    }
    const codeInput = qs("authCode");
    const insertedCode = (codeInput?.value || "").trim();
    let expectedCode = CORRECT_CODE;

    if (!insertedCode) {
      showNotification("Please enter the access code", "warning");
      return;
    }

    if (isTokenSession && currentTokenCustomCode)
      expectedCode = currentTokenCustomCode;

    if (insertedCode !== expectedCode) {
      incrementFailedAttempt();
      return;
    }
    resetFailedAttempts();

    if (isTokenSession) {
      try {
        if (currentTokenId)
          localStorage.setItem(`token_ok_${currentTokenId}`, "1");
        if (currentTokenId) await setTokenUsageStartTime(currentTokenId);
        qs("expiredOverlay")?.classList.add("hidden");
        qs("sessionExpired")?.classList.add("hidden");
        unblockAccess();
      } catch {}
      showControlPanel();
      return;
    }
    await performManualLogin();
  }

  // =============================================
  // INIZIALIZZAZIONE APP
  // =============================================
  async function init() {
    console.log("Inizializzazione app.");

    // FIXED: Always hide overlays on startup
    qs("expiredOverlay")?.classList.add("hidden");
    qs("sessionExpired")?.classList.add("hidden");

    const firebaseSettings = await loadSettingsFromFirebase();
    if (firebaseSettings) applyFirebaseSettings(firebaseSettings);

    if (isSessionStuck()) console.warn("Rilevata possibile sessione bloccata");

    // FIXED: Update currentCodeVersion properly
    currentCodeVersion = parseInt(localStorage.getItem(CODE_VERSION_KEY)) || 1;

    const savedCodeVersion =
      parseInt(localStorage.getItem("code_version")) || 1;
    if (savedCodeVersion < currentCodeVersion) {
      localStorage.setItem("code_version", String(currentCodeVersion));
      showNotification(
        "Il codice di accesso è stato aggiornato. Inserisci il nuovo codice."
      );
    }

    setupEventListeners();
    setupSettingsListener();
    monitorFirebaseConnection();

    // FIXED: Only show expired overlay for explicitly blocked devices
    const isBlocked = localStorage.getItem("block_manual_login") === "1";
    if (isBlocked) {
      isTokenSession = false;
      window.isTokenSession = false;
      showSessionExpired();
      return;
    }

    // Handle token first
    const tokenHandled = await handleSecureToken();

    setupTokenUI();

    if (isTokenSession) unblockAccess();

    // FIXED: Simplified logic for normal links
    if (!isTokenSession) {
      const expired = await checkTimeLimit();
      if (!expired) {
        const startTime = getStorage("usage_start_time");
        if (startTime) {
          sessionStartTime = parseInt(startTime, 10);
          showControlPanel();
        } else {
          showAuthForm();
        }
      } else {
        showAuthForm();
      }
    }

    updateDoorVisibility();
    updateLockUI();
    setupIntervals();
    document.addEventListener("contextmenu", (e) => e.preventDefault());
    updateCheckinTimeDisplay();
  }

  function setupEventListeners() {
    on("btnCheckCode", "click", handleCodeSubmit);

    DEVICES.forEach((device) => {
      const btn = qs(device.button_id);
      if (btn)
        btn.addEventListener("click", () => showConfirmationPopup(device));
    });

    on("confirmYes", "click", () => {
      if (currentDevice) {
        activateDevice(currentDevice);
        closeConfirmationPopup();
      }
    });
    on("confirmNo", "click", closeConfirmationPopup);

    document.querySelectorAll(".popup .btn").forEach((button) => {
      button.addEventListener("click", function () {
        const popup = this.closest(".popup");
        if (popup) {
          const id = popup.id.replace("popup-", "");
          closePopup(id);
        }
      });
    });
  }

  function showControlPanel() {
    const cp = qs("controlPanel");
    if (cp) {
      cp.classList.remove("hidden");
      cp.style.display = "block";
    }
    const root = qs("test2");
    if (root) root.style.display = "block";
    const ac = qs("authCode");
    if (ac) ac.style.display = "none";
    const af = qs("auth-form");
    if (af) af.style.display = "none";
    const bc = qs("btnCheckCode");
    if (bc) bc.style.display = "none";
    const imp = qs("important");
    if (imp) imp.style.display = "none";
    qs("expiredOverlay")?.classList.add("hidden");
    qs("sessionExpired")?.classList.add("hidden");
    const info = qs("checkinTimeInfo");
    if (info) info.style.display = "block";
    updateCheckinTimeDisplay();
    DEVICES.forEach(updateButtonState);
    updateStatusBar();
  }

  function showAuthForm() {
    const cp = qs("controlPanel");
    if (cp) cp.style.display = "none";
    const ac = qs("authCode");
    if (ac) ac.style.display = "block";
    const af = qs("auth-form");
    if (af) af.style.display = "block";
    const bc = qs("btnCheckCode");
    if (bc) bc.style.display = "block";
    const imp = qs("important");
    if (imp) imp.style.display = "block";
    qs("expiredOverlay")?.classList.add("hidden");
    qs("sessionExpired")?.classList.add("hidden");
  }

  function setupTokenUI() {
    if (!isTokenSession) return;

    const adminLink = document.querySelector('a[href="admin.html"]');
    if (adminLink) adminLink.style.display = "none";

    const expiredMessage = document.querySelector("#sessionExpired p");
    if (expiredMessage)
      expiredMessage.textContent =
        "The access link has expired. To access again, request a new link.";

    const assistanceBtn = document.querySelector(
      "#sessionExpired .btn-whatsapp"
    );
    if (assistanceBtn) {
      assistanceBtn.href =
        "https://api.whatsapp.com/send?phone=+393898883634&text=Hi, I need a new access link";
      assistanceBtn.innerHTML =
        '<i class="fab fa-whatsapp"></i> Request new link';
    }

    const authCodeInput = qs("authCode");
    if (authCodeInput) {
      authCodeInput.placeholder = currentTokenCustomCode
        ? "Inserisci il codice dedicato del link"
        : "Inserisci il codice principale";
    }
  }

  function setupIntervals() {
    setupCodeChangeListener();

    timeCheckInterval = setInterval(async () => {
      const expired = await checkTimeLimit();
      if (!expired) {
        updateCheckinTimeDisplay();
      }
      updateLockUI();
    }, 1000);

    setInterval(updateCheckinTimeDisplay, 60000);
  }

  // =============================================
  // AVVIO/STOP
  // =============================================
  document.addEventListener("DOMContentLoaded", init);

  window.addEventListener("beforeunload", () => {
    if (timeCheckInterval) clearInterval(timeCheckInterval);
    if (codeCheckInterval) clearInterval(codeCheckInterval);
    if (LINK_CHECK_INTERVAL) clearInterval(LINK_CHECK_INTERVAL);
    stopTokenRealtimeListener();
    if (settingsRef) settingsRef.off && settingsRef.off();
  });

  // Export functions to global scope
  Object.assign(window, {
    qs,
    on,
    showNotification,
    formatTime,
    fetchWithTimeout,
    setStorage,
    getStorage,
    clearStorage,
    generateHash,
    loadSettingsFromFirebase,
    applyFirebaseSettings,
    setupSettingsListener,
    monitorFirebaseConnection,
    setUsageStartTime,
    checkTimeLimit,
    showFatalError,
    showSessionExpired,
    isSessionStuck,
    isCheckinTime,
    updateCheckinTimeDisplay,
    showEarlyCheckinPopup,
    closeEarlyCheckinPopup,
    updateStatusBar,
    getClicksLeft,
    setClicksLeft,
    updateButtonState,
    updateDoorVisibility,
    setupCodeChangeListener,
    checkCodeVersion,
    handleCodeChange,
    resetSessionForNewCode,
    checkExpiredLinks,
    showConfirmationPopup,
    closeConfirmationPopup,
    showDevicePopup,
    closePopup,
    activateDevice,
    handleSecureToken,
    stopTokenRealtimeListener,
    clearManualSession,
    blockAccess,
    unblockAccess,
    forceGlobalLogout,
    forceLogoutFromToken,
    startTokenRealtimeListener,
    validateSecureToken,
    incrementTokenUsage,
    showTokenNotification,
    showTokenError,
    cleanUrl,
    startTokenExpirationCheck,
    performManualLogin,
    handleCodeSubmit,
    init,
    setupEventListeners,
    showControlPanel,
    showAuthForm,
    setupTokenUI,
    setupIntervals,
    isLoginLocked,
    updateLockUI,
    incrementFailedAttempt,
    resetFailedAttempts,
  });
})();
