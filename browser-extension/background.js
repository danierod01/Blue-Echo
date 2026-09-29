// Blue-Echo IOC Scanner — service worker (Manifest V3).
// Añade una opción al menú contextual para escanear el texto seleccionado
// (una IP, hash, dominio o URL) contra la instancia de Blue-Echo configurada.

const MENU_ID = "blue-echo-scan-selection";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: MENU_ID,
    title: 'Escanear "%s" en Blue-Echo',
    contexts: ["selection", "link"],
  });
});

chrome.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId !== MENU_ID) return;
  const ioc = (info.selectionText || info.linkUrl || "").trim();
  if (!ioc) return;
  await scanAndNotify(ioc);
});

async function getSettings() {
  const { baseUrl, apiKey } = await chrome.storage.sync.get(["baseUrl", "apiKey"]);
  return {
    baseUrl: (baseUrl || "").replace(/\/+$/, ""),
    apiKey: apiKey || "",
  };
}

/** Lanza el escaneo y muestra el resultado como notificación del sistema. */
async function scanAndNotify(ioc) {
  const { baseUrl, apiKey } = await getSettings();
  if (!baseUrl) {
    notify("Configura Blue-Echo", "Abre las opciones de la extensión y define la URL del servidor.");
    return;
  }
  try {
    const res = await fetch(`${baseUrl}/api/scan/json`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(apiKey ? { "X-API-Key": apiKey } : {}),
      },
      body: JSON.stringify({ ioc }),
    });
    if (!res.ok) {
      notify("Blue-Echo", `Error HTTP ${res.status} al escanear ${ioc}.`);
      return;
    }
    const data = await res.json();
    const verdict = (data.verdict || "").toUpperCase();
    notify(
      `${ioc} — ${verdict} (${data.score}/100)`,
      truncate(data.ai_summary || "Escaneo completado.", 180),
    );
  } catch (e) {
    notify("Blue-Echo", `No se pudo conectar con el servidor: ${e.message}`);
  }
}

function notify(title, message) {
  chrome.notifications.create({
    type: "basic",
    iconUrl: "icon.svg",
    title,
    message,
  });
}

function truncate(s, n) {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

// Exponer para el popup (mensajería).
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === "scan") {
    doScan(msg.ioc).then(sendResponse);
    return true; // respuesta asíncrona
  }
});

async function doScan(ioc) {
  const { baseUrl, apiKey } = await getSettings();
  if (!baseUrl) return { error: "Configura la URL del servidor en las opciones." };
  try {
    const res = await fetch(`${baseUrl}/api/scan/json`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(apiKey ? { "X-API-Key": apiKey } : {}),
      },
      body: JSON.stringify({ ioc: ioc.trim() }),
    });
    if (!res.ok) {
      let detail = `Error HTTP ${res.status}`;
      try { detail = (await res.json()).detail || detail; } catch { /* ignore */ }
      return { error: detail };
    }
    return { data: await res.json() };
  } catch (e) {
    return { error: `No se pudo conectar: ${e.message}` };
  }
}
