// Guarda/carga la configuración de la extensión (URL del servidor + API key).

const baseUrlEl = document.getElementById("baseUrl");
const apiKeyEl = document.getElementById("apiKey");
const okEl = document.getElementById("ok");

// Cargar valores guardados.
chrome.storage.sync.get(["baseUrl", "apiKey"]).then(({ baseUrl, apiKey }) => {
  baseUrlEl.value = baseUrl || "";
  apiKeyEl.value = apiKey || "";
});

document.getElementById("save").addEventListener("click", async () => {
  const baseUrl = baseUrlEl.value.trim().replace(/\/+$/, "");
  const apiKey = apiKeyEl.value.trim();
  await chrome.storage.sync.set({ baseUrl, apiKey });
  okEl.hidden = false;
  setTimeout(() => { okEl.hidden = true; }, 2000);
});
