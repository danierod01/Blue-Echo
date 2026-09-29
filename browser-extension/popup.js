// Popup del scanner: envía el IOC al service worker, que hace la petición.

const form = document.getElementById("form");
const iocInput = document.getElementById("ioc");
const goBtn = document.getElementById("go");
const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");
const scoreEl = document.getElementById("score");
const verdictEl = document.getElementById("verdict");
const ioctypeEl = document.getElementById("ioctype");
const summaryEl = document.getElementById("summary");
const hintEl = document.getElementById("hint");

const VERDICT_LABEL = {
  clean: "LIMPIO",
  suspicious: "SOSPECHOSO",
  malicious: "MALICIOSO",
  critical: "CRÍTICO",
};

// Enlaces a las opciones.
for (const id of ["opts", "opts2"]) {
  document.getElementById(id)?.addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });
}

// Prerrellenar con el texto seleccionado en la pestaña activa, si lo hay.
chrome.tabs?.query({ active: true, currentWindow: true }, async ([tab]) => {
  try {
    const [res] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => window.getSelection().toString().trim(),
    });
    if (res?.result) iocInput.value = res.result;
  } catch { /* sin permiso de scripting en esta página: se ignora */ }
});

// Ocultar la pista si ya hay servidor configurado.
chrome.storage.sync.get(["baseUrl"]).then(({ baseUrl }) => {
  if (baseUrl) hintEl.hidden = true;
});

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const ioc = iocInput.value.trim();
  if (!ioc) return;

  setBusy(true);
  showStatus("Consultando fuentes de Threat Intelligence…");
  resultEl.hidden = true;

  const resp = await chrome.runtime.sendMessage({ type: "scan", ioc });
  setBusy(false);

  if (!resp || resp.error) {
    showStatus(resp?.error || "Error desconocido.", true);
    return;
  }
  renderResult(resp.data);
});

function renderResult(data) {
  statusEl.hidden = true;
  const verdict = data.verdict || "clean";
  scoreEl.textContent = data.score ?? "–";
  scoreEl.className = "score v-" + verdict;
  verdictEl.textContent = VERDICT_LABEL[verdict] || verdict.toUpperCase();
  verdictEl.className = "verdict v-" + verdict;
  ioctypeEl.textContent = `${data.ioc_value} · ${data.ioc_type}`;
  summaryEl.textContent = stripMarkdown(data.ai_summary || "");
  resultEl.hidden = false;
}

function showStatus(msg, isError) {
  statusEl.textContent = msg;
  statusEl.className = "status" + (isError ? " error" : "");
  statusEl.hidden = false;
}

function setBusy(busy) {
  goBtn.disabled = busy;
  iocInput.disabled = busy;
}

// Quita marcas Markdown básicas para mostrar el resumen en texto plano.
function stripMarkdown(s) {
  return s.replace(/[*_`#]/g, "").replace(/\n{2,}/g, "\n").trim();
}
