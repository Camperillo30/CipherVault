// CipherVault – extensión del navegador (S.C.A)
// Habla con la app de escritorio por "native messaging" (CipherVaultBridge.exe).
// Las contraseñas nunca se guardan en la extensión: se piden a la app en el momento
// de rellenar y solo para la página abierta.
"use strict";

const HOST = "com.sca.ciphervault";
const content = document.getElementById("content");
let tab = null;

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const child of children) node.append(child);
  return node;
}

function show(...nodes) {
  content.replaceChildren(...nodes);
}

function send(message) {
  return new Promise((resolve) => {
    chrome.runtime.sendNativeMessage(HOST, message, (response) => {
      if (chrome.runtime.lastError || !response) {
        resolve({ ok: false, error: "no_host" });
      } else {
        resolve(response);
      }
    });
  });
}

async function client() {
  const stored = await chrome.storage.local.get(["client_id", "client_key"]);
  if (stored.client_id && stored.client_key) return stored;
  const rand = (n) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => b.toString(16).padStart(2, "0")).join("");
  const fresh = { client_id: rand(8), client_key: rand(32) };
  await chrome.storage.local.set(fresh);
  return fresh;
}

async function request(action, extra = {}) {
  const c = await client();
  return send({ action, client_id: c.client_id, client_key: c.client_key, ...extra });
}

function browserName() {
  const brands = (navigator.userAgentData && navigator.userAgentData.brands) || [];
  const named = brands.map((b) => b.brand).find((b) => !/Not.?A.?Brand|Chromium/i.test(b));
  return named || "Navegador";
}

// Se ejecuta DENTRO de la página: rellena usuario y contraseña.
function fillPage(username, password) {
  const visible = (e) => !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length) &&
    getComputedStyle(e).visibility !== "hidden" && !e.disabled && !e.readOnly;
  const setValue = (input, value) => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    input.focus();
    setter.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const userSelector = 'input[autocomplete="username"], input[type="email"], input[type="text"], input[type="tel"], input:not([type])';
  const pass = Array.from(document.querySelectorAll('input[type="password"]')).find(visible);
  let user = null;
  if (pass) {
    const scope = pass.form || document;
    const candidates = Array.from(scope.querySelectorAll(userSelector)).filter(visible);
    user = candidates.filter((c) => c.compareDocumentPosition(pass) & Node.DOCUMENT_POSITION_FOLLOWING).pop() || null;
  } else {
    user = Array.from(document.querySelectorAll(userSelector)).find(visible) || null;
  }
  if (user && username) setValue(user, username);
  if (pass) {
    setValue(pass, password);
    return "filled";
  }
  return user ? "username_only" : "no_fields";
}

async function fill(item) {
  if (item.weak && !confirm(`«${item.service}» no tiene guardada esta dirección web.\n\n` +
      `Revisa que estás en el sitio real (${new URL(tab.url).hostname}) antes de continuar. ¿Rellenar?`)) {
    return;
  }
  const res = await request("credentials", { id: item.id, url: tab.url, confirm_weak: !!item.weak });
  if (!res.ok) return render();
  let result = "no_fields";
  try {
    const [out] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: fillPage,
      args: [res.username || "", res.password || ""],
    });
    result = out && out.result;
  } catch (e) {
    result = "blocked";
  }
  const parts = [];
  if (result === "filled") parts.push(el("h2", {}, "✅ Listo"));
  else if (result === "username_only") parts.push(el("h2", {}, "Usuario escrito"),
    el("p", { class: "muted" }, "Cuando aparezca el campo de contraseña, vuelve a abrir CipherVault."));
  else if (result === "blocked") parts.push(el("h2", {}, "Esta página no permite rellenar"),
    el("p", { class: "muted" }, "Usa Ctrl + Alt + A desde la app de CipherVault."));
  else parts.push(el("h2", {}, "No encontré dónde escribir"),
    el("p", { class: "muted" }, "Haz clic en el campo de usuario y usa Ctrl + Alt + A desde la app."));
  if (res.totp) {
    parts.push(el("p", { class: "section" }, "Código 2FA"), el("div", { class: "code" }, res.totp),
      el("button", { class: "small", onclick: async () => { await navigator.clipboard.writeText(res.totp); window.close(); } }, "Copiar código"));
  } else if (result === "filled") {
    setTimeout(() => window.close(), 700);
  }
  show(...parts);
}

async function render() {
  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let host = "";
  try { host = new URL(tab.url).hostname; } catch (e) { /* página interna */ }
  document.getElementById("site").textContent = host;
  if (!tab || !/^https?:/.test(tab.url || "")) {
    return show(el("p", { class: "muted" }, "Abre la página de inicio de sesión de un sitio web."));
  }
  const status = await request("status");
  if (status.error === "no_host") {
    return show(el("h2", {}, "No se encontró CipherVault"),
      el("p", { class: "muted" }, "Instala la app de CipherVault para Windows y ábrela al menos una vez."));
  }
  if (status.error === "app_closed") {
    return show(el("h2", {}, "Abre CipherVault"),
      el("p", { class: "muted" }, "La app de escritorio debe estar abierta para rellenar contraseñas."));
  }
  if (!status.associated) {
    return show(el("h2", {}, "Conecta la extensión"),
      el("p", { class: "muted" }, "La app te pedirá confirmar. Solo hay que hacerlo una vez en este navegador."),
      el("button", { class: "primary", onclick: async () => {
        show(el("p", { class: "muted" }, "Acepta la conexión en la ventana de CipherVault…"));
        const res = await request("associate", { browser: browserName() });
        if (!res.ok) return show(el("p", { class: "warn" }, "No se conectó. Vuelve a intentarlo y acepta en la app."));
        render();
      } }, "Conectar con CipherVault"));
  }
  if (!status.unlocked) {
    return show(el("h2", {}, "CipherVault está bloqueado"),
      el("p", { class: "muted" }, "Inicia sesión en la app y vuelve a abrir la extensión."),
      el("button", { class: "primary", onclick: () => { request("show"); window.close(); } }, "Abrir CipherVault"));
  }
  const res = await request("logins", { url: tab.url });
  if (!res.ok) return show(el("p", { class: "warn" }, "No se pudo consultar la app."));
  if (!res.items.length) {
    return show(el("h2", {}, "Sin contraseñas para este sitio"),
      el("p", { class: "muted" }, `Guarda en CipherVault una entrada con la página web ${host}.`));
  }
  const exact = res.items.filter((i) => !i.weak);
  const weak = res.items.filter((i) => i.weak);
  const button = (i) => el("button", { class: "item" + (i.weak ? " weak" : ""), onclick: () => fill(i) },
    el("strong", {}, i.service), el("span", { class: "user" }, i.username || "(sin usuario)"));
  const nodes = exact.map(button);
  if (weak.length) {
    nodes.push(el("p", { class: "section" }, "Posibles coincidencias (revisa la dirección)"), ...weak.map(button));
  }
  show(...nodes);
  const first = content.querySelector("button");
  if (first) first.focus();
}

render();
