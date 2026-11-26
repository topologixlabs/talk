"use strict";
// All text is inserted with textContent, so message content can never become markup.

const PEOPLE = ["alice", "bob", "carol"];
const cap = (s) => s[0].toUpperCase() + s.slice(1);
const root = document.getElementById("root");
const state = { stage: "new", person: "alice", chat: null, view: null, draft: "", link: { stage: "off" }, linkOpen: false, linkDraft: "", pane: "list", platform: "" };
const phone = () => state.platform === "ios" || window.matchMedia("(max-width: 760px)").matches;
const desktopOnly = () => state.platform === "ios";

async function call(name, args = {}) {
  if (window.__TAURI__) return window.__TAURI__.core.invoke("cmd", { name, args });
  const r = await fetch("/api", { method: "POST", body: JSON.stringify({ name, args }) });
  const j = await r.json();
  if (j.error !== undefined) throw j.error;
  return j.ok;
}

function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "text") el.textContent = v;
    else if (v === true) el.setAttribute(k, "");
    else if (v !== false && v != null) el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid != null) el.append(kid);
  return el;
}

let toastTimer;
function toast(text) {
  const t = document.getElementById("toast");
  t.textContent = text;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 3500);
}

async function act(fn) {
  try { const out = await fn(); await refresh(); return out; }
  catch (err) { toast(String(err)); }
}

async function refresh() {
  const status = await call("status");
  state.stage = status.stage;
  state.platform = status.platform || "";
  if (state.stage === "open") {
    state.view = await call("view", { person: state.person });
    if (!state.view.chats.some((c) => c.id === state.chat)) state.chat = state.view.chats[0]?.id ?? null;
    state.link = await call("linkStatus");
    if (state.link.stage !== "connected") state.linkOpen = false;
  } else { state.view = null; state.chat = null; state.link = { stage: "off" }; state.linkOpen = false; }
  render();
}

function gate() {
  const isNew = state.stage === "new";
  const err = h("div", { class: "error", role: "alert" });
  const pass = h("input", { type: "password", id: "pass", autocomplete: "new-password", required: true });
  const again = isNew ? h("input", { type: "password", id: "again", autocomplete: "new-password", required: true }) : null;
  const submit = async (e) => {
    e.preventDefault();
    err.textContent = "";
    if (isNew && pass.value !== again.value) { err.textContent = "The passphrases do not match"; return; }
    const btn = e.target.querySelector("button.primary");
    btn.disabled = true;
    try {
      await call(isNew ? "create" : "unlock", { passphrase: pass.value });
      pass.value = "";
      if (again) again.value = "";
      await refresh();
    } catch (x) { err.textContent = String(x); btn.disabled = false; }
  };
  const reset = () => confirmDialog("Delete test workspace?",
    "This permanently deletes the workspace and all its fictional chats. It cannot be undone.",
    "Delete workspace", () => act(() => call("reset", { confirm: "RESET" })));
  return h("div", { class: "gate" }, h("form", { onsubmit: submit },
    h("div", { class: "mark", "aria-hidden": "true" }, h("i"), h("i")),
    h("h1", { text: isNew ? "Set up Talk" : "Unlock Talk" }),
    h("p", { class: "muted", text: isNew
      ? "This private test creates three fictional people on this device, so you can see both sides of an encrypted chat."
      : "Enter the passphrase for this test workspace." }),
    h("div", { class: "notice", text: "Test version. Do not enter real messages or personal information." }),
    h("label", { class: "field" }, isNew ? "Create a passphrase (12 or more characters)" : "Passphrase", pass),
    isNew ? h("label", { class: "field" }, "Repeat passphrase", again) : null,
    err,
    h("button", { class: "primary", type: "submit", text: isNew ? "Create workspace" : "Unlock" }),
    isNew ? h("p", { class: "muted small", text: "If you forget it, the workspace cannot be recovered." })
          : h("button", { class: "link", type: "button", onclick: reset, text: "Forgot it? Delete test workspace" }),
  ));
}

let dialogReturn = null;
function closeDialog() {
  const o = document.querySelector(".overlay");
  if (!o) return;
  o.remove();
  // Return focus to the control that opened the dialog, so keyboard and screen-reader users keep their place.
  if (dialogReturn?.isConnected) dialogReturn.focus();
  dialogReturn = null;
}

function dialog(...kids) {
  closeDialog();
  dialogReturn = document.activeElement;
  const box = h("div", { class: "dialog", role: "dialog", "aria-modal": "true" }, ...kids);
  const title = box.querySelector("h2");
  if (title) { title.id = "dialog-title"; box.setAttribute("aria-labelledby", "dialog-title"); }
  // Keep Tab inside the open dialog.
  box.addEventListener("keydown", (e) => {
    if (e.key !== "Tab") return;
    const items = [...box.querySelectorAll("button:not(:disabled),input:not(:disabled),textarea:not(:disabled),select:not(:disabled),[href]")];
    if (!items.length) return;
    const first = items[0], last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  });
  const o = h("div", { class: "overlay", onmousedown: (e) => { if (e.target === o) closeDialog(); } }, box);
  o.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDialog(); });
  document.body.append(o);
  (box.querySelector("input,button.primary") || box.querySelector("button"))?.focus();
}

// Native confirm boxes are unreliable in desktop web views, so the app draws its own.
function confirmDialog(title, body, label, onYes) {
  dialog(
    h("h2", { text: title }),
    h("p", { class: "muted", text: body }),
    h("div", { class: "actions" },
      h("button", { text: "Cancel", onclick: closeDialog }),
      h("button", { class: "primary", text: label, onclick: async () => { closeDialog(); await onYes(); } })),
  );
}

async function verifyDialog(other) {
  const me = state.person;
  let c;
  try { c = await call("codes", { a: me, b: other }); } catch (x) { toast(String(x)); return; }
  const tick = h("input", { type: "checkbox", id: "same" });
  const ok = h("button", { class: "primary", disabled: true, text: "Mark as verified",
    onclick: async () => { closeDialog(); await act(() => call("verify", { a: me, b: other })); toast(`${cap(me)} and ${cap(other)} are verified`); } });
  tick.addEventListener("change", () => { ok.disabled = !tick.checked; });
  dialog(
    h("h2", { text: `Verify ${cap(other)}` }),
    h("p", { class: "muted", text: "Real users would compare these codes in person or on a call. A different code means someone may be intercepting the chat." }),
    h("div", { class: "codes" },
      h("div", {}, h("b", { text: `${cap(me)} sees` }), h("code", { text: c.codeA })),
      h("div", {}, h("b", { text: `${cap(other)} sees` }), h("code", { text: c.codeB }))),
    h("label", { class: "check" }, tick, "The two codes are identical"),
    h("div", { class: "actions" }, h("button", { text: "Cancel", onclick: closeDialog }), ok),
  );
}

function newChatDialog() {
  const others = PEOPLE.filter((p) => p !== state.person);
  const verified = new Set(state.view.people.filter((p) => p.verified).map((p) => p.name));
  const title = h("input", { id: "chat-title", maxlength: 60, placeholder: "For example: Project notes" });
  const boxes = others.map((p) => {
    const b = h("input", { type: "checkbox", value: p, disabled: !verified.has(p), checked: verified.has(p) && others.length === 1 });
    return { p, b, row: h("label", { class: "check" }, b, verified.has(p) ? cap(p) : `${cap(p)} (verify first)`) };
  });
  const err = h("div", { class: "error", role: "alert" });
  const create = async () => {
    const members = boxes.filter((x) => x.b.checked).map((x) => x.p);
    if (!title.value.trim()) { err.textContent = "Give the chat a name"; return; }
    if (!members.length) { err.textContent = "Choose at least one person"; return; }
    try {
      const out = await call("createChat", { person: state.person, title: title.value, members });
      closeDialog(); state.chat = out.id; state.pane = "chat"; await refresh();
    } catch (x) { err.textContent = String(x); }
  };
  dialog(
    h("h2", { text: "New encrypted chat" }),
    h("label", { class: "field" }, "Chat name", title),
    h("div", { class: "field" }, "People", boxes.map((x) => x.row)),
    err,
    h("div", { class: "actions" }, h("button", { text: "Cancel", onclick: closeDialog }), h("button", { class: "primary", text: "Create chat", onclick: create })),
  );
}

// Talk only hands the text to WhatsApp. The person chooses who gets it and presses send there.
function whatsappDialog(text) {
  const err = h("div", { class: "error", role: "alert" });
  const open = async () => {
    err.textContent = "";
    if (!window.__TAURI__) { err.textContent = "WhatsApp can only be opened from the Mac app"; return; }
    try {
      await window.__TAURI__.core.invoke("share_whatsapp", { text });
      closeDialog();
      toast("WhatsApp is open. Choose a person and press send there");
    } catch (x) { err.textContent = String(x); }
  };
  dialog(
    h("h2", { text: "Share to WhatsApp?" }),
    h("div", { class: "share-text", text }),
    h("p", { class: "muted", text: "WhatsApp will open with this text ready. You choose the person and press send there." }),
    h("div", { class: "notice", text: "Once it leaves Talk, this message has WhatsApp's encryption, not Talk's quantum-resistant encryption." }),
    err,
    h("div", { class: "actions" },
      h("button", { text: "Cancel", onclick: closeDialog }),
      h("button", { class: "primary", text: "Open WhatsApp", onclick: open })),
  );
}

// Talk only hands the text to Apple's compose window. The person chooses who gets it and presses send there.
function imessageDialog(text) {
  const err = h("div", { class: "error", role: "alert" });
  const open = async () => {
    err.textContent = "";
    if (!window.__TAURI__) { err.textContent = "Messages can only be opened from the Mac app"; return; }
    try {
      await window.__TAURI__.core.invoke("share_imessage", { text });
      closeDialog();
      toast("Messages is open. Choose a person and press send there");
    } catch (x) { err.textContent = String(x); }
  };
  dialog(
    h("h2", { text: "Share to iMessage?" }),
    h("div", { class: "share-text", text }),
    h("p", { class: "muted", text: "Apple's compose window will open with this text ready. You choose the person and press send there." }),
    h("div", { class: "notice", text: "Once it leaves Talk, this message does not have Talk's quantum-resistant encryption. If Messages sends it as SMS, it is not end-to-end encrypted." }),
    err,
    h("div", { class: "actions" },
      h("button", { text: "Cancel", onclick: closeDialog }),
      h("button", { class: "primary", text: "Open Messages", onclick: open })),
  );
}

// ---------- Linked device ----------

async function connectSpark() {
  const err = h("div", { class: "error", role: "alert" });
  const go = h("button", { class: "primary", text: "Connect" });
  const cancel = h("button", { text: "Cancel", onclick: closeDialog });
  go.addEventListener("click", async () => {
    err.textContent = "";
    go.disabled = cancel.disabled = true;
    go.textContent = "Connecting";
    try {
      state.link = await call("linkStart");
      compareCodes();
    } catch (x) {
      err.textContent = String(x);
      go.disabled = cancel.disabled = false;
      go.textContent = "Try again";
    }
  });
  dialog(
    h("h2", { text: "Connect spark-a" }),
    h("p", { class: "muted", text: "Talk starts a temporary encrypted relay on spark-a, reachable only over your private Tailscale network. It stops when you disconnect, or after 30 minutes." }),
    h("div", { class: "notice", text: "Test link. Use fictional messages only. spark-a replies automatically to prove it decrypted them." }),
    err,
    h("div", { class: "actions" }, cancel, go),
  );
}

function compareCodes() {
  const err = h("div", { class: "error", role: "alert" });
  const tick = h("input", { type: "checkbox", id: "same" });
  const stop = h("button", { text: "Cancel", onclick: async () => { closeDialog(); await act(() => call("linkStop")); } });
  const ok = h("button", { class: "primary", disabled: true, text: "Verify and connect" });
  tick.addEventListener("change", () => { ok.disabled = !tick.checked; });
  ok.addEventListener("click", async () => {
    ok.disabled = stop.disabled = true;
    ok.textContent = "Connecting";
    try {
      state.link = await call("linkConfirm");
      closeDialog();
      state.linkOpen = true;
      render();
      document.getElementById("link-composer")?.focus();
    } catch (x) { err.textContent = String(x); stop.disabled = false; }
  });
  dialog(
    h("h2", { text: "Compare safety codes" }),
    h("p", { class: "muted", text: "Each device calculated this code on its own. If they differ, someone may be intercepting the link." }),
    h("div", { class: "codes" },
      h("div", {}, h("b", { text: "This Mac" }), h("code", { text: state.link.macCode })),
      h("div", {}, h("b", { text: "spark-a" }), h("code", { text: state.link.sparkCode }))),
    h("label", { class: "check" }, tick, "The two codes are identical"),
    err,
    h("div", { class: "actions" }, stop, ok),
  );
}

function devicesSection() {
  if (desktopOnly()) return null;
  const l = state.link;
  const row = l.stage === "connected"
    ? h("button", { class: "chatrow device", "aria-current": String(state.linkOpen), onclick: () => { state.linkOpen = true; state.pane = "chat"; render(); } },
        h("b", {}, h("i", { class: "live" }), "spark-a"), h("span", { text: "Connected over Tailscale" }))
    : h("div", { class: "device-off" }, h("span", { text: "spark-a" }),
        h("button", { text: l.stage === "verify" ? "Verify" : "Connect", onclick: l.stage === "verify" ? compareCodes : connectSpark }));
  return h("div", { class: "devices" }, h("h2", { text: "Devices" }), row);
}

function linkMain() {
  const l = state.link;
  const log = h("div", { class: "log", role: "log", "aria-label": "Messages with spark-a" },
    l.messages.length ? l.messages.map((m) => h("div", { class: "msg" + (m.from === "mac" ? " me" : "") },
      h("small", { text: `${m.from === "mac" ? "This Mac" : "spark-a"} · ${time(m.at)}` }), m.text))
      : h("div", { class: "empty" }, h("h2", { text: "Linked to spark-a" }),
          h("p", { class: "muted", text: "Send a fictional message. spark-a decrypts it and replies over the same encrypted link." })));
  const box = h("textarea", { id: "link-composer", "aria-label": "Message to spark-a", placeholder: "Message spark-a", maxlength: 3900 });
  box.value = state.linkDraft;
  box.addEventListener("input", () => { state.linkDraft = box.value; });
  const send = async () => {
    const text = box.value.trim();
    if (!text) return;
    state.linkDraft = "";
    box.value = "";
    try { state.link = await call("linkSend", { text }); render(); }
    catch (x) { state.linkDraft = text; toast(String(x)); render(); }
    document.getElementById("link-composer")?.focus();
  };
  box.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); send(); } });
  queueMicrotask(() => { log.scrollTop = log.scrollHeight; });
  return h("main", { class: "main" },
    h("div", { class: "chathead" }, backToChats(), h("h2", { text: "spark-a" }), h("div", { class: "muted small", text: "Second device · private network" }), detailsButton()),
    h("div", { class: "trust" }, h("i"), "Quantum-resistant, end to end · device verified"),
    log,
    h("div", { class: "compose" }, box, h("button", { class: "primary", text: "Send", onclick: send })),
  );
}

function linkInfo() {
  const l = state.link;
  return h("aside", { class: "info" }, backToChat(),
    h("section", { class: "section" }, h("h3", { text: "Device link" }),
      h("dl", {},
        h("dt", { text: "Device" }), h("dd", { text: "spark-a" }),
        h("dt", { text: "Network" }), h("dd", { text: "Tailscale only" }),
        h("dt", { text: "Connection" }), h("dd", { text: l.transport.replace("NamedGroup::", "") || "TLS 1.3" }),
        h("dt", { text: "Message keys" }), h("dd", { text: "X25519 + ML-KEM-768" }),
        h("dt", { text: "Signatures" }), h("dd", { text: "Ed25519 (classical)" }),
        h("dt", { text: "Group check" }), h("dd", { text: l.check })),
      h("div", { class: "row" }, h("button", { class: "danger", text: "Disconnect", onclick: () => confirmDialog("Disconnect spark-a?",
        "This ends the link, deletes its temporary keys and files on both devices, and clears this conversation.",
        "Disconnect", () => act(() => call("linkStop"))) }))));
}

let polling = false;
setInterval(async () => {
  if (polling || state.stage !== "open" || state.link.stage !== "connected") return;
  polling = true;
  try {
    const before = state.link.messages.length;
    const next = await call("linkPoll");
    if (state.link.stage === "connected" && next.stage === "connected") {
      state.link = next;
      if (state.linkOpen && next.messages.length !== before) {
        const focused = document.activeElement?.id === "link-composer";
        render();
        if (focused) {
          const c = document.getElementById("link-composer");
          c?.focus();
          c?.setSelectionRange(c.value.length, c.value.length);
        }
      }
    }
  } catch (x) { toast(String(x)); }
  polling = false;
}, 900);

// ---------- Phone navigation ----------

function backToChats() {
  return phone() ? h("button", { class: "nav-back", "aria-label": "Back to chats", text: "‹ Chats", onclick: () => { state.pane = "list"; render(); } }) : null;
}

function detailsButton() {
  return phone() ? h("button", { class: "nav-details", text: "Details", onclick: () => { state.pane = "info"; render(); } }) : null;
}

function backToChat() {
  return phone() ? h("div", { class: "info-nav" }, h("button", { class: "nav-back", "aria-label": "Back to conversation", text: "‹ Back", onclick: () => { state.pane = "chat"; render(); } })) : null;
}

let wasPhone = null;

// When the on-screen keyboard opens, iOS shrinks the visible area and may pan the page.
// Talk sizes itself to the visible area instead, so the conversation stays in view.
function fitViewport() {
  const v = window.visualViewport;
  if (!v) return;
  document.documentElement.style.setProperty("--app-h", `${Math.round(v.height)}px`);
  if (window.scrollY !== 0 || v.offsetTop !== 0) window.scrollTo(0, 0);
}
window.visualViewport?.addEventListener("resize", fitViewport);
window.visualViewport?.addEventListener("scroll", fitViewport);
fitViewport();
window.addEventListener("resize", () => { if (phone() !== wasPhone && state.stage === "open") render(); });

function sidebar() {
  const v = state.view;
  return h("aside", { class: "side" },
    h("div", { class: "brand" }, h("div", { class: "mark", "aria-hidden": "true" }, h("i"), h("i")), h("b", { text: "Talk" }), h("span", { class: "tag", text: "Local test" })),
    h("div", { class: "persona" }, h("span", { text: "Viewing as" }),
      h("div", { class: "seg", role: "group", "aria-label": "Viewing as" }, PEOPLE.map((p) =>
        h("button", { "aria-pressed": String(p === state.person), text: cap(p), onclick: () => { state.person = p; state.chat = null; state.draft = ""; state.linkOpen = false; act(async () => {}); } })))),
    h("div", { class: "listhead" }, h("h2", { text: "Chats" }), h("button", { class: "primary", text: "New", onclick: newChatDialog })),
    h("div", { class: "chats" }, v.chats.length ? v.chats.map((c) => {
      const last = c.messages[c.messages.length - 1];
      return h("button", { class: "chatrow", "aria-current": String(!state.linkOpen && c.id === state.chat), onclick: () => { state.chat = c.id; state.draft = ""; state.linkOpen = false; state.pane = "chat"; render(); } },
        h("b", { text: c.title }),
        h("span", { text: c.left ? "You left this chat" : last ? `${cap(last.from)}: ${last.text}` : "No messages yet" }));
    }) : h("p", { class: "muted small nochats", text: "No chats yet" })),
    devicesSection(),
    h("div", { class: "sidefoot" }, h("button", { class: "link", text: "Lock", onclick: () => act(() => call("lock")) })),
  );
}

const time = (t) => new Date(t * 1000).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });

function main(chat) {
  if (!chat) {
    const anyVerified = state.view.people.some((p) => p.verified);
    return h("main", { class: "main" }, h("div", { class: "empty" },
      h("h2", { text: anyVerified ? "Start a chat" : "Verify someone first" }),
      h("p", { class: "muted", text: anyVerified
        ? "Choose New to create an encrypted chat with someone you have verified."
        : "Talk only lets you chat with people whose safety code you have checked. Choose Verify next to a person on the right." }),
      anyVerified ? h("div", {}, h("button", { class: "primary", text: "New chat", onclick: newChatDialog })) : null));
  }
  const log = h("div", { class: "log", role: "log", "aria-label": "Messages" },
    chat.messages.length ? chat.messages.map((m) => h("div", { class: "msg" + (m.from === state.person ? " me" : "") },
      h("small", { text: `${m.from === state.person ? "You" : cap(m.from)} · ${time(m.at)}` }), m.text))
      : h("div", { class: "empty" }, h("p", { class: "muted", text: "No messages yet. Messages are encrypted on this person's device before they leave it." })));
  const box = h("textarea", { id: "composer", "aria-label": "Message", placeholder: chat.left ? "You are no longer in this chat" : `Message as ${cap(state.person)}`, maxlength: 4000, disabled: chat.left });
  box.value = state.draft;
  const share = h("button", { text: "WhatsApp", "aria-label": "Share to WhatsApp", title: "Share to WhatsApp", disabled: chat.left || !state.draft.trim(), onclick: () => whatsappDialog(box.value.trim()) });
  const imessage = h("button", { text: "iMessage", "aria-label": "Share to iMessage", title: "Share to iMessage", disabled: chat.left || !state.draft.trim(), onclick: () => imessageDialog(box.value.trim()) });
  box.addEventListener("input", () => { state.draft = box.value; share.disabled = imessage.disabled = chat.left || !box.value.trim(); });
  const send = async () => {
    const text = box.value.trim();
    if (!text) return;
    state.draft = "";
    await act(() => call("send", { person: state.person, chat: chat.id, text }));
    document.getElementById("composer")?.focus();
  };
  box.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); send(); } });
  queueMicrotask(() => { log.scrollTop = log.scrollHeight; });
  return h("main", { class: "main" },
    h("div", { class: "chathead" }, backToChats(), h("h2", { text: chat.title }),
      h("div", { class: "muted small", text: chat.left ? "You are no longer a member" : chat.members.map(cap).join(", ") }), detailsButton()),
    chat.left
      ? h("div", { class: "trust off" }, h("i"), "You left: new messages cannot be read")
      : chat.sameHistory
        ? h("div", { class: "trust" }, h("i"), "Quantum-resistant, end to end · everyone verified")
        : h("div", { class: "trust off" }, h("i"), "Warning: members have different histories. Do not trust this chat"),
    log,
    h("div", { class: "compose" }, box, desktopOnly() ? null : share, desktopOnly() ? null : imessage, h("button", { class: "primary", text: "Send", disabled: chat.left, onclick: send })),
  );
}

function infoPanel(chat) {
  const v = state.view;
  const people = h("section", { class: "section" }, h("h3", { text: `${cap(state.person)}'s verified people` }),
    v.people.map((p) => h("div", { class: "person" }, h("span", { text: cap(p.name) }),
      p.verified ? h("span", { class: "badge ok", text: "Verified" }) : h("button", { text: "Verify", onclick: () => verifyDialog(p.name) }))));
  if (!chat) return h("aside", { class: "info" }, backToChat(), people);
  const outsiders = PEOPLE.filter((p) => !chat.members.includes(p));
  const manage = chat.left ? null : h("section", { class: "section" }, h("h3", { text: "Members" }),
    chat.members.map((m) => h("div", { class: "person" }, h("span", { text: m === state.person ? `${cap(m)} (you)` : cap(m) }),
      m === state.person ? null : h("button", { class: "danger", text: "Remove", onclick: () => confirmDialog(`Remove ${cap(m)}?`,
        "They will keep messages they already received, but will not be able to read new ones.",
        "Remove", () => act(() => call("removeMember", { person: state.person, chat: chat.id, member: m }))) }))),
    outsiders.map((m) => h("div", { class: "person" }, h("span", { class: "muted", text: cap(m) }),
      h("button", { text: "Add", onclick: () => act(() => call("addMember", { person: state.person, chat: chat.id, member: m })) }))));
  const security = chat.left ? null : h("section", { class: "section" }, h("h3", { text: "Security" }),
    h("dl", {},
      h("dt", { text: "Key exchange" }), h("dd", { text: "X25519 + ML-KEM-768" }),
      h("dt", { text: "Signatures" }), h("dd", { text: "Ed25519 (classical)" }),
      h("dt", { text: "Key generation" }), h("dd", { text: String(chat.epoch) }),
      h("dt", { text: "Group check" }), h("dd", { text: chat.check }),
      h("dt", { text: "Same history" }), h("dd", { text: chat.sameHistory ? "Yes, all members" : "No, do not trust" })),
    h("div", { class: "row" },
      h("button", { text: "Rotate keys", onclick: async () => { await act(() => call("rotate", { person: state.person, chat: chat.id })); toast("New keys are in use"); } }),
      h("button", { text: "Test tampering", onclick: async () => {
        const r = await act(() => call("tamper", { person: state.person, chat: chat.id }));
        if (r) toast(r.rejected ? `Altered message rejected by ${cap(r.recipient)}` : "WARNING: altered message was accepted");
      } })));
  return h("aside", { class: "info" }, backToChat(), people, manage, security);
}

function render() {
  root.replaceChildren();
  if (state.stage !== "open") { root.append(gate()); document.getElementById("pass")?.focus(); return; }
  const chat = state.view.chats.find((c) => c.id === state.chat) ?? null;
  const linked = state.linkOpen && state.link.stage === "connected";
  wasPhone = phone();
  if (state.pane !== "list" && !chat && !linked) state.pane = "list";
  root.append(h("div", { class: "shell" + (wasPhone ? " phone" : ""), "data-pane": state.pane }, sidebar(), linked ? linkMain() : main(chat), linked ? linkInfo() : infoPanel(chat)));
}

refresh().catch((x) => toast(String(x)));
