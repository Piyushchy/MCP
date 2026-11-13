/* mcpgate site. No dependencies, no network requests. */
(function () {
  "use strict";
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  function store(k, v) { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (e) { return null; } }

  /* ---------- theme ---------- */
  $("#theme").addEventListener("click", function () {
    var root = document.documentElement;
    var current = root.dataset.theme || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    var next = current === "dark" ? "light" : "dark";
    root.dataset.theme = next;
    store("mcpgate-theme", next);
  });

  /* ---------- the patch panel ---------- */
  var rack = $("#rack");
  var svg = $("#cables");
  var NS = "http://www.w3.org/2000/svg";
  var slots = $$(".slot", rack);
  var checks = $$("input[type=checkbox]", rack);
  var own = { n: 8, min: 1, max: 40 };
  var shown = { before: 0, after: 0 };
  var BAR_MAX = 46 + 1 + own.max;

  function tools(input) { return input.hasAttribute("data-own") ? own.n : Number(input.dataset.tools); }
  function total() { return checks.reduce(function (sum, c) { return sum + (c.checked ? tools(c) : 0); }, 0); }

  function tween(el, key, to) {
    var from = shown[key];
    shown[key] = to;
    if (reduced || from === to) { el.textContent = to; return; }
    var t0 = performance.now(), dur = 420;
    (function frame(now) {
      var p = Math.min(1, (now - t0) / dur);
      var e = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(from + (to - from) * e);
      if (p < 1 && shown[key] === to) requestAnimationFrame(frame); else el.textContent = shown[key];
    })(t0);
  }

  function meters() {
    var n = total();
    tween($("#n-before"), "before", n);
    tween($("#n-after"), "after", 5);
    $("#b-before").style.width = Math.min(100, n / BAR_MAX * 100) + "%";
    $("#b-after").style.width = (5 / BAR_MAX * 100) + "%";
    $$(".ct", rack).forEach(function (el) {
      var input = el.closest(".slot").querySelector("input[type=checkbox]");
      if (input.hasAttribute("data-own")) el.textContent = own.n === 1 ? "tool it offers" : "tools it offers";
    });
  }

  var paths = [];
  function layout(animate) {
    var box = svg.getBoundingClientRect();
    var w = Math.max(60, box.width), h = Math.max(120, box.height);
    svg.setAttribute("viewBox", "0 0 " + w + " " + h);
    svg.textContent = "";
    paths = [];
    var midY = h / 2;
    slots.forEach(function (slot, i) {
      var r = slot.getBoundingClientRect();
      var y = r.top + r.height / 2 - box.top;
      var p = document.createElementNS(NS, "path");
      p.setAttribute("d", "M0 " + y.toFixed(1) + " C " + (w * .55).toFixed(1) + " " + y.toFixed(1) + ", " + (w * .45).toFixed(1) + " " + midY.toFixed(1) + ", " + w + " " + midY.toFixed(1));
      p.setAttribute("class", "cable" + (checks[i].checked ? " on" : ""));
      svg.appendChild(p);
      paths.push(p);
    });
    if (animate && !reduced) paths.forEach(function (p, i) { if (checks[i].checked) plug(p, 140 * i); });
  }
  function plug(p, delay) {
    var len = Math.ceil(p.getTotalLength());
    p.style.setProperty("--len", len);
    p.style.animationDelay = (delay || 0) + "ms";
    p.classList.remove("draw");
    void p.getBoundingClientRect();
    p.classList.add("draw");
  }

  checks.forEach(function (c, i) {
    c.addEventListener("change", function () {
      var p = paths[i];
      if (p) {
        p.classList.toggle("on", c.checked);
        if (c.checked && !reduced) plug(p, 0); else p.classList.remove("draw");
      }
      meters();
    });
  });
  function step(d) {
    own.n = Math.max(own.min, Math.min(own.max, own.n + d));
    $("#own-n").textContent = own.n;
    meters();
  }
  $("#own-less").addEventListener("click", function () { step(-1); });
  $("#own-more").addEventListener("click", function () { step(1); });

  meters();
  layout(true);
  if (window.ResizeObserver) new ResizeObserver(function () { layout(false); }).observe(rack);
  else window.addEventListener("resize", function () { layout(false); });
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(function () { layout(false); });

  /* ---------- admin page gallery ---------- */
  var pages = [
    { id: "overview", tab: "Overview", url: "#/overview", title: "Where things stand", text: "How many servers are connected, what is waiting for you, whether remote access is on, and a four-step list to get started: register a server, choose what the model may do, connect claude.ai, then add it there." },
    { id: "add", tab: "Add a server", url: "#/backends", title: "Add anything that speaks MCP", text: "Pick a preset such as GitHub or Google Colab, a remote server by address, or a command that runs on your computer. Tokens, headers and environment variables go into a private store as you type them." },
    { id: "approvals", tab: "Approvals", url: "#/approvals", title: "Say yes or no to risky calls", text: "Tools you marked as needing approval wait here with the exact arguments they were called with. Approve once, for a while, or deny." },
    { id: "remote", tab: "Remote access", url: "#/remote", title: "Reach it from claude.ai", text: "Your public address, the switch that lets apps sign in with your approval passphrase, a check that reports what an outside app would see, and setup steps for Tailscale Funnel or Cloudflare." },
    { id: "credentials", tab: "Credentials", url: "#/secrets", title: "Replace a token without starting over", text: "Every token mcpgate uses to sign in to your servers, which servers use it, and buttons to replace or delete it. The value is never shown again." },
    { id: "edit", tab: "Edit a server", url: "#/backends", title: "Change a server in place", text: "Edit an address, command or header, or paste a new token, without removing the server and adding it again." },
    { id: "activity", tab: "Activity", url: "#/activity", title: "See what happened", text: "Every tool call and every change on the admin page, newest first, with filters, paging and a download button." },
    { id: "wizard", tab: "Guided setup", url: "#/", title: "A first run that explains itself", text: "Passphrase, first server, a test, and the line that connects your app. It opens once on a fresh install and can be reopened from Settings." }
  ];
  var tabs = $("#gtabs"), frame = $("#gframe"), cap = $("#gcap"), gurl = $("#gurl");
  function showPage(i, focus) {
    var p = pages[i];
    $$("button", tabs).forEach(function (b, j) { b.setAttribute("aria-selected", j === i ? "true" : "false"); b.tabIndex = j === i ? 0 : -1; });
    frame.textContent = "";
    ["light", "dark"].forEach(function (t) {
      var img = document.createElement("img");
      img.className = t;
      img.src = "assets/img/" + p.id + "-" + t + ".webp";
      img.alt = t === "light" ? "Screenshot of the " + p.tab + " page" : "";
      img.loading = "lazy"; img.decoding = "async";
      frame.appendChild(img);
    });
    gurl.textContent = "127.0.0.1:8767/" + p.url;
    cap.textContent = "";
    var h = document.createElement("h3"); h.textContent = p.title;
    var t = document.createElement("p"); t.textContent = p.text;
    cap.appendChild(h); cap.appendChild(t);
    frame.setAttribute("aria-labelledby", "g-" + p.id);
    if (focus) $$("button", tabs)[i].focus();
  }
  pages.forEach(function (p, i) {
    var b = document.createElement("button");
    b.type = "button"; b.id = "g-" + p.id; b.setAttribute("role", "tab"); b.textContent = p.tab;
    b.addEventListener("click", function () { showPage(i); });
    tabs.appendChild(b);
  });
  arrowKeys(tabs, function (i) { showPage(i, true); });
  showPage(0);

  /* ---------- app tabs (claude.ai / same computer / other) ---------- */
  var ctabs = $("#ctabs"), cbtns = $$("button", ctabs);
  function showApp(i, focus) {
    cbtns.forEach(function (b, j) {
      var on = j === i;
      b.setAttribute("aria-selected", on ? "true" : "false");
      b.tabIndex = on ? 0 : -1;
      $("#" + b.getAttribute("aria-controls")).hidden = !on;
    });
    if (focus) cbtns[i].focus();
  }
  cbtns.forEach(function (b, i) { b.addEventListener("click", function () { showApp(i); }); });
  arrowKeys(ctabs, function (i) { showApp(i, true); });

  function arrowKeys(list, go) {
    list.addEventListener("keydown", function (e) {
      var btns = $$("button", list);
      var i = btns.indexOf(document.activeElement);
      if (i < 0) return;
      var next = null;
      if (e.key === "ArrowDown" || e.key === "ArrowRight") next = (i + 1) % btns.length;
      else if (e.key === "ArrowUp" || e.key === "ArrowLeft") next = (i - 1 + btns.length) % btns.length;
      else if (e.key === "Home") next = 0;
      else if (e.key === "End") next = btns.length - 1;
      if (next !== null) { e.preventDefault(); go(next); }
    });
  }

  /* ---------- copy buttons ---------- */
  $$("button.copy").forEach(function (b) {
    b.addEventListener("click", function () {
      var text = b.getAttribute("data-copy");
      var done = function () {
        b.textContent = "Copied"; b.setAttribute("data-done", "");
        setTimeout(function () { b.textContent = "Copy"; b.removeAttribute("data-done"); }, 1600);
      };
      if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done, fallback);
      else fallback();
      function fallback() {
        var ta = document.createElement("textarea");
        ta.value = text; ta.setAttribute("readonly", ""); ta.style.position = "fixed"; ta.style.opacity = "0";
        document.body.appendChild(ta); ta.select();
        try { document.execCommand("copy"); done(); } catch (e) { b.textContent = "Press Ctrl+C"; }
        document.body.removeChild(ta);
      }
    });
  });
})();
