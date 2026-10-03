// MCPsight documentation: sidebar, search, on-this-page, copy buttons, theme,
// and prev/next links. To add a page, create the HTML file and list it in NAV.
(function () {
  "use strict";

  var NAV = [
    { group: "Get started", pages: [
      ["index.html", "Overview"],
      ["install.html", "Install"],
      ["first-scan.html", "Your first scan"],
      ["reading-a-report.html", "Reading a report"]
    ]},
    { group: "Walkthrough", pages: [
      ["practice-servers.html", "Try it with the practice servers"],
      ["poisoned-server.html", "Spot a poisoned server"],
      ["rug-pull.html", "Catch a rug pull"],
      ["tokens.html", "Servers that need a token"],
      ["your-setup.html", "Scan your own setup"],
      ["sandbox.html", "The Linux sandbox"]
    ]},
    { group: "Use it in CI", pages: [
      ["ci.html", "Gate pull requests"],
      ["output-formats.html", "Output formats"],
      ["exit-codes.html", "Exit codes"]
    ]},
    { group: "Reference", pages: [
      ["commands.html", "Commands and flags"],
      ["rules.html", "Every rule"],
      ["scoring.html", "How scoring works"],
      ["custom-rules.html", "Custom injection rules"],
      ["troubleshooting.html", "Troubleshooting"]
    ]},
    { group: "Security", pages: [
      ["protection.html", "What MCPsight protects you from"],
      ["verify-download.html", "Verify a download"],
      ["report-vulnerability.html", "Report a vulnerability"]
    ]},
    { group: "Self-host", pages: [
      ["self-host-index.html", "Run the registry index"]
    ]}
  ];

  var REPO = "https://github.com/greyquill/mcpsight";
  var flat = [];
  NAV.forEach(function (g) { g.pages.forEach(function (p) { flat.push({ href: p[0], title: p[1], group: g.group }); }); });
  var here = location.pathname.split("/").pop() || "index.html";
  var hereIdx = flat.findIndex(function (p) { return p.href === here; });

  function el(tag, attrs, html) {
    var e = document.createElement(tag);
    for (var k in attrs || {}) e.setAttribute(k, attrs[k]);
    if (html != null) e.innerHTML = html;
    return e;
  }
  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function slug(s) {
    return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  }

  /* ---------- theme ---------- */
  var ICONS = {
    light: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
    system: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></svg>',
    dark: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>'
  };
  function getTheme() { try { return localStorage.getItem("mcpsight.theme") || "system"; } catch (e) { return "system"; } }
  function setTheme(t) {
    try { localStorage.setItem("mcpsight.theme", t); } catch (e) {}
    if (t === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", t);
    document.querySelectorAll(".theme button").forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.t === t)); });
  }

  /* ---------- sidebar ---------- */
  var side = document.getElementById("sidebar");
  var html = '<a class="brand" href="../"><span class="brand-mark">M</span><span class="brand-text"><b>MCPsight</b><small>Documentation</small></span></a>' +
    '<button class="search-btn" type="button" data-search><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>Search<kbd>⌘K</kbd></button>' +
    '<nav class="nav" aria-label="Documentation">';
  NAV.forEach(function (g) {
    html += "<h4>" + esc(g.group) + "</h4>";
    g.pages.forEach(function (p) {
      html += '<a href="' + p[0] + '"' + (p[0] === here ? ' aria-current="page"' : "") + ">" + esc(p[1]) + "</a>";
    });
  });
  html += '</nav><div class="side-foot"><a href="' + REPO + '">GitHub</a><div class="theme" role="group" aria-label="Theme">' +
    ["light", "system", "dark"].map(function (t) {
      return '<button type="button" data-t="' + t + '" aria-label="' + t + ' theme" aria-pressed="false">' + ICONS[t] + "</button>";
    }).join("") + "</div></div>";
  side.innerHTML = html;
  side.querySelectorAll(".theme button").forEach(function (b) { b.onclick = function () { setTheme(b.dataset.t); }; });
  setTheme(getTheme());

  var top = el("div", { class: "topbar" },
    '<button type="button" data-menu aria-label="Open navigation">Menu</button><b>MCPsight docs</b>' +
    '<button type="button" data-search style="margin-left:auto">Search</button>');
  document.body.insertBefore(top, document.body.firstChild);
  top.querySelector("[data-menu]").onclick = function () { side.classList.toggle("open"); };
  document.addEventListener("click", function (e) {
    if (side.classList.contains("open") && !side.contains(e.target) && !e.target.closest("[data-menu]")) side.classList.remove("open");
  });

  /* ---------- headings, on this page ---------- */
  var doc = document.querySelector(".doc");
  var heads = Array.prototype.slice.call(doc.querySelectorAll("h2, h3"));
  heads.forEach(function (h) {
    if (!h.id) h.id = slug(h.textContent);
    h.appendChild(el("a", { class: "anchor", href: "#" + h.id, "aria-label": "Link to this section" }, "#"));
  });
  var toc = document.getElementById("toc");
  if (toc && heads.length) {
    toc.innerHTML = '<h5><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 6h16M4 12h10M4 18h14"/></svg>On this page</h5>' +
      heads.map(function (h) {
        var t = h.cloneNode(true); t.querySelectorAll(".anchor").forEach(function (a) { a.remove(); });
        return '<a href="#' + h.id + '"' + (h.tagName === "H3" ? ' class="sub"' : "") + ">" + esc(t.textContent) + "</a>";
      }).join("");
    var links = {};
    toc.querySelectorAll("a").forEach(function (a) { links[a.getAttribute("href").slice(1)] = a; });
    if ("IntersectionObserver" in window) {
      var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (en) {
          if (en.isIntersecting) {
            toc.querySelectorAll("a.active").forEach(function (a) { a.classList.remove("active"); });
            if (links[en.target.id]) links[en.target.id].classList.add("active");
          }
        });
      }, { rootMargin: "0px 0px -70% 0px" });
      heads.forEach(function (h) { io.observe(h); });
    }
  }

  /* ---------- code blocks ---------- */
  // A "$" goes on each new command, not on continuation lines, indented loop
  // bodies, or the lines that close a loop or heredoc.
  function decorateCommand(text) {
    var cont = false, depth = 0;
    return text.split("\n").map(function (line) {
      var out;
      if (/^\s*#/.test(line)) out = '<span class="c">' + esc(line) + "</span>";
      else {
        var m = line.match(/^(.*?)(\s+#\s.*)$/);
        var inner = cont || depth > 0 || !line || /^\s/.test(line);
        out = (inner ? "" : '<span class="p">$ </span>') +
          (m ? esc(m[1]) + '<span class="c">' + esc(m[2]) + "</span>" : esc(line));
      }
      cont = /\\$/.test(line);
      if (/;\s*do$|^\s*(for|while)\b.*\bdo$/.test(line)) depth++;
      if (/^\s*done\b/.test(line)) depth = Math.max(0, depth - 1);
      return out;
    }).join("\n");
  }
  function decorateOutput(text) {
    return text.split("\n").map(function (line) {
      var e = esc(line);
      e = e.replace(/^(\s*)(CRITICAL)\b/, '$1<span class="t-crit">$2</span>')
        .replace(/^(\s*)(HIGH)\b/, '$1<span class="t-high">$2</span>')
        .replace(/^(\s*)(MEDIUM)\b/, '$1<span class="t-med">$2</span>')
        .replace(/^(\s*)(LOW)\b/, '$1<span class="t-low">$2</span>')
        .replace(/^(\s*)(INFO)\b/, '$1<span class="t-info">$2</span>')
        .replace(/(\[[a-z_]+\.[a-z_]+\])\s*$/, '<span class="t-dim">$1</span>')
        .replace(/^(\s*Grade\s+)([AB])\b/, '$1<span class="t-ok">$2</span>')
        .replace(/^(\s*Grade\s+)([CD])\b/, '$1<span class="t-med">$2</span>')
        .replace(/^(\s*Grade\s+)(F)\b/, '$1<span class="t-bad">$2</span>')
        .replace(/^(\s*)(fix:)/, '$1<span class="t-dim">$2</span>')
        .replace(/(DRIFTED: .*)$/, '<span class="t-bad">$1</span>')
        .replace(/^(\s*)(No findings\.|All servers match their baselines\.)/, '$1<span class="t-ok">$2</span>')
        .replace(/^(✗ .*)$/, '<span class="t-bad">$1</span>');
      return e;
    }).join("\n");
  }
  doc.querySelectorAll("pre[data-kind]").forEach(function (pre) {
    var kind = pre.dataset.kind;
    var raw = pre.textContent.replace(/^\n/, "").replace(/\s+$/, "");
    var wrap = el("div", { class: "block " + kind });
    var head = el("div", { class: "block-head" });
    if (kind === "out") {
      head.innerHTML = '<span class="dots"><i></i><i></i><i></i></span><span>' + esc(pre.dataset.label || "Output") + "</span>";
      pre.innerHTML = decorateOutput(raw);
    } else {
      head.innerHTML = "<span>" + esc(pre.dataset.label || (kind === "cmd" ? "Terminal" : "File")) + "</span>";
      var btn = el("button", { class: "copy", type: "button" }, "Copy");
      btn.onclick = function () {
        var done = function () { btn.textContent = "Copied"; setTimeout(function () { btn.textContent = "Copy"; }, 1400); };
        if (navigator.clipboard) navigator.clipboard.writeText(raw).then(done, function () {});
      };
      head.appendChild(btn);
      pre.innerHTML = kind === "cmd" && !pre.hasAttribute("data-plain") ? decorateCommand(raw) : esc(raw);
    }
    pre.parentNode.insertBefore(wrap, pre);
    wrap.appendChild(head);
    wrap.appendChild(pre);
  });

  /* ---------- prev / next ---------- */
  if (hereIdx >= 0) {
    var prev = flat[hereIdx - 1], next = flat[hereIdx + 1];
    var pager = el("nav", { class: "pager", "aria-label": "Previous and next page" },
      (prev ? '<a href="' + prev.href + '"><small>Previous</small>' + esc(prev.title) + "</a>" : "<span></span>") +
      (next ? '<a class="next" href="' + next.href + '"><small>Next</small>' + esc(next.title) + "</a>" : ""));
    doc.appendChild(pager);
  }

  /* ---------- search ---------- */
  var dlg = el("dialog", { class: "search-dlg", "aria-label": "Search the docs" },
    '<div class="search-box"><input type="search" placeholder="Search the docs" aria-label="Search the docs"><div class="results"></div></div>');
  document.body.appendChild(dlg);
  var input = dlg.querySelector("input"), results = dlg.querySelector(".results");
  var index = null, sel = 0;

  // textContent runs table cells and list items together; keep a space between them.
  function spaced(n) {
    var t = document.createElement("textarea");
    t.innerHTML = n.innerHTML.replace(/<[^>]+>/g, " ");
    return t.value.replace(/\s+/g, " ");
  }
  function buildIndex() {
    if (index) return Promise.resolve(index);
    return Promise.all(flat.map(function (p) {
      return fetch(p.href).then(function (r) { return r.text(); }).then(function (txt) {
        var d = new DOMParser().parseFromString(txt, "text/html");
        var art = d.querySelector(".doc"); if (!art) return [];
        var entries = [], cur = { page: p, id: "", head: p.title, text: "" };
        Array.prototype.forEach.call(art.children, function (n) {
          if (/^H[23]$/.test(n.tagName)) {
            entries.push(cur);
            cur = { page: p, id: n.id || slug(n.textContent), head: n.textContent, text: "" };
          } else if (n.tagName !== "H1") {
            cur.text += " " + spaced(n);
          }
        });
        entries.push(cur);
        return entries;
      }).catch(function () { return []; });
    })).then(function (lists) { index = [].concat.apply([], lists); return index; });
  }
  function render(q) {
    var words = q.toLowerCase().split(/\s+/).filter(Boolean);
    if (!words.length) { results.innerHTML = ""; return; }
    var hits = index.filter(function (e) {
      var hay = (e.page.title + " " + e.head + " " + e.text).toLowerCase();
      return words.every(function (w) { return hay.indexOf(w) >= 0; });
    }).slice(0, 12);
    sel = 0;
    if (!hits.length) { results.innerHTML = '<div class="none">Nothing matches "' + esc(q) + '". Try a rule ID or a flag.</div>'; return; }
    results.innerHTML = hits.map(function (h, i) {
      var t = h.text.replace(/\s+/g, " ").trim(), at = t.toLowerCase().indexOf(words[0]);
      var from = Math.max(0, at - 40);
      if (from > 0) { var sp = t.indexOf(" ", from); if (sp >= 0 && sp < at) from = sp + 1; }
      var snip = (from > 0 ? "… " : "") + (at >= 0 ? t.slice(from, at + 90) : t.slice(0, 110));
      var mark = esc(snip).replace(new RegExp("(" + words.map(function (w) { return w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }).join("|") + ")", "gi"), "<mark>$1</mark>");
      return '<a href="' + h.page.href + (h.id ? "#" + h.id : "") + '"' + (i === 0 ? ' class="sel"' : "") + ">" +
        esc(h.page.title) + (h.head !== h.page.title ? " › " + esc(h.head) : "") + "<small>" + mark + "</small></a>";
    }).join("");
  }
  function openSearch() {
    if (!dlg.open) dlg.showModal();
    input.value = ""; results.innerHTML = '<div class="none">Type to search every page.</div>';
    input.focus();
    buildIndex();
  }
  document.querySelectorAll("[data-search]").forEach(function (b) { b.onclick = openSearch; });
  input.addEventListener("input", function () { buildIndex().then(function () { render(input.value); }); });
  input.addEventListener("keydown", function (e) {
    var items = results.querySelectorAll("a");
    if (!items.length) return;
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      items[sel].classList.remove("sel");
      sel = (sel + (e.key === "ArrowDown" ? 1 : items.length - 1)) % items.length;
      items[sel].classList.add("sel"); items[sel].scrollIntoView({ block: "nearest" });
    } else if (e.key === "Enter") { e.preventDefault(); location.href = items[sel].getAttribute("href"); }
  });
  dlg.addEventListener("click", function (e) { if (e.target === dlg) dlg.close(); });
  document.addEventListener("keydown", function (e) {
    if ((e.key === "k" && (e.metaKey || e.ctrlKey)) || (e.key === "/" && !/INPUT|TEXTAREA/.test(document.activeElement.tagName))) {
      e.preventDefault(); openSearch();
    }
  });
})();
