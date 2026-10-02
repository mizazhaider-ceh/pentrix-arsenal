/* PENTRIX ARSENAL attack-surface graph renderer.
 * Vanilla JS, zero dependencies, no network calls. Reads the graph from
 * window.__ARSENAL_GRAPH__ = {nodes:[{id,label,kind,meta}], links:[{a,b}]}
 * and renders it as SVG with pan/zoom (wheel + drag) and a click-to-inspect
 * detail panel. Works from file:// offline.
 */
(function () {
  "use strict";

  var data = window.__ARSENAL_GRAPH__ || { nodes: [], links: [] };
  var svg = document.getElementById("attack-graph");
  var panel = document.getElementById("graph-detail");
  if (!svg) return;

  var NS = svg.namespaceURI; // avoid hardcoding the SVG namespace string
  var W = 1400, H = 700;

  var COLORS = {
    domain: "#4da3ff",
    subdomain: "#7cc4ff",
    ip: "#ffb020",
    port: "#ff5d5d",
    tech: "#9d7bff",
    finding: "#ff7a59"
  };
  var KIND_ORDER = ["domain", "subdomain", "ip", "port", "tech", "finding"];

  var nodes = Array.isArray(data.nodes) ? data.nodes : [];
  var links = Array.isArray(data.links) ? data.links : [];

  // ---- layout: one column per kind, deterministic -------------------------
  var byKind = {};
  KIND_ORDER.forEach(function (k) { byKind[k] = []; });
  nodes.forEach(function (n) {
    var k = KIND_ORDER.indexOf(n.kind) >= 0 ? n.kind : "domain";
    n.kind = k;
    byKind[k].push(n);
  });

  var pos = {};
  KIND_ORDER.forEach(function (kind, ci) {
    var col = byKind[kind];
    var x = 90 + ci * 225;
    col.forEach(function (n, i) {
      var y = H * (i + 1) / (col.length + 1);
      pos[n.id] = { x: x, y: y };
    });
  });

  // ---- viewport: pan + zoom ----------------------------------------------
  var viewport = document.createElementNS(NS, "g");
  svg.appendChild(viewport);
  var view = { x: 0, y: 0, k: 1 };

  function apply() {
    viewport.setAttribute(
      "transform",
      "translate(" + view.x + "," + view.y + ") scale(" + view.k + ")"
    );
  }

  svg.addEventListener("wheel", function (e) {
    e.preventDefault();
    var factor = e.deltaY < 0 ? 1.12 : 1 / 1.12;
    var k2 = Math.min(4, Math.max(0.3, view.k * factor));
    // zoom toward cursor
    var rect = svg.getBoundingClientRect();
    var mx = e.clientX - rect.left, my = e.clientY - rect.top;
    view.x = mx - (mx - view.x) * (k2 / view.k);
    view.y = my - (my - view.y) * (k2 / view.k);
    view.k = k2;
    apply();
  }, { passive: false });

  var dragging = false, lx = 0, ly = 0;
  svg.addEventListener("pointerdown", function (e) {
    dragging = true; lx = e.clientX; ly = e.clientY;
    svg.setPointerCapture(e.pointerId);
  });
  svg.addEventListener("pointermove", function (e) {
    if (!dragging) return;
    view.x += e.clientX - lx;
    view.y += e.clientY - ly;
    lx = e.clientX; ly = e.clientY;
    apply();
  });
  svg.addEventListener("pointerup", function () { dragging = false; });
  svg.addEventListener("dblclick", function () {
    view = { x: 0, y: 0, k: 1 };
    apply();
  });

  // ---- edges --------------------------------------------------------------
  links.forEach(function (l) {
    var a = pos[l.a], b = pos[l.b];
    if (!a || !b) return;
    var line = document.createElementNS(NS, "line");
    line.setAttribute("x1", a.x); line.setAttribute("y1", a.y);
    line.setAttribute("x2", b.x); line.setAttribute("y2", b.y);
    line.setAttribute("stroke", "#3a4358");
    line.setAttribute("stroke-width", "1.5");
    viewport.appendChild(line);
  });

  // ---- nodes --------------------------------------------------------------
  function esc(s) {
    return String(s == null ? "" : s).replace(/&/g, "&amp;")
      .replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function showDetail(n) {
    if (!panel) return;
    var html = "<h3>" + esc(n.label || n.id) + "</h3>";
    html += "<p><span class='g-kind'>" + esc(n.kind) + "</span></p>";
    if (n.meta && typeof n.meta === "object") {
      html += "<dl>";
      Object.keys(n.meta).forEach(function (k) {
        html += "<dt>" + esc(k) + "</dt><dd>" + esc(n.meta[k]) + "</dd>";
      });
      html += "</dl>";
    } else if (n.meta) {
      html += "<p>" + esc(n.meta) + "</p>";
    }
    panel.innerHTML = html;
  }

  nodes.forEach(function (n) {
    var p = pos[n.id];
    if (!p) return;
    var g = document.createElementNS(NS, "g");
    g.setAttribute("class", "g-node");
    g.setAttribute("transform", "translate(" + p.x + "," + p.y + ")");

    var circle = document.createElementNS(NS, "circle");
    circle.setAttribute("r", "16");
    circle.setAttribute("fill", COLORS[n.kind] || "#8a93a6");
    circle.setAttribute("stroke", "#0d1117");
    circle.setAttribute("stroke-width", "2");
    g.appendChild(circle);

    var text = document.createElementNS(NS, "text");
    text.setAttribute("x", "24");
    text.setAttribute("y", "5");
    text.setAttribute("fill", "#dbe2f0");
    text.setAttribute("font-size", "13");
    text.setAttribute("font-family", "sans-serif");
    text.textContent = String(n.label || n.id).slice(0, 42);
    g.appendChild(text);

    g.style.cursor = "pointer";
    g.addEventListener("click", function (e) {
      e.stopPropagation();
      showDetail(n);
    });
    viewport.appendChild(g);
  });

  // ---- legend -------------------------------------------------------------
  var legend = document.getElementById("graph-legend");
  if (legend) {
    var html = "";
    KIND_ORDER.forEach(function (k) {
      var count = byKind[k].length;
      if (!count) return;
      html += "<span class='g-legend-item'><span class='g-dot' style='background:" +
        COLORS[k] + "'></span>" + k + " (" + count + ")</span>";
    });
    legend.innerHTML = html || "<span class='g-legend-item'>no nodes</span>";
  }

  if (panel && nodes.length) {
    panel.innerHTML = "<p class='g-hint'>Click any node to inspect it. " +
      "Drag to pan, scroll to zoom, double-click to reset.</p>";
  }

  apply();
})();
