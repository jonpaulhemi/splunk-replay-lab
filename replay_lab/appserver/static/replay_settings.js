/* The Datasets page: lists every dataset with its state, progress and export, and edits its settings
 * through /services/replay_lab (see bin/replaylib/settings.py). No libraries; works in Splunk Web and,
 * for tests, in any page that has <div id="replay-settings"> and sets window.REPLAY_LAB_API. */
(function () {
  "use strict";

  function apiBase() {
    if (window.REPLAY_LAB_API) return window.REPLAY_LAB_API;
    var locale = (window.location.pathname.split("/")[1] || "en-US");
    return "/" + locale + "/splunkd/__raw/services/replay_lab";
  }

  function formKey() {
    var match = document.cookie.match(/(?:^|; )splunkweb_csrf_token_\d+=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : "";
  }

  function request(method, path, form) {
    var options = {method: method, credentials: "same-origin",
                   headers: {"X-Requested-With": "XMLHttpRequest", "X-Splunk-Form-Key": formKey()}};
    if (form) {
      options.headers["Content-Type"] = "application/x-www-form-urlencoded";
      options.body = new URLSearchParams(form).toString();
    }
    return fetch(apiBase() + "/" + path + "?output_mode=json", options).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (body) {
        return {status: response.status, body: body};
      });
    });
  }

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "text") node.textContent = attrs[k];
      else node.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) { if (c) node.appendChild(c); });
    return node;
  }

  function when(epoch) {
    if (!epoch) return "";
    return new Date(Number(epoch) * 1000).toLocaleString();
  }

  // off, no export, error, standby, playing, idle until next start, no recent tick
  function stateOf(dataset) {
    var s = dataset.status || {}, on = String(dataset.settings.enabled) === "1";
    if (!on) return "off";
    if (s.last_error) return "error";
    if (!s.state) return "waiting for first tick";
    if (s.updated && Date.now() / 1000 - Number(s.updated) > 300) return "no recent tick";
    if (s.state === "no_export") return "no export";
    if (s.state === "on") return (s.playing === true || s.playing === "true" || s.playing === 1) ? "playing" : "idle until next start";
    return s.state;
  }

  function progress(dataset) {
    var s = dataset.status || {};
    if (s.state !== "on") return "";
    var parts = ["period " + s.loop + (s.segment !== undefined ? " (segment " + s.segment + ")" : ""),
                 "position " + (Number(s.position || 0) / 3600).toFixed(2) + " h of " +
                 (Number(s.loop_seconds || 0) / 3600).toFixed(1) + " h",
                 "events last tick " + (s.events || 0)];
    if (s.next_start_text) parts.push("next start " + s.next_start_text);
    return parts.join(" · ");
  }

  function exportState(dataset) {
    var e = (dataset.status || {}).export;
    if (!e) return "unknown";
    return e.ready ? "ready" + (e.segments > 1 ? " (" + e.segments + " segments)" : "") +
                     (dataset.status.member ? " on " + dataset.status.member : "")
                   : "not exported";
  }

  var FIELDS = [
    ["enabled", "On", "checkbox"],
    ["run_on", "Plays on", "member"],
    ["schedule", "Schedule", ["loop", "daily"]],
    ["daily_start", "Daily start (HH:MM)", "text"],
    ["schedule_timezone", "Time zone", "text"],
    ["anchor", "Anchor (epoch, empty = when switched on)", "text"],
    ["index", "Live index", "text"],
    ["window_start", "Window start (epoch)", "text"],
    ["window_end", "Window end (epoch)", "text"],
    ["segments", "Segments (start-end pairs)", "textarea"],
    ["rules_mode", "Rules", ["escu", "none"]]
  ];

  function editor(dataset, members, cluster, done) {
    var form = el("form", {"class": "rl-form", "data-dataset": dataset.name});
    var settings = dataset.settings;
    FIELDS.forEach(function (f) {
      var name = f[0], kind = f[2], value = settings[name] === undefined ? "" : String(settings[name]), input;
      if (kind === "checkbox") {
        input = el("input", {type: "checkbox", name: name});
        input.checked = value === "1";
      } else if (kind === "member") {
        input = el("select", {name: name});
        if (cluster) input.appendChild(el("option", {value: "", text: "(choose a member)"}));
        members.forEach(function (m) { input.appendChild(el("option", {value: m, text: m})); });
        input.value = value || (cluster ? "" : (members[0] || ""));
      } else if (Array.isArray(kind)) {
        input = el("select", {name: name});
        kind.forEach(function (o) { input.appendChild(el("option", {value: o, text: o})); });
        input.value = value || kind[0];
      } else if (kind === "textarea") {
        input = el("textarea", {name: name, rows: "3"});
        input.value = value.split(/\s+/).filter(Boolean).join("\n");
      } else {
        input = el("input", {type: "text", name: name});
        input.value = value;
      }
      input.setAttribute("data-shown", kind === "checkbox" ? (input.checked ? "1" : "0") : input.value);
      form.appendChild(el("label", {"for": name, text: f[1]}));
      form.appendChild(input);
    });
    var save = el("button", {type: "submit", "class": "btn btn-primary", text: "Save"});
    var message = el("span", {"class": "rl-note"});
    form.appendChild(el("span"));
    form.appendChild(el("div", {}, [save, message]));
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      var values = {};  // only what changed, so settings the page doesn't show stay as they are
      FIELDS.forEach(function (f) {
        var input = form.elements[f[0]];
        var value = f[2] === "checkbox" ? (input.checked ? "1" : "0")
                  : f[2] === "textarea" ? input.value.split(/\s+/).filter(Boolean).join(" ")
                  : input.value;
        var before = input.getAttribute("data-shown");  // as first shown, defaults included
        if (f[2] === "textarea") before = before.split(/\s+/).filter(Boolean).join(" ");
        if (value !== before) values[f[0]] = value;
      });
      Array.prototype.forEach.call(form.querySelectorAll(".rl-field-error"), function (n) { n.remove(); });
      message.textContent = "Saving...";
      request("POST", "datasets/" + encodeURIComponent(dataset.name), values).then(function (r) {
        if (r.status === 200) {
          message.textContent = "Saved.";
          done();
          return;
        }
        message.textContent = r.body.error || ("Not saved (HTTP " + r.status + ")");
        var fields = r.body.fields || {};
        Object.keys(fields).forEach(function (name) {
          var input = form.elements[name];
          if (input) input.insertAdjacentElement("afterend", el("div", {"class": "rl-field-error", text: fields[name]}));
        });
      });
    });
    return form;
  }

  function render(root, data) {
    root.innerHTML = "";
    if (!data.cluster) root.appendChild(el("p", {"class": "rl-note",
      text: "Standalone search head: every dataset plays here (" + (data.members[0] || "this server") + ")."}));
    var table = el("table", {"class": "rl"});
    table.appendChild(el("tr", {}, ["Dataset", "State", "Plays on", "Progress", "Export", ""].map(function (h) {
      return el("th", {text: h});
    })));
    data.datasets.forEach(function (d) {
      var state = stateOf(d);
      var edit = el("button", {type: "button", "class": "btn", text: "Edit"});
      var row = el("tr", {"data-dataset": d.name}, [
        el("td", {text: (d.settings.label || d.name) + " (" + d.name + ")"}),
        el("td", {}, [el("span", {"class": "rl-state " + state.replace(/ /g, "-").split("-")[0], text: state}),
                      d.status && d.status.last_error ? el("div", {"class": "rl-error", text: d.status.last_error}) : null]),
        el("td", {text: d.settings.run_on || (data.cluster ? "(not chosen)" : (data.members[0] || ""))}),
        el("td", {text: progress(d)}),
        el("td", {text: exportState(d)}),
        el("td", {}, [edit])
      ]);
      table.appendChild(row);
      var editRow = el("tr", {"class": "rl-edit", style: "display:none"}, [
        el("td", {colspan: "6"}, [editor(d, data.members, data.cluster, load)])]);
      table.appendChild(editRow);
      edit.addEventListener("click", function () {
        editRow.style.display = editRow.style.display === "none" ? "" : "none";
      });
    });
    root.appendChild(table);
  }

  var waits = 0;

  function load() {
    var root = document.getElementById("replay-settings");
    if (!root) {  // Simple XML renders the panel after this script loads
      if (waits++ < 100) setTimeout(load, 100);
      return;
    }
    request("GET", "datasets").then(function (r) {
      if (r.status !== 200) {
        root.textContent = r.body.error || ("Couldn't load datasets (HTTP " + r.status + ")");
        return;
      }
      render(root, r.body);
    }).catch(function (e) { root.textContent = "Couldn't load datasets: " + e; });
  }

  // Fresh status every 30 s, unless an edit form is open.
  setInterval(function () {
    var open = Array.prototype.some.call(document.querySelectorAll("#replay-settings tr.rl-edit"),
                                         function (r) { return r.style.display !== "none"; });
    if (!open) load();
  }, 30000);

  window.replayLabSettings = {load: load, stateOf: stateOf};
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", load);
  else load();
})();
