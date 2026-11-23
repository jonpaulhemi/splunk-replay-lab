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
    if (s.state === "preparing") return "preparing";
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
    if (s.state === "preparing") {
      var p = s.prepare || {}, running = (p.steps || []).filter(function (k) {
        return ((p.state || {})[k] || {}).status === "running"; });
      return "Prepare: " + (running.length ? running[0] : "starting") + (p.feeds ? " · " + p.feeds + " feeds exported" : "");
    }
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


  // --- Prepare dataset: setup, export, assets, run by the input on the member that plays it ---

  var STEPS = [["setup", "Setup"], ["export", "Export"], ["assets", "Asset lists"]];

  function prepareBlocker(dataset, cluster) {
    if (String(dataset.settings.enabled) === "1") return "Switch the dataset off first: a re-export can't replace files under a running replay.";
    if (cluster && !dataset.settings.run_on) return "Choose the member that plays it first: the export lands on that member's disk.";
    return "";
  }

  // What the page knows about the latest request: waiting for the member, running, or finished.
  function prepareView(dataset) {
    var s = dataset.status || {}, p = s.prepare || {}, asked = dataset.settings.prepare_request || "";
    if (asked && p.request !== asked) return {phase: "waiting", request: asked};
    if (!p.request) return {phase: "none"};
    if (p.refused) return {phase: "refused", error: p.refused};
    var summary = p.summary;
    return {phase: summary ? (summary.ok ? "done" : "failed") : "running", progress: p, summary: summary};
  }

  function stepLine(name, label, view) {
    var p = view.progress || {}, wanted = (p.steps || []).indexOf(name) >= 0;
    if (!wanted) return null;
    var st = (p.state || {})[name], text;
    if (!st) text = view.phase === "running" ? "waiting" : "not run";
    else if (st.status === "running") text = "running" + (name === "export" && p.feeds ? " (" + p.feeds + " feeds done)" : "");
    else if (st.status === "failed") text = "failed: " + st.error;
    else {
      var bits = Object.keys(st).filter(function (k) { return k !== "status"; }).map(function (k) { return k + " " + st[k]; });
      text = "done" + (bits.length ? " (" + bits.join(", ") + ")" : "");
    }
    return el("li", {"class": "rl-step " + (st ? st.status : "pending"), "data-step": name, text: label + ": " + text});
  }

  function preparePanel(dataset, cluster, done) {
    var box = el("div", {"class": "rl-prepare", "data-dataset": dataset.name});
    box.appendChild(el("h4", {text: "Prepare dataset"}));
    box.appendChild(el("p", {"class": "rl-note", text: "Setup points this search head's CIM macros, roles and data model "
      + "accelerations at the live index (with undo). Export copies the source index to the playing member's disk. "
      + "Asset lists derive ES assets and identities from the dataset. Loading the source index stays on the command line."}));
    var view = prepareView(dataset), blocker = prepareBlocker(dataset, cluster);
    var buttons = el("div", {"class": "rl-buttons"});
    var note = el("div", {"class": "rl-note rl-prepare-note"});
    var confirmBox = el("div", {"class": "rl-confirm", style: "display:none"});
    var busy = view.phase === "waiting" || view.phase === "running";

    function send(steps) {
      note.textContent = "Requesting...";
      var value = Math.floor(Date.now() / 1000) + ":" + steps.join(",");
      request("POST", "datasets/" + encodeURIComponent(dataset.name), {prepare_request: value}).then(function (r) {
        if (r.status === 200) { note.textContent = "Requested."; done(); return; }
        note.textContent = r.body.error || ("Not requested (HTTP " + r.status + ")");
      });
    }

    function ask(steps) {
      var e = (dataset.status || {}).export || {};
      if (steps.indexOf("export") < 0 || !e.ready) { send(steps); return; }
      // a re-export replaces the files on the member: say so and wait for a second click
      confirmBox.innerHTML = "";
      confirmBox.appendChild(el("span", {text: "This replaces the export on " + (dataset.settings.run_on || "this server")
        + ". The replay reads the new files when switched back on. "}));
      var yes = el("button", {type: "button", "class": "btn btn-primary rl-confirm-yes", text: "Replace the export"});
      var no = el("button", {type: "button", "class": "btn rl-confirm-no", text: "Cancel"});
      yes.addEventListener("click", function () { confirmBox.style.display = "none"; send(steps); });
      no.addEventListener("click", function () { confirmBox.style.display = "none"; note.textContent = ""; });
      confirmBox.appendChild(yes);
      confirmBox.appendChild(no);
      confirmBox.style.display = "";
    }

    var all = el("button", {type: "button", "class": "btn btn-primary", "data-steps": "setup,export,assets",
                             text: "Prepare (all steps)"});
    all.addEventListener("click", function () { ask(["setup", "export", "assets"]); });
    buttons.appendChild(all);
    STEPS.forEach(function (s) {
      var b = el("button", {type: "button", "class": "btn", "data-steps": s[0], text: s[1] + " only"});
      b.addEventListener("click", function () { ask([s[0]]); });
      buttons.appendChild(b);
    });
    Array.prototype.forEach.call(buttons.querySelectorAll("button"), function (b) {
      if (blocker || busy) b.disabled = true;
    });
    box.appendChild(buttons);
    if (blocker) note.textContent = blocker;
    box.appendChild(confirmBox);
    box.appendChild(note);

    var result = el("div", {"class": "rl-prepare-result", "data-phase": view.phase});
    if (view.phase === "waiting") {
      result.appendChild(el("p", {text: "Requested; " + (dataset.settings.run_on || "this server")
        + " starts it on its next tick (within " + (dataset.settings.tick_seconds || 30) + " s)."}));
    } else if (view.phase === "refused") {
      result.appendChild(el("p", {"class": "rl-error", text: "Refused: " + view.error}));
    } else if (view.phase !== "none") {
      var head = {running: "Running", done: "Finished", failed: "Failed"}[view.phase];
      result.appendChild(el("p", {"class": "rl-prepare-head " + view.phase, text: head + " (" + view.progress.steps.join(", ") + ")"}));
      var list = el("ul");
      STEPS.forEach(function (s) { var li = stepLine(s[0], s[1], view); if (li) list.appendChild(li); });
      result.appendChild(list);
      var warnings = (view.summary && view.summary.warnings) || [];
      if (!view.summary && view.progress.missing_addons && view.progress.missing_addons.length)
        warnings = ["missing add-ons (some detections won't fire): " + view.progress.missing_addons.join(", ")];
      warnings.forEach(function (w) { result.appendChild(el("div", {"class": "rl-warning", text: "Warning: " + w})); });
      if (view.summary && view.summary.error) result.appendChild(el("div", {"class": "rl-error", text: view.summary.error}));
    }
    box.appendChild(result);
    return box;
  }

  function preparing(data) {
    return data.datasets.some(function (d) {
      var phase = prepareView(d).phase;
      return phase === "waiting" || phase === "running";
    });
  }

  function render(root, data) {
    var open = {};  // keep open what was open
    Array.prototype.forEach.call(root.querySelectorAll("tr.rl-edit"), function (r) {
      if (r.style.display !== "none") open[r.getAttribute("data-edit")] = true;
    });
    lastData = data;
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
      var editRow = el("tr", {"class": "rl-edit", "data-edit": d.name, style: open[d.name] ? "" : "display:none"}, [
        el("td", {colspan: "6"}, [editor(d, data.members, data.cluster, load), preparePanel(d, data.cluster, load)])]);
      table.appendChild(editRow);
      edit.addEventListener("click", function () {
        editRow.style.display = editRow.style.display === "none" ? "" : "none";
      });
    });
    root.appendChild(table);
  }

  var waits = 0, lastData = null;

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

  function unsaved() {
    return Array.prototype.some.call(document.querySelectorAll("#replay-settings form.rl-form [data-shown]"), function (i) {
      var value = i.type === "checkbox" ? (i.checked ? "1" : "0") : i.value;
      return value !== i.getAttribute("data-shown");
    });
  }

  // Fresh status every 30 s (every 5 s while a Prepare is waiting or running), unless someone is
  // typing in a settings form or has changes there they haven't saved.
  var since = 0;
  setInterval(function () {
    since += 5;
    var typing = document.activeElement && document.activeElement.closest &&
                 document.activeElement.closest("#replay-settings form.rl-form");
    if (typing || unsaved()) return;
    if (since >= 30 || (lastData && preparing(lastData))) { since = 0; load(); }
  }, 5000);

  window.replayLabSettings = {load: load, stateOf: stateOf, prepareView: prepareView};
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", load);
  else load();
})();
