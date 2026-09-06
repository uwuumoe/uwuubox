// ShareX `.sxcu` generator: builds file/paste custom-uploader configs locally
// from the user's API token. The token never leaves the browser except
// embedded inside the downloaded file (as the Authorization header), so no
// server round-trip is involved. Syntax follows the current ShareX schema:
// `{json:...}` response parsing with a `Version` above 13.7.1 (older
// `$...$` syntax without a Version is rejected on import).
(function () {
  var root = document.getElementById("sharex");
  if (!root) return;
  var tokenEl = document.getElementById("sharex-token");
  var visEl = document.getElementById("sharex-visibility");
  var expEl = document.getElementById("sharex-expiry");
  var statusEl = document.getElementById("sharex-status");
  var filesBtn = document.getElementById("sharex-files-dl");
  var pastesBtn = document.getElementById("sharex-pastes-dl");
  if (!tokenEl || !visEl || !expEl || !filesBtn || !pastesBtn) return;

  var base = (root.getAttribute("data-base-url") || window.location.origin).replace(/\/+$/, "");
  var instance = root.getAttribute("data-instance") || base;
  var host = base.replace(/^https?:\/\//, "").split("/")[0] || "uwuubox";

  function status(msg) {
    if (statusEl) statusEl.textContent = msg;
  }

  // Null when the form is incomplete; otherwise the config plus filename.
  function build(kind) {
    var token = tokenEl.value.trim();
    var visibility = visEl.value === "public" ? "public" : "unlisted";
    var never = expEl.value === "never";
    if (!token) {
      status("paste an API token first (create one above — it is shown once).");
      tokenEl.focus();
      return null;
    }
    if (!/^uwu_.{8,}$/.test(token)) {
      status("that token looks truncated — paste the full uwu_… value.");
      tokenEl.focus();
      return null;
    }
    var headers = { Authorization: "Bearer " + token };
    if (kind === "files") {
      var args = { visibility: visibility };
      if (never) args.expires_in_secs = "never";
      return {
        filename: host + "-files.sxcu",
        cfg: {
          Version: "16.1.0",
          Name: instance + " files",
          DestinationType: "ImageUploader, FileUploader",
          RequestMethod: "POST",
          RequestURL: base + "/api/upload",
          Headers: headers,
          Body: "MultipartFormData",
          Arguments: args,
          FileFormName: "file",
          URL: "{json:raw_url}",
          ThumbnailURL: "{json:preview_url}",
          ErrorMessage: "{response}"
        }
      };
    }
    // ShareX substitutes `{input}` with the JSON-escaped clipboard text, so
    // the template stays valid JSON after substitution.
    var data = { body: "{input}", visibility: visibility };
    if (never) data.expires_in_secs = "never";
    return {
      filename: host + "-pastes.sxcu",
      cfg: {
        Version: "16.1.0",
        Name: instance + " pastes",
        DestinationType: "TextUploader",
        RequestMethod: "POST",
        RequestURL: base + "/api/pastes",
        Headers: headers,
        Body: "JSON",
        Data: JSON.stringify(data),
        URL: "{json:preview_url}",
        ThumbnailURL: "{json:raw_url}",
        ErrorMessage: "{response}"
      }
    };
  }

  function download(kind) {
    var out = build(kind);
    if (!out) return;
    var blob = new Blob([JSON.stringify(out.cfg, null, 2)], { type: "application/json" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = out.filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    status("downloaded " + out.filename + " — double-click to import into ShareX.");
  }

  filesBtn.addEventListener("click", function () { download("files"); });
  pastesBtn.addEventListener("click", function () { download("pastes"); });
})();
