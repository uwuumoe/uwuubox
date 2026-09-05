// Progressive enhancement for the upload form: XHR with a progress bar plus
// byte-count/speed readout that renders the JSON links in place. Without JS
// the form posts natively and the server 303-redirects to the preview page.
(function () {
  var form = document.getElementById("upload");
  var file = document.getElementById("file");
  var bar = document.getElementById("bar");
  var stat = document.getElementById("upstat");
  var result = document.getElementById("result");
  if (!form || !file || !bar || !result || !window.XMLHttpRequest) return;

  function human(n) {
    if (n < 1024) return n + " B";
    var units = ["KB", "MB", "GB", "TB"];
    var v = n, u = -1;
    while (v >= 1024 && u < units.length - 1) { v /= 1024; u++; }
    return (v >= 100 ? Math.round(v) : v.toFixed(1)) + " " + units[u];
  }

  function show(html) {
    result.innerHTML = html;
  }
  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  form.addEventListener("submit", function (ev) {
    if (!file.files || file.files.length === 0) return;
    ev.preventDefault();
    show("");
    bar.hidden = false;
    bar.value = 0;
    if (stat) { stat.hidden = false; stat.textContent = "starting…"; }

    var startedAt = Date.now();
    var lastAt = startedAt;
    var lastLoaded = 0;
    var speed = 0; // bytes/sec, exponentially smoothed

    function render(loaded, total) {
      if (!stat) return;
      var done = human(loaded);
      var text = total ? done + " / " + human(total) : done + " uploaded";
      if (speed > 0) text += " · " + human(Math.round(speed)) + "/s";
      stat.textContent = text;
    }

    var xhr = new XMLHttpRequest();
    xhr.open("POST", form.action);
    xhr.setRequestHeader("Accept", "application/json");
    xhr.upload.addEventListener("progress", function (e) {
      if (e.lengthComputable) bar.value = Math.round((e.loaded / e.total) * 100);
      var now = Date.now();
      var dt = (now - lastAt) / 1000;
      if (dt >= 0.25) {
        var instant = (e.loaded - lastLoaded) / dt;
        speed = speed === 0 ? instant : speed * 0.7 + instant * 0.3;
        lastAt = now;
        lastLoaded = e.loaded;
      }
      render(e.loaded, e.lengthComputable ? e.total : 0);
    });
    xhr.addEventListener("load", function () {
      bar.hidden = true;
      if (stat) {
        var secs = Math.max((Date.now() - startedAt) / 1000, 0.01);
        var avg = lastLoaded / secs;
        stat.textContent += " · done in " + secs.toFixed(1) + "s (avg " + human(Math.round(avg)) + "/s)";
      }
      var body;
      try {
        body = JSON.parse(xhr.responseText);
      } catch (e) {
        body = null;
      }
      if (xhr.status >= 200 && xhr.status < 300 && body && body.preview_url) {
        var html = '<p>uploaded: <a href="' + esc(body.preview_url) + '">' + esc(body.preview_url) + "</a></p>";
        html += '<p class="hint">raw: <a href="' + esc(body.raw_url) + '">' + esc(body.raw_url) + "</a></p>";
        if (body.exif_stripped) {
          html += '<p class="hint">image metadata stripped before storage</p>';
        }
        if (body.delete_token) {
          html += '<p class="hint">delete token (shown once): <code>' + esc(body.delete_token) + "</code></p>";
        }
        show(html);
        form.reset();
      } else {
        var msg = (body && (body.message || body.error)) || ("upload failed (" + xhr.status + ")");
        show('<p class="notice">' + esc(msg) + "</p>");
      }
    });
    xhr.addEventListener("error", function () {
      bar.hidden = true;
      show('<p class="notice">network error during upload</p>');
    });
    xhr.send(new FormData(form));
  });
})();
