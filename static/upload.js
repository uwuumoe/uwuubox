// Progressive enhancement for the upload form: XHR with a progress bar that
// renders the JSON links in place. Without JS the form posts natively and the
// server 303-redirects to the preview page.
(function () {
  var form = document.getElementById("upload");
  var file = document.getElementById("file");
  var bar = document.getElementById("bar");
  var result = document.getElementById("result");
  if (!form || !file || !bar || !result || !window.XMLHttpRequest) return;

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

    var xhr = new XMLHttpRequest();
    xhr.open("POST", form.action);
    xhr.setRequestHeader("Accept", "application/json");
    xhr.upload.addEventListener("progress", function (e) {
      if (e.lengthComputable) bar.value = Math.round((e.loaded / e.total) * 100);
    });
    xhr.addEventListener("load", function () {
      bar.hidden = true;
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
