(() => {
  "use strict";

  async function jsonRequest(url, options = {}) {
    const response = await fetch(url, {
      credentials: "same-origin",
      ...options,
      headers: { Accept: "application/json", ...(options.headers || {}) },
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.message || payload.error || `request failed (${response.status})`);
    }
    return payload;
  }

  for (const form of document.querySelectorAll("form[data-api-form]")) {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const status = form.closest("section")?.querySelector("[data-api-status]");
      const submit = form.querySelector("button[type=submit]");
      const body = Object.fromEntries(new FormData(form).entries());
      if (submit) submit.disabled = true;
      if (status) status.textContent = "saving…";
      try {
        await jsonRequest(form.action, {
          method: form.dataset.method || "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        if (form.dataset.success) {
          window.location.assign(form.dataset.success);
        } else {
          window.location.reload();
        }
      } catch (error) {
        if (status) status.textContent = error.message;
        if (submit) submit.disabled = false;
      }
    });
  }

  for (const section of document.querySelectorAll("[data-comments]")) {
    const kind = section.dataset.targetKind;
    const core = section.dataset.targetCore;
    const list = section.querySelector("[data-comment-list]");
    const pages = section.querySelector("[data-comment-pages]");
    const status = section.querySelector("[data-comment-status]");
    const form = section.querySelector("[data-comment-form]");
    let currentPage = 1;

    const load = async (page = 1) => {
      try {
        const query = new URLSearchParams({ target_kind: kind, target_core: core, page });
        const payload = await jsonRequest(`/api/comments?${query}`);
        currentPage = payload.page;
        list.replaceChildren();
        if (!payload.comments.length) {
          const empty = document.createElement("li");
          empty.className = "hint";
          empty.textContent = "no comments yet.";
          list.append(empty);
        }
        for (const comment of payload.comments) {
          const row = document.createElement("li");
          const content = document.createElement("span");
          const author = document.createElement("strong");
          author.textContent = comment.author_name;
          const time = document.createElement("span");
          time.className = "dim";
          time.textContent = ` · ${new Date(comment.created_at).toLocaleString()}`;
          const body = document.createElement("span");
          body.style.whiteSpace = "pre-wrap";
          body.style.overflowWrap = "anywhere";
          body.textContent = `\n${comment.body}`;
          content.append(author, time, body);
          row.append(content);
          if (comment.can_delete) {
            const remove = document.createElement("button");
            remove.type = "button";
            remove.textContent = "delete";
            remove.addEventListener("click", async () => {
              remove.disabled = true;
              try {
                await jsonRequest(`/api/comments/${comment.id}`, { method: "DELETE" });
                await load(currentPage);
              } catch (error) {
                if (status) status.textContent = error.message;
                remove.disabled = false;
              }
            });
            row.append(remove);
          }
          list.append(row);
        }
        pages.replaceChildren();
        if (payload.page > 1) {
          const newer = document.createElement("button");
          newer.type = "button";
          newer.className = "linklike";
          newer.textContent = "← newer";
          newer.addEventListener("click", () => load(payload.page - 1));
          pages.append(newer);
        }
        if (payload.has_next) {
          const older = document.createElement("button");
          older.type = "button";
          older.className = "linklike";
          older.textContent = "older →";
          older.addEventListener("click", () => load(payload.page + 1));
          pages.append(older);
        }
      } catch (error) {
        list.replaceChildren();
        const failed = document.createElement("li");
        failed.className = "hint";
        failed.textContent = error.message;
        list.append(failed);
      }
    };

    form?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const textarea = form.elements.body;
      const submit = form.querySelector("button[type=submit]");
      if (submit) submit.disabled = true;
      if (status) status.textContent = "posting…";
      try {
        await jsonRequest("/api/comments", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ target_kind: kind, target_core: core, body: textarea.value }),
        });
        textarea.value = "";
        if (status) status.textContent = "";
        await load(1);
      } catch (error) {
        if (status) status.textContent = error.message;
      } finally {
        if (submit) submit.disabled = false;
      }
    });

    load();
  }
})();
