(() => {
  "use strict";

  const loginForm = document.getElementById("passkey-login");
  const registrationForm = document.getElementById("passkey-register");
  if (!loginForm && !registrationForm) return;

  const supported =
    window.isSecureContext &&
    "PublicKeyCredential" in window &&
    navigator.credentials;

  function statusFor(form) {
    return form === loginForm
      ? document.getElementById("passkey-status")
      : document.getElementById("passkey-register-status");
  }

  function setStatus(form, message) {
    const target = statusFor(form);
    if (target) target.textContent = message;
  }

  if (!supported) {
    [loginForm, registrationForm].filter(Boolean).forEach((form) => {
      setStatus(form, "Passkeys are not available in this browser or connection.");
      const button = form.querySelector("button[type=submit]");
      if (button) button.disabled = true;
    });
    return;
  }

  function decodeBase64Url(value) {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/") +
      "=".repeat((4 - (value.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function encodeBase64Url(value) {
    const bytes = new Uint8Array(value);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function creationOptions(payload) {
    const options = payload.publicKey;
    options.challenge = decodeBase64Url(options.challenge);
    options.user.id = decodeBase64Url(options.user.id);
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map((credential) => ({
        ...credential,
        id: decodeBase64Url(credential.id),
      }));
    }
    return { publicKey: options };
  }

  function requestOptions(payload) {
    const options = payload.publicKey;
    options.challenge = decodeBase64Url(options.challenge);
    options.allowCredentials = options.allowCredentials.map((credential) => ({
      ...credential,
      id: decodeBase64Url(credential.id),
    }));
    return { publicKey: options };
  }

  function registrationCredential(credential) {
    return {
      id: credential.id,
      rawId: encodeBase64Url(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: encodeBase64Url(credential.response.attestationObject),
        clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
        transports: credential.response.getTransports
          ? credential.response.getTransports()
          : undefined,
      },
      extensions: credential.getClientExtensionResults(),
    };
  }

  function authenticationCredential(credential) {
    return {
      id: credential.id,
      rawId: encodeBase64Url(credential.rawId),
      type: credential.type,
      response: {
        authenticatorData: encodeBase64Url(credential.response.authenticatorData),
        clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
        signature: encodeBase64Url(credential.response.signature),
        userHandle: credential.response.userHandle
          ? encodeBase64Url(credential.response.userHandle)
          : null,
      },
      extensions: credential.getClientExtensionResults(),
    };
  }

  async function postJson(url, body) {
    const response = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.message || data.error || "Passkey request failed.");
    }
    return data;
  }

  async function runBusy(form, operation) {
    const button = form.querySelector("button[type=submit]");
    if (button) button.disabled = true;
    setStatus(form, "Waiting for your authenticator…");
    try {
      await operation();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Passkey request failed.";
      setStatus(form, message);
    } finally {
      if (button) button.disabled = false;
    }
  }

  if (loginForm) {
    loginForm.addEventListener("submit", (event) => {
      event.preventDefault();
      void runBusy(loginForm, async () => {
        const username = String(new FormData(loginForm).get("username") || "").trim();
        if (!username) throw new Error("Enter your username first.");
        const options = await postJson("/passkeys/auth/start", { username });
        const credential = await navigator.credentials.get(requestOptions(options));
        if (!credential) throw new Error("No passkey was selected.");
        const result = await postJson(
          "/passkeys/auth/finish",
          authenticationCredential(credential),
        );
        window.location.assign(result.redirect || "/account");
      });
    });
  }

  if (registrationForm) {
    registrationForm.addEventListener("submit", (event) => {
      event.preventDefault();
      void runBusy(registrationForm, async () => {
        const name = String(new FormData(registrationForm).get("name") || "").trim();
        const options = await postJson("/account/passkeys/start", { name });
        const credential = await navigator.credentials.create(creationOptions(options));
        if (!credential) throw new Error("No passkey was created.");
        await postJson(
          "/account/passkeys/finish",
          registrationCredential(credential),
        );
        window.location.reload();
      });
    });
  }
})();
