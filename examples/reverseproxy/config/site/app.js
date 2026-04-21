const issuer = "https://oidc.localhost:8443";
const clientId = "sample-spa-client";
const redirectPath = "/auth/callback";
const scopes = ["openid", "profile", "email", "offline_access", "User.Read"];
const tokenStorageKey = "oidcld-edge-sample-token";
const verifierStorageKey = "oidcld-edge-sample-code-verifier";
const stateStorageKey = "oidcld-edge-sample-state";

const app = document.querySelector("#app");
const loginButton = document.querySelector("#login-button");
const logoutButton = document.querySelector("#logout-button");
const reloadButton = document.querySelector("#reload-button");

loginButton.addEventListener("click", () => {
  void startLogin();
});
logoutButton.addEventListener("click", () => {
  signOut();
});
reloadButton.addEventListener("click", () => {
  window.location.reload();
});

document.querySelectorAll("[data-route]").forEach((link) => {
  link.addEventListener("click", (event) => {
    event.preventDefault();
    const route = link.getAttribute("data-route") || "/";
    history.pushState({}, "", route);
    render();
  });
});

window.addEventListener("popstate", () => render());

void bootstrap();

async function bootstrap() {
  if (window.location.pathname === redirectPath && window.location.search.includes("code=")) {
    await finishLogin();
    history.replaceState({}, "", "/dashboard");
  }
  render();
}

function render() {
  updateHeaderState();
  const route = currentRoute();
  setActiveRoute(route);
  if (route === "/dashboard") {
    renderDashboard();
    return;
  }
  renderHome();
}

function updateHeaderState() {
  const token = readToken();
  logoutButton.disabled = !token;
}

function setActiveRoute(route) {
  document.querySelectorAll("[data-route]").forEach((link) => {
    link.classList.toggle("active", link.getAttribute("data-route") === route);
  });
}

function currentRoute() {
  return window.location.pathname === "/dashboard" ? "/dashboard" : "/";
}

function renderHome() {
  const token = readToken();
  app.innerHTML = `
    <section class="panel-grid">
      <article class="panel">
        <h2>What this sample demonstrates</h2>
        <div class="status-grid">
          <div class="status-card">
            <p>Static hosting</p>
            <strong>Served from <code>static_dir</code></strong>
          </div>
          <div class="status-card">
            <p>SPA fallback</p>
            <strong>Reload <code>/dashboard</code> safely</strong>
          </div>
          <div class="status-card">
            <p>API route</p>
            <strong><code>/api</code> comes from OpenAPI mock</strong>
          </div>
          <div class="status-card">
            <p>Gateway</p>
            <strong>Bearer token with <code>User.Read</code> required</strong>
          </div>
        </div>
        <p class="copy" style="margin-top:1rem">
          Use <strong>Sign In</strong> to complete an Authorization Code + PKCE round trip against OIDCLD.
          The issued access token is then sent to the mock API route, which enforces the gateway rule before returning example responses.
        </p>
      </article>
      <article class="panel">
        <h2>Session status</h2>
        <div class="pill-row">
          <span class="pill ${token ? "success" : "warning"}">${token ? "Authenticated" : "Signed out"}</span>
          <span class="pill">${token ? "Audience: sample-spa-client" : "No token stored"}</span>
        </div>
        <p class="copy" style="margin-top:1rem">
          The sample token request asks for:
          <code>${scopes.join(" ")}</code>
        </p>
        <p class="copy" style="margin-top:1rem">
          Explore the other sample hosts:
          <a href="https://react.localhost:8443/" style="color:#8cc5ff">react.localhost</a>
          and
          <a href="https://api.localhost:8443/health" style="color:#8cc5ff">api.localhost</a>.
        </p>
      </article>
    </section>
  `;
}

function renderDashboard() {
  const token = readToken();
  app.innerHTML = `
    <section class="panel-grid">
      <article class="panel">
        <h2>Mock API</h2>
        <p class="copy">
          These buttons call the OpenAPI-backed route on <code>/api</code>. The route is protected by gateway rules, so requests fail with <code>401</code> until you sign in.
        </p>
        <div class="api-actions">
          <button data-api="health" data-method="get">GET /api/health</button>
          <button data-api="items" data-method="get">GET /api/items</button>
          <button data-api="create" data-method="post">POST /api/items</button>
          <button data-api="delete" data-method="delete">DELETE /api/items/demo-1</button>
        </div>
        <div class="pill-row" style="margin-top:1rem">
          <span class="pill ${token ? "success" : "error"}">${token ? "Gateway token ready" : "Gateway will reject calls"}</span>
        </div>
      </article>
      <article class="panel">
        <h2>Last response</h2>
        <pre id="response-log">${JSON.stringify({ message: "No request sent yet" }, null, 2)}</pre>
      </article>
    </section>
    <section class="panel" style="margin-top:1rem">
      <h2>Notes</h2>
      <div class="list">
        <div class="list-item">
          <h3>Virtual Host</h3>
          <p><code>app.localhost</code> is terminated by OIDCLD on the same HTTPS listener as the issuer.</p>
        </div>
        <div class="list-item">
          <h3>OpenAPI mock</h3>
          <p>Responses are served from named examples in <code>examples/reverseproxy/config/openapi/mock.yaml</code>.</p>
        </div>
        <div class="list-item">
          <h3>Gateway auth</h3>
          <p>The <code>/api</code> route requires a self-issued Bearer token with <code>User.Read</code> and audience <code>sample-spa-client</code>.</p>
        </div>
      </div>
    </section>
  `;

  app.querySelectorAll("[data-api]").forEach((button) => {
    button.addEventListener("click", () => {
      void callApi(button.getAttribute("data-api"));
    });
  });
}

async function startLogin() {
  const redirectUri = `${window.location.origin}${redirectPath}`;
  const state = randomString(16);
  const codeVerifier = randomString(64);
  sessionStorage.setItem(verifierStorageKey, codeVerifier);
  sessionStorage.setItem(stateStorageKey, state);
  const codeChallenge = await pkceChallenge(codeVerifier);

  const authorizeUrl = new URL(`${issuer}/authorize`);
  authorizeUrl.searchParams.set("client_id", clientId);
  authorizeUrl.searchParams.set("redirect_uri", redirectUri);
  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("scope", scopes.join(" "));
  authorizeUrl.searchParams.set("state", state);
  authorizeUrl.searchParams.set("code_challenge_method", "S256");
  authorizeUrl.searchParams.set("code_challenge", codeChallenge);

  window.location.assign(authorizeUrl.toString());
}

async function finishLogin() {
  const search = new URLSearchParams(window.location.search);
  const code = search.get("code");
  const state = search.get("state");
  const expectedState = sessionStorage.getItem(stateStorageKey);
  const codeVerifier = sessionStorage.getItem(verifierStorageKey);

  if (!code || !state || !expectedState || state !== expectedState || !codeVerifier) {
    throw new Error("Missing or invalid authorization response");
  }

  const redirectUri = `${window.location.origin}${redirectPath}`;
  const tokenResponse = await fetch(`${issuer}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: clientId,
      code,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
    }),
  });

  if (!tokenResponse.ok) {
    throw new Error(`Token exchange failed with ${tokenResponse.status}`);
  }

  const payload = await tokenResponse.json();
  localStorage.setItem(tokenStorageKey, payload.access_token);
  sessionStorage.removeItem(verifierStorageKey);
  sessionStorage.removeItem(stateStorageKey);
}

function signOut() {
  localStorage.removeItem(tokenStorageKey);
  const logoutUrl = new URL(`${issuer}/end_session`);
  logoutUrl.searchParams.set("post_logout_redirect_uri", `${window.location.origin}/`);
  window.location.assign(logoutUrl.toString());
}

async function callApi(kind) {
  const responseLog = document.querySelector("#response-log");
  const token = readToken();
  const headers = token ? { Authorization: `Bearer ${token}` } : {};

  let response;
  switch (kind) {
    case "health":
      response = await fetch("/api/health", { headers });
      break;
    case "items":
      response = await fetch("/api/items", { headers });
      break;
    case "create":
      response = await fetch("/api/items", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...headers },
        body: JSON.stringify({ title: "Created from sample SPA" }),
      });
      break;
    case "delete":
      response = await fetch("/api/items/demo-1", {
        method: "DELETE",
        headers,
      });
      break;
    default:
      return;
  }

  const text = await response.text();
  let body = text;
  try {
    body = JSON.parse(text);
  } catch (_) {
    // Keep raw text when it is not JSON.
  }

  responseLog.textContent = JSON.stringify({
    status: response.status,
    ok: response.ok,
    path: response.url,
    body,
  }, null, 2);
}

function readToken() {
  return localStorage.getItem(tokenStorageKey);
}

function randomString(length) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => chars[value % chars.length]).join("");
}

async function pkceChallenge(verifier) {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return base64UrlEncode(new Uint8Array(digest));
}

function base64UrlEncode(bytes) {
  let value = "";
  bytes.forEach((byte) => {
    value += String.fromCharCode(byte);
  });
  return btoa(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
