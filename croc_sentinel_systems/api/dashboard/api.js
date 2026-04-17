(function () {
  const LS = "croc_sentinel_api_token";
  const LS_USER = "croc_sentinel_api_user";

  function apiBase() {
    const u = new URL(window.location.href);
    return u.origin;
  }

  function getToken() {
    return localStorage.getItem(LS) || "";
  }

  function setToken(t) {
    if (t) localStorage.setItem(LS, t);
    else localStorage.removeItem(LS);
  }

  async function apiFetch(path, opts) {
    const token = getToken();
    const headers = Object.assign(
      { Authorization: token ? "Bearer " + token : "" },
      opts && opts.headers ? opts.headers : {}
    );
    if (opts && opts.body && typeof opts.body === "object" && !(opts.body instanceof FormData)) {
      headers["Content-Type"] = "application/json";
      opts = Object.assign({}, opts, { body: JSON.stringify(opts.body) });
    }
    const r = await fetch(apiBase() + path, Object.assign({}, opts, { headers }));
    if (!r.ok) {
      const txt = await r.text();
      throw new Error(r.status + " " + txt);
    }
    const ct = r.headers.get("content-type") || "";
    if (ct.includes("application/json")) return r.json();
    return r.text();
  }

  window.CrocApi = {
    LS,
    LS_USER,
    apiBase,
    getToken,
    setToken,
    apiFetch,
  };
})();
