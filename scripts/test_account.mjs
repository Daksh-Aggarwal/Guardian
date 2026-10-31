import assert from "node:assert/strict";
import { test } from "node:test";
import { createClient } from "@supabase/supabase-js";
import { accountRequest } from "../lib/account-request.ts";

const session = (token) => ({
  data: { session: token ? { access_token: token } : null },
  error: null,
});

test("account requests reject anonymous sessions without fetching", async () => {
  let calls = 0;
  const old = globalThis.fetch;
  globalThis.fetch = async () => {
    calls++;
    throw new Error("unexpected");
  };
  try {
    await assert.rejects(
      accountRequest(
        {
          getSession: async () => session(null),
          refreshSession: async () => session(null),
        },
        "/scans",
      ),
      /expired/,
    );
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = old;
  }
});

test("expired access token refreshes once and uses the new bearer", async () => {
  const old = globalThis.fetch,
    tokens = [];
  globalThis.fetch = async (url, options) => {
    assert.equal(url, "/api/account/scans");
    assert.equal(options.cache, "no-store");
    tokens.push(options.headers.get("Authorization"));
    return tokens.length === 1
      ? new Response("{}", { status: 401 })
      : Response.json([{ id: "real-response" }]);
  };
  try {
    let refreshes = 0;
    const result = await accountRequest(
      {
        getSession: async () => session("expired"),
        refreshSession: async () => {
          refreshes++;
          return session("rotated");
        },
      },
      "/scans",
    );
    assert.deepEqual(result, [{ id: "real-response" }]);
    assert.equal(refreshes, 1);
    assert.deepEqual(tokens, ["Bearer expired", "Bearer rotated"]);
  } finally {
    globalThis.fetch = old;
  }
});

test("failed refresh and revoked sessions remain visible", async () => {
  const old = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response("{}", { status: 401 });
    await assert.rejects(
      accountRequest(
        {
          getSession: async () => session("expired"),
          refreshSession: async () => session(null),
        },
        "/devices",
      ),
      /expired/,
    );
    globalThis.fetch = async () =>
      Response.json({ detail: "Device revoked" }, { status: 403 });
    await assert.rejects(
      accountRequest(
        {
          getSession: async () => session("token"),
          refreshSession: async () => session("token"),
        },
        "/devices",
      ),
      /revoked/,
    );
  } finally {
    globalThis.fetch = old;
  }
});

test("official Supabase SDK persists, restores, emits session events and logs out", async () => {
  const data = new Map(),
    events = [];
  const storage = {
    getItem: (key) => data.get(key) ?? null,
    setItem: (key, value) => data.set(key, value),
    removeItem: (key) => data.delete(key),
  };
  const id = "114ea5da-39fd-4b72-bdd2-a53c7ca6d875";
  const user = {
    id,
    aud: "authenticated",
    role: "authenticated",
    email: "user@example.test",
    app_metadata: { provider: "github" },
    user_metadata: {},
    created_at: new Date().toISOString(),
  };
  const token = [
    "eyJhbGciOiJIUzI1NiJ9",
    Buffer.from(
      JSON.stringify({ sub: id, exp: Math.floor(Date.now() / 1000) + 3600 }),
    ).toString("base64url"),
    "test-signature",
  ].join(".");
  const fetch = async (url) =>
    url.includes("/user")
      ? Response.json(user)
      : new Response(null, { status: 204 });
  const options = {
    global: { fetch },
    auth: {
      storage,
      storageKey: "guardian-test",
      persistSession: true,
      autoRefreshToken: false,
      detectSessionInUrl: false,
      flowType: "pkce",
    },
  };
  const client = createClient(
    "https://guardian-test.supabase.co",
    "sb_publishable_test",
    options,
  );
  const listener = client.auth.onAuthStateChange((event) => events.push(event));
  const connected = await client.auth.setSession({
    access_token: token,
    refresh_token: "mock-refresh-token",
  });
  assert.equal(connected.error, null);
  assert.equal(connected.data.user.id, id);
  assert.ok(data.get("guardian-test"));
  const restored = createClient(
    "https://guardian-test.supabase.co",
    "sb_publishable_test",
    options,
  );
  assert.equal((await restored.auth.getSession()).data.session.user.id, id);
  assert.equal((await client.auth.signOut({ scope: "local" })).error, null);
  assert.equal((await client.auth.getSession()).data.session, null);
  assert.ok(events.includes("SIGNED_IN") && events.includes("SIGNED_OUT"));
  assert.equal(data.has("guardian-test"), false);
  listener.data.subscription.unsubscribe();
});

test("website GitHub login generates PKCE and exchanges the code through the SDK", async () => {
  const data = new Map();
  const storage = {
    getItem: (key) => data.get(key) ?? null,
    setItem: (key, value) => data.set(key, value),
    removeItem: (key) => data.delete(key),
  };
  let exchanged = false;
  const fetch = async (url, options) => {
    assert.ok(url.includes("grant_type=pkce"));
    const body = JSON.parse(options.body);
    assert.equal(body.auth_code, "one-use-code");
    assert.ok(body.code_verifier.length >= 43);
    exchanged = true;
    return Response.json({
      access_token: "mock-access-token",
      refresh_token: "mock-refresh-token",
      token_type: "bearer",
      expires_in: 3600,
      user: { id: "test-user", aud: "authenticated", user_metadata: {} },
    });
  };
  const client = createClient(
    "https://guardian-test.supabase.co",
    "sb_publishable_test",
    {
      global: { fetch },
      auth: {
        storage,
        storageKey: "guardian-pkce",
        flowType: "pkce",
        persistSession: true,
        autoRefreshToken: false,
        detectSessionInUrl: false,
      },
    },
  );
  const result = await client.auth.signInWithOAuth({
    provider: "github",
    options: {
      redirectTo: "https://guardian.example/auth/callback",
      skipBrowserRedirect: true,
      scopes: "read:user user:email",
    },
  });
  assert.equal(result.error, null);
  const url = new URL(result.data.url);
  assert.equal(url.searchParams.get("provider"), "github");
  assert.equal(
    url.searchParams.get("redirect_to"),
    "https://guardian.example/auth/callback",
  );
  assert.equal(url.searchParams.get("code_challenge_method"), "s256");
  assert.match(url.searchParams.get("code_challenge"), /^[A-Za-z0-9_-]{43}$/);
  assert.ok(data.get("guardian-pkce-code-verifier"));
  const session = await client.auth.exchangeCodeForSession("one-use-code");
  assert.equal(session.error, null);
  assert.ok(exchanged);
  assert.equal(session.data.session.refresh_token, "mock-refresh-token");
  assert.equal(data.has("guardian-pkce-code-verifier"), false);
});
