import assert from "node:assert/strict";
import test from "node:test";
import { auth, fetchConsoleAPI } from "./auth.ts";

function browserFixture(t) {
  const values = new Map();
  const localStorage = {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: (key) => values.delete(key),
  };
  const redirects = [];
  const document = { cookie: "" };
  const window = {
    localStorage,
    location: { protocol: "https:", replace: (path) => redirects.push(path) },
  };
  for (const [name, value] of Object.entries({ window, document, localStorage })) {
    const original = Object.getOwnPropertyDescriptor(globalThis, name);
    Object.defineProperty(globalThis, name, { configurable: true, value });
    t.after(() => {
      if (original) Object.defineProperty(globalThis, name, original);
      else delete globalThis[name];
    });
  }
  return { document, redirects };
}

const challenge = { "WWW-Authenticate": "Bearer" };

test("a rejected download clears the browser session and preserves the raw response", async (t) => {
  const { document, redirects } = browserFixture(t);
  auth.setToken("fixture-token");
  t.mock.method(globalThis, "fetch", (_path, init) => {
    assert.equal(init.mode, "same-origin");
    return Promise.resolve(new Response("download rejected", { status: 401, headers: challenge }));
  });

  const response = await fetchConsoleAPI("/api/export", {
    headers: new Headers({ Authorization: "Bearer fixture-token" }),
  });
  assert.equal(await response.text(), "download rejected");
  assert.equal(auth.getToken(), null);
  assert.match(document.cookie, /max-age=0/);
  assert.deepEqual(redirects, ["/login"]);
});

test("a late response for an old token preserves the latest sign-in", async (t) => {
  const { redirects } = browserFixture(t);
  auth.setToken("old-token");
  let complete;
  t.mock.method(globalThis, "fetch", () => new Promise((resolve) => { complete = resolve; }));
  const pending = fetchConsoleAPI("/api/export", { headers: { Authorization: "Bearer old-token" } });

  auth.setToken("new-token");
  complete(new Response(null, { status: 401, headers: challenge }));
  await pending;

  assert.equal(auth.getToken(), "new-token");
  assert.deepEqual(redirects, []);
});

test("401 without a Bearer challenge does not clear the session", async (t) => {
  const { redirects } = browserFixture(t);
  auth.setToken("fixture-token");
  t.mock.method(globalThis, "fetch", async () => new Response(null, { status: 401 }));
  await fetchConsoleAPI("/api/auth/change-password", { headers: { Authorization: "Bearer fixture-token" } });
  assert.equal(auth.getToken(), "fixture-token");
  assert.deepEqual(redirects, []);
});
