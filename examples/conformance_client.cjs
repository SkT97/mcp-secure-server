/* Supply the test client's bearer token only to the exact protected fixture URL. */
const endpoint = process.env.CONFORMANCE_TEST_ENDPOINT;
const token = process.env.CONFORMANCE_TEST_TOKEN;
delete process.env.CONFORMANCE_TEST_TOKEN;
delete process.env.CONFORMANCE_TEST_ENDPOINT;

if (!/^http:\/\/127\.0\.0\.1:[1-9][0-9]*\/mcp$/.test(endpoint || "") || !token) {
  throw new Error("the conformance client needs a loopback fixture and an ephemeral token");
}

const originalFetch = globalThis.fetch;
globalThis.fetch = (input, options) => {
  const url = input instanceof Request ? input.url : String(input);
  if (url !== endpoint) {
    return originalFetch(input, options);
  }
  const headers = new Headers(options?.headers ?? (input instanceof Request ? input.headers : undefined));
  if (!headers.has("Authorization")) {
    headers.set("Authorization", "Bearer " + token);
  }
  return originalFetch(input, { ...options, headers, redirect: "error" });
};
