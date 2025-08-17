// frontend/script.js
// Small helper API client for the frontend pages.
// Assumes backend is same-origin; if different origin, update BASE_URL and enable CORS server-side.

const BASE_URL = ""; // empty means same origin; set to 'http://localhost:5000' if needed

async function apiCall(path, method = "GET", body = null, token = null) {
  const headers = { Accept: "application/json" };
  if (body && !(body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(BASE_URL + path, {
    method,
    headers,
    body: body
      ? body instanceof FormData
        ? body
        : JSON.stringify(body)
      : null,
    credentials: "same-origin",
  });
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch (e) {
    return { error: "Invalid JSON response" };
  }
}
