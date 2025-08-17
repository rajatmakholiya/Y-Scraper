// frontend/script.js
// API Client and all frontend logic for the application.

const BASE_URL = "http://127.0.0.1:5000";

/**
 * A helper function to make API calls to the backend.
 * @param {string} path - The API endpoint path (e.g., /api/recent).
 * @param {string} method - The HTTP method (e.g., 'GET', 'POST').
 * @param {object|null} body - The request body for POST/PUT requests.
 * @param {string|null} token - The JWT token for authorization.
 * @returns {Promise<object>} - The JSON response from the API.
 */
async function apiCall(path, method = "GET", body = null, token = null) {
  const headers = { Accept: "application/json" };
  if (body) {
    headers["Content-Type"] = "application/json";
  }
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  const res = await fetch(BASE_URL + path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : null,
  });
  // Check for empty or non-JSON responses
  const text = await res.text();
  if (!text) {
    return { error: "Empty response from server" };
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    console.error("Invalid JSON response:", text);
    return { error: "Invalid JSON response from server" };
  }
}


// ========== Page-specific Logic ==========

// Run dashboard-specific code only if we are on dashboard.html
if (window.location.pathname.endsWith("dashboard.html")) {
  
  // This logic runs first to capture the token from the URL after Google login
  (function handleTokenFromUrl() {
    const urlParams = new URLSearchParams(window.location.search);
    const tokenFromUrl = urlParams.get('token');
    if (tokenFromUrl) {
      localStorage.setItem('token', tokenFromUrl);
      // Clean the URL to remove the token
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  })();

  const token = localStorage.getItem('token');
  if (!token) {
    window.location.href = 'index.html';
  } else {
    // If a token exists, initialize the dashboard
    initializeDashboard(token);
  }
}

/**
 * Sets up all the event listeners and loads initial data for the dashboard.
 * @param {string} token - The user's JWT token.
 */
function initializeDashboard(token) {
  const logoutButton = document.getElementById('btn-logout');
  const downloadButton = document.getElementById('btn-download');

  logoutButton.addEventListener('click', () => {
    localStorage.removeItem('token');
    window.location.href = 'index.html';
  });

  downloadButton.addEventListener('click', async () => {
    const urlInput = document.getElementById('video-url');
    const url = urlInput.value.trim();
    if (!url) {
      alert('Please provide a URL.');
      return;
    }
    
    const progressMsg = document.getElementById('progress-msg');
    const progressBar = document.getElementById('progress-bar');

    progressMsg.textContent = 'Starting download...';
    progressBar.style.display = 'block';
    progressBar.value = 0;

    const res = await apiCall('/api/download', 'POST', { url }, token);

    if (res.error) {
      alert('Error: ' + res.error);
      progressMsg.textContent = '';
      progressBar.style.display = 'none';
    } else {
      progressMsg.textContent = `Completed: ${res.title} (${prettySize(res.size_bytes)})`;
      progressBar.value = 100;
      urlInput.value = ''; // Clear the input field
      await refreshRecent(token);
    }
  });

  // Load the initial list of recent downloads
  refreshRecent(token);
}

/**
 * Fetches the list of recent downloads and renders them on the page.
 * @param {string} token - The user's JWT token.
 */
async function refreshRecent(token) {
  const res = await apiCall('/api/recent', 'GET', null, token);
  const list = document.getElementById('recent-list');
  list.innerHTML = '';

  if (!res || !res.downloads || res.downloads.length === 0) {
    list.innerHTML = '<li class="muted">No downloads yet.</li>';
    return;
  }

  for (const d of res.downloads) {
    const li = document.createElement('li');
    li.className = 'list-item';
    
    const a = document.createElement('a');
    a.href = `#`; // Use # to prevent page reload
    a.textContent = `${d.title} (${prettySize(d.size_bytes)})`;
    a.addEventListener('click', (ev) => {
      ev.preventDefault();
      downloadFile(d.id, d.title, token);
    });
    
    li.appendChild(a);
    list.appendChild(li);
  }
}

/**
 * Fetches a file using its ID and triggers a browser download.
 * @param {number} id - The ID of the download.
 * @param {string} filenameHint - The original title of the file.
 * @param {string} token - The user's JWT token.
 */
async function downloadFile(id, filenameHint, token) {
  try {
    const res = await fetch(`/api/file/${id}`, {
      headers: { Authorization: `Bearer ${token}` }
    });

    if (!res.ok) {
      throw new Error('Failed to fetch file. Server responded with ' + res.status);
    }

    const blob = await res.blob();
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filenameHint; // Use the title as the default filename
    document.body.appendChild(link);
    link.click();
    URL.revokeObjectURL(link.href);
    link.remove();
  } catch (error) {
    console.error('Download error:', error);
    alert('Could not download the file.');
  }
}

/**
 * Converts bytes into a human-readable string (KB, MB, GB).
 * @param {number} b - The number of bytes.
 * @returns {string} - The human-readable size.
 */
function prettySize(b) {
  if (!b || b === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(b) / Math.log(1024));
  return `${(b / Math.pow(1024, i)).toFixed(2)} ${units[i]}`;
}