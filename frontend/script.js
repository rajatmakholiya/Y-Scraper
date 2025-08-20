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
  const text = await res.text();
  if (!res.ok) {
      try {
          const parsed = JSON.parse(text);
          throw new Error(parsed.error || "An unknown error occurred");
      } catch (e) {
          throw new Error(text || "An unknown error occurred");
      }
  }
  return text ? JSON.parse(text) : {};
}


// ========== Page-specific Logic ==========

// Run page-specific logic after the DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
    // If we are on the login page (index.html)
    if (document.getElementById('btn-continue')) {
        initializeLoginPage();
    } 
    // If we are on the dashboard page
    else if (window.location.pathname.endsWith("dashboard.html")) {
        // --- This was the logic for the original Google Login flow ---
        /*
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
        */

        const token = localStorage.getItem('token');
        if (!token) {
            window.location.href = 'index.html'; // Redirect if no token
        } else {
            // If a token exists, initialize the dashboard
            initializeDashboard(token);
        }
    }
});

/**
 * Sets up the login page button for the new guest login.
 */
function initializeLoginPage() {
    const continueButton = document.getElementById('btn-continue');
    continueButton.addEventListener('click', async () => {
        try {
            const res = await apiCall('/api/login/guest', 'POST');
            if (res.access_token) {
                localStorage.setItem('token', res.access_token);
                window.location.href = 'dashboard.html';
            } else {
                alert('Could not log in as guest. Check the backend server.');
            }
        } catch (error) {
            console.error('Login failed:', error);
            alert('Login failed: ' + error.message);
        }
    });
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

    try {
        const res = await apiCall('/api/download', 'POST', { url }, token);
        progressMsg.textContent = `Completed: ${res.title} (${prettySize(res.size_bytes)})`;
        progressBar.value = 100;
        urlInput.value = ''; // Clear the input field
        await refreshRecent(token);
    } catch (err) {
        alert('Error: ' + err.message);
        progressMsg.textContent = 'Download failed.';
        progressBar.style.display = 'none';
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

        const contentDiv = document.createElement('div');
        contentDiv.className = 'list-item-content';

        const titleSpan = document.createElement('span');
        titleSpan.textContent = d.title;
        titleSpan.className = 'list-item-title';
        
        const sizeSpan = document.createElement('span');
        sizeSpan.textContent = `(${prettySize(d.size_bytes)})`;
        sizeSpan.className = 'list-item-size';

        const titleContainer = document.createElement('div');
        titleContainer.appendChild(titleSpan);
        titleContainer.appendChild(sizeSpan);

        const buttonsDiv = document.createElement('div');
        buttonsDiv.className = 'list-item-buttons';

        const clipBtn = document.createElement('a');
        clipBtn.href = `clip.html?id=${d.id}`;
        clipBtn.textContent = 'Clip';
        clipBtn.className = 'btn small';
        
        const deleteBtn = document.createElement('button');
        deleteBtn.textContent = 'Delete';
        deleteBtn.className = 'btn small btn-delete';
        deleteBtn.onclick = () => {
            if (confirm(`Are you sure you want to delete "${d.title}"?`)) {
                deleteDownload(d.id, token);
            }
        };
        
        buttonsDiv.appendChild(clipBtn);
        buttonsDiv.appendChild(deleteBtn);

        contentDiv.appendChild(titleContainer);
        contentDiv.appendChild(buttonsDiv);
        
        li.appendChild(contentDiv);
        list.appendChild(li);
    }
}

/**
 * Deletes a downloaded file.
 * @param {number} id - The ID of the download.
 * @param {string} token - The user's JWT token.
 */
async function deleteDownload(id, token) {
    try {
        await apiCall(`/api/download/${id}`, 'DELETE', null, token);
        await refreshRecent(token);
    } catch (err) {
        alert('Error: ' + err.message);
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