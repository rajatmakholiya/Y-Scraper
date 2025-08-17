// code/frontend/clip.js
const BASE_URL = "http://127.0.0.1:5000";

/**
 * A helper function to make API calls to the backend.
 */
async function apiCall(path, method = "GET", body = null, token = null) {
    const headers = { Accept: "application/json" };
    if (body) headers["Content-Type"] = "application/json";
    if (token) headers["Authorization"] = `Bearer ${token}`;
    
    const res = await fetch(BASE_URL + path, {
        method, headers, body: body ? JSON.stringify(body) : null,
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

/**
 * Converts bytes into a human-readable string.
 */
function prettySize(b) {
    if (b === null || typeof b === 'undefined') return 'N/A';
    if (b === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(b) / Math.log(1024));
    return `${(b / Math.pow(1024, i)).toFixed(2)} ${units[i]}`;
}

// ========== Page-specific Logic ==========

document.addEventListener("DOMContentLoaded", () => {
    const token = localStorage.getItem("token");
    if (!token) {
        window.location.href = "index.html";
        return;
    }

    document.getElementById('btn-logout').addEventListener('click', () => {
        localStorage.removeItem('token');
        window.location.href = 'index.html';
    });
    
    const urlParams = new URLSearchParams(window.location.search);
    const downloadId = urlParams.get("id");

    if (!downloadId) {
        alert("No video ID provided!");
        window.location.href = "dashboard.html";
        return;
    }

    initializeClipPage(token, downloadId);
});

/**
 * Initializes the clipping page.
 */
async function initializeClipPage(token, downloadId) {
    const videoTitle = document.getElementById("video-title");
    const createClipButton = document.getElementById("btn-create-clip");

    try {
        const data = await apiCall(`/api/download/${downloadId}/details`, "GET", null, token);
        videoTitle.textContent = data.title;
        
        // MODIFIED: Load video with authentication
        await loadVideoPlayer(token, downloadId);
        
        renderClips(data.clips, token);

        createClipButton.addEventListener("click", () => createClip(token, downloadId));

        // Periodically refresh the clips list to update their status
        setInterval(() => refreshClips(token, downloadId), 5000);
    } catch (err) {
        alert("Failed to load video details: " + err.message);
        window.location.href = "dashboard.html";
    }
}

/**
 * NEW: Fetches the video file with authentication and loads it into the player.
 */
async function loadVideoPlayer(token, downloadId) {
    const videoPlayer = document.getElementById("video-player");
    try {
        const res = await fetch(`${BASE_URL}/api/file/${downloadId}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!res.ok) {
            throw new Error(`Server responded with status ${res.status}`);
        }

        const videoBlob = await res.blob();
        const videoObjectUrl = URL.createObjectURL(videoBlob);
        videoPlayer.src = videoObjectUrl;
        videoPlayer.load();

    } catch (error) {
        console.error("Failed to load video for preview:", error);
        alert("Could not load video preview. Please try again.");
    }
}


async function createClip(token, downloadId) {
    const startTimeInput = document.getElementById("start-time");
    const endTimeInput = document.getElementById("end-time");
    const errorDiv = document.getElementById("clip-error");

    errorDiv.textContent = "";

    if (!startTimeInput.value || !endTimeInput.value) {
        errorDiv.textContent = "Please provide both a start and end time.";
        return;
    }

    try {
        await apiCall("/api/clip", "POST", {
            download_id: downloadId,
            start_time: startTimeInput.value,
            end_time: endTimeInput.value,
        }, token);
        
        startTimeInput.value = "";
        endTimeInput.value = "";
        // Refresh immediately to show the new pending clip
        await refreshClips(token, downloadId);
    } catch (err) {
        errorDiv.textContent = "Error: " + err.message;
    }
}

/**
 * Fetches the latest clips data and re-renders the list.
 */
async function refreshClips(token, downloadId) {
    const data = await apiCall(`/api/download/${downloadId}/details`, "GET", null, token);
    if (data && data.clips) {
        renderClips(data.clips, token);
    }
}

/**
 * Renders the list of clips with their current status.
 */
function renderClips(clips, token) {
    const list = document.getElementById("clips-list");
    list.innerHTML = "";

    if (!clips || clips.length === 0) {
        list.innerHTML = '<li class="muted">No clips created yet.</li>';
        return;
    }

    for (const clip of clips) {
        const li = document.createElement("li");
        li.className = "list-item";
        
        const statusColors = {
            PENDING: '#e6edf3',
            SUCCESS: '#388bfd',
            FAILURE: '#f85149',
            PROCESSING: '#d29922'
        };
        const statusText = clip.status.charAt(0).toUpperCase() + clip.status.slice(1).toLowerCase();

        let content = `
            <div class="list-item-content">
                <div class="list-item-title-container">
                     <span class="list-item-title">${clip.title}</span>
                     <span class="list-item-size">(${prettySize(clip.size_bytes)})</span>
                </div>
                <div class="list-item-buttons">
                    <span style="font-weight: 600; color: ${statusColors[clip.status] || '#e6edf3'}">${statusText}</span>
        `;

        if (clip.status === "SUCCESS") {
            content += `<a href="#" onclick="downloadClip(${clip.id}, '${clip.title}', '${token}'); return false;" class="btn small" style="margin-left: 1rem;">Download</a>`;
        }
        
        content += `</div></div>`;
        li.innerHTML = content;
        list.appendChild(li);
    }
}

/**
 * Downloads a completed clip file.
 */
async function downloadClip(clipId, filename, token) {
    try {
        const res = await fetch(`${BASE_URL}/api/clip/${clipId}/file`, {
            headers: { Authorization: `Bearer ${token}` },
        });

        if (!res.ok) throw new Error(`Server responded with status ${res.status}`);

        const blob = await res.blob();
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    } catch (error) {
        alert("Failed to download clip: " + error.message);
    }
}