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
    const clearQueueButton = document.getElementById("btn-clear-queue");

    try {
        const data = await apiCall(`/api/download/${downloadId}/details`, "GET", null, token);
        videoTitle.textContent = data.title;
        
        await loadVideoPlayer(token, downloadId);
        
        renderClips(data.clips, token);

        createClipButton.addEventListener("click", () => createClip(token, downloadId));
        clearQueueButton.addEventListener("click", () => clearQueue(token, downloadId));

        // Periodically refresh the clips list to update their status
        setInterval(() => refreshClips(token, downloadId), 3000);
    } catch (err) {
        alert("Failed to load video details: " + err.message);
        window.location.href = "dashboard.html";
    }
}

/**
 * Fetches the video file with authentication and loads it into the player.
 */
async function loadVideoPlayer(token, downloadId) {
    const videoPlayer = document.getElementById("video-player");
    try {
        const res = await fetch(`${BASE_URL}/api/file/${downloadId}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!res.ok) throw new Error(`Server responded with status ${res.status}`);

        const videoBlob = await res.blob();
        const videoObjectUrl = URL.createObjectURL(videoBlob);
        videoPlayer.src = videoObjectUrl;
        videoPlayer.load();

    } catch (error) {
        console.error("Failed to load video for preview:", error);
        alert("Could not load video preview. Please try again.");
    }
}

/**
 * MODIFIED: Handles the creation of a new clip with immediate UI update.
 */
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
        // 1. Send the request to the backend to start the clipping job.
        await apiCall("/api/clip", "POST", {
            download_id: downloadId,
            start_time: startTimeInput.value,
            end_time: endTimeInput.value,
        }, token);
        
        // 2. Clear the input fields.
        startTimeInput.value = "";
        endTimeInput.value = "";

        // 3. Perform a quick refresh to immediately show the new "Pending" item.
        // We don't need to wait for the full polling cycle.
        const data = await apiCall(`/api/download/${downloadId}/details`, "GET", null, token);
        if (data && data.clips) {
            renderClips(data.clips, token);
        }

    } catch (err) {
        errorDiv.textContent = "Error: " + err.message;
    }
}

/**
 * Handles clearing the entire clip queue.
 */
async function clearQueue(token, downloadId) {
    if (!confirm("Are you sure you want to delete all clips and cancel any pending jobs? This cannot be undone.")) {
        return;
    }
    try {
        await apiCall(`/api/download/${downloadId}/clips`, 'DELETE', null, token);
        await refreshClips(token, downloadId);
    } catch (err) {
        alert("Failed to clear queue: " + err.message);
    }
}


/**
 * Fetches the latest clips data, triggers status checks, and re-renders the lists.
 */
async function refreshClips(token, downloadId) {
    try {
        const data = await apiCall(`/api/download/${downloadId}/details`, "GET", null, token);
        if (!data || !data.clips) {
            renderClips([], token);
            return;
        }

        const pendingClips = data.clips.filter(c => c.status === 'PENDING' || c.status === 'PROCESSING');
        
        // If there are no pending clips, we don't need to do the heavy update.
        if (pendingClips.length === 0) {
            renderClips(data.clips, token);
            return;
        }

        const statusUpdatePromises = pendingClips.map(clip => 
            apiCall(`/api/clip/${clip.id}/status`, 'GET', null, token)
        );

        await Promise.all(statusUpdatePromises);

        const updatedData = await apiCall(`/api/download/${downloadId}/details`, "GET", null, token);
        if (updatedData && updatedData.clips) {
            renderClips(updatedData.clips, token);
        }

    } catch(err) {
        console.error("Stopping refresh due to error:", err.message);
    }
}


/**
 * Renders clips into separate pending and completed lists.
 */
function renderClips(clips, token) {
    const pendingList = document.getElementById("pending-list");
    const completedList = document.getElementById("completed-list");
    pendingList.innerHTML = "";
    completedList.innerHTML = "";

    const pendingClips = clips.filter(c => c.status === 'PENDING' || c.status === 'PROCESSING');
    const completedClips = clips.filter(c => c.status === 'SUCCESS' || c.status === 'FAILURE');

    if (pendingClips.length === 0) {
        pendingList.innerHTML = '<li class="muted">No pending clips.</li>';
    } else {
        for (const clip of pendingClips) {
            const li = document.createElement("li");
            li.className = "list-item";
            const statusText = clip.status.charAt(0).toUpperCase() + clip.status.slice(1).toLowerCase();
            li.innerHTML = `
                <div class="list-item-content">
                    <span class="list-item-title">${clip.title}</span>
                    <span style="font-weight: 600; color: #d29922;">${statusText}...</span>
                </div>`;
            pendingList.appendChild(li);
        }
    }

    if (completedClips.length === 0) {
        completedList.innerHTML = '<li class="muted">No completed clips.</li>';
    } else {
        for (const clip of completedClips) {
            const li = document.createElement("li");
            li.className = "list-item";
            const isSuccess = clip.status === 'SUCCESS';
            const statusColor = isSuccess ? '#388bfd' : '#f85149';
            const statusText = isSuccess ? 'Completed' : 'Failed';

            let content = `
                <div class="list-item-content">
                    <div class="list-item-title-container">
                        <span class="list-item-title">${clip.title}</span>
                        <span class="list-item-size">(${prettySize(clip.size_bytes)})</span>
                    </div>
                    <div class="list-item-buttons">
                        <span style="font-weight: 600; color: ${statusColor};">${statusText}</span>
            `;
            if (isSuccess) {
                content += `<a href="#" onclick="downloadClip(${clip.id}, '${clip.title}', '${token}'); return false;" class="btn small" style="margin-left: 1rem;">Download</a>`;
            }
            content += `</div></div>`;
            li.innerHTML = content;
            completedList.appendChild(li);
        }
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