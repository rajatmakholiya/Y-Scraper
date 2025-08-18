// code/frontend/clip.js
const BASE_URL = "http://127.0.0.1:5000";

// ========== State for the new Marker UI ==========
let isMarking = false;
let markInTime = null;
let markedClips = [];

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

/**
 * Formats seconds into HH:MM:SS string.
 */
function formatTime(totalSeconds) {
    const hours = Math.floor(totalSeconds / 3600).toString().padStart(2, '0');
    const minutes = Math.floor((totalSeconds % 3600) / 60).toString().padStart(2, '0');
    const seconds = Math.floor(totalSeconds % 60).toString().padStart(2, '0');
    return `${hours}:${minutes}:${seconds}`;
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
    const videoPlayer = document.getElementById("video-player");
    const videoTitle = document.getElementById("video-title");
    const createClipButton = document.getElementById("btn-create-clip");
    const clearQueueButton = document.getElementById("btn-clear-queue");
    // Marker UI elements
    const showMarkerButton = document.getElementById("btn-show-marker");
    const markerBar = document.getElementById("marker-bar");
    const markInOutButton = document.getElementById("btn-mark-in-out");
    const queueAllButton = document.getElementById("btn-queue-all");


    try {
        const data = await apiCall(`/api/download/${downloadId}/details`, "GET", null, token);
        videoTitle.textContent = data.title;
        
        await loadVideoPlayer(token, downloadId);
        
        renderClips(data.clips, token);

        // Event listeners for manual creation
        createClipButton.addEventListener("click", () => createClip(token, downloadId));
        clearQueueButton.addEventListener("click", () => clearQueue(token, downloadId));

        // Event listeners for interactive marking
        showMarkerButton.addEventListener("click", () => {
            const isHidden = markerBar.style.display === 'none';
            markerBar.style.display = isHidden ? 'flex' : 'none';
            showMarkerButton.textContent = isHidden ? 'Close Marker' : 'Mark Clips';
        });
        markInOutButton.addEventListener("click", handleMarkInOut);
        queueAllButton.addEventListener("click", () => queueAllMarkedClips(token, downloadId));

        videoPlayer.addEventListener('timeupdate', updateProgressBar);

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

// ========== NEW: Spinner and Loading State Functions ==========
function showSpinner(show) {
    const spinner = document.getElementById('queue-spinner');
    spinner.style.display = show ? 'block' : 'none';
}

// ========== Interactive Marker Functions ==========

function updateProgressBar() {
    const videoPlayer = document.getElementById("video-player");
    const barFill = document.getElementById("progress-bar-fill");
    if (videoPlayer.duration) {
        const percentage = (videoPlayer.currentTime / videoPlayer.duration) * 100;
        barFill.style.width = `${percentage}%`;
    }
}

function addMarkerOnBar(time, type) {
    const videoPlayer = document.getElementById("video-player");
    const barContainer = document.getElementById("progress-bar-container");
    if (!videoPlayer.duration) return;

    const percentage = (time / videoPlayer.duration) * 100;
    const marker = document.createElement('div');
    marker.className = `progress-marker marker-${type}`;
    marker.style.left = `${percentage}%`;
    marker.dataset.markerType = type; 
    barContainer.appendChild(marker);
}

function clearMarkersOnBar() {
    const barContainer = document.getElementById("progress-bar-container");
    const markers = barContainer.querySelectorAll('.progress-marker');
    markers.forEach(marker => marker.remove());
}


function handleMarkInOut() {
    const videoPlayer = document.getElementById("video-player");
    const markInOutButton = document.getElementById("btn-mark-in-out");
    const feedbackDiv = document.getElementById("marker-feedback");
    const currentTime = videoPlayer.currentTime;

    if (!isMarking) {
        clearMarkersOnBar();
        markInTime = currentTime;
        isMarking = true;
        markInOutButton.textContent = "Mark Out";
        feedbackDiv.textContent = `Marked In at: ${formatTime(markInTime)}`;
        addMarkerOnBar(markInTime, 'in');
    } else {
        if (currentTime <= markInTime) {
            feedbackDiv.textContent = "Error: Mark Out time must be after Mark In time.";
            return;
        }
        
        addMarkerOnBar(currentTime, 'out');
        markedClips.push({ start: formatTime(markInTime), end: formatTime(currentTime) });
        
        isMarking = false;
        markInTime = null;
        markInOutButton.textContent = "Mark In";
        feedbackDiv.textContent = `Clip added: ${markedClips[markedClips.length-1].start} - ${markedClips[markedClips.length-1].end}`;
        
        renderMarkedClips();
    }
}

function renderMarkedClips() {
    const list = document.getElementById("marked-clips-list");
    const queueAllButton = document.getElementById("btn-queue-all");
    list.innerHTML = "";

    if (markedClips.length === 0) {
        list.innerHTML = '<li class="muted">No clips marked yet.</li>';
        queueAllButton.disabled = true;
        return;
    }

    markedClips.forEach((clip, index) => {
        const li = document.createElement("li");
        li.className = "list-item";
        li.innerHTML = `
            <div class="list-item-content">
                <span class="list-item-title">Clip: ${clip.start} - ${clip.end}</span>
                <button class="btn-remove-marked" onclick="removeMarkedClip(${index})">&times;</button>
            </div>
        `;
        list.appendChild(li);
    });
    
    queueAllButton.disabled = false;
}

function removeMarkedClip(index) {
    markedClips.splice(index, 1);
    renderMarkedClips();
}

async function queueAllMarkedClips(token, downloadId) {
    if (markedClips.length === 0) return;

    showSpinner(true);
    const queuePromises = markedClips.map(clip => 
        apiCall("/api/clip", "POST", {
            download_id: downloadId,
            start_time: clip.start,
            end_time: clip.end,
        }, token)
    );

    try {
        await Promise.all(queuePromises);
        markedClips = [];
        renderMarkedClips();
        clearMarkersOnBar();
        document.getElementById("marker-feedback").textContent = "All marked clips have been queued!";
        await refreshClips(token, downloadId);
    } catch (err) {
        alert("Failed to queue all clips: " + err.message);
    } finally {
        showSpinner(false);
    }
}


// ========== Existing Clip Queue Functions ==========

/**
 * MODIFIED: Provides immediate feedback by manually adding a "Queued" item.
 */
async function createClip(token, downloadId) {
    const startTimeInput = document.getElementById("start-time");
    const endTimeInput = document.getElementById("end-time");
    const errorDiv = document.getElementById("clip-error");
    errorDiv.textContent = "";

    const startTime = startTimeInput.value;
    const endTime = endTimeInput.value;

    if (!startTime || !endTime) {
        errorDiv.textContent = "Please provide both a start and end time.";
        return;
    }

    // --- Immediate UI Update ---
    // 1. Create a fake clip object to show in the UI right away.
    const tempClip = { 
        title: `Clip from ${startTime} to ${endTime}`, 
        status: 'QUEUED' // A temporary status
    };
    // 2. Add it to the pending list.
    const pendingList = document.getElementById("pending-list");
    if (pendingList.querySelector('.muted')) {
        pendingList.innerHTML = ''; // Clear "No pending clips" message
    }
    const li = document.createElement("li");
    li.className = "list-item";
    li.innerHTML = `
        <div class="list-item-content">
            <span class="list-item-title">${tempClip.title}</span>
            <span style="font-weight: 600; color: #d29922;">Queued...</span>
        </div>`;
    pendingList.appendChild(li);
    // --- End of Immediate Update ---


    try {
        await apiCall("/api/clip", "POST", {
            download_id: downloadId,
            start_time: startTime,
            end_time: endTime,
        }, token);
        
        startTimeInput.value = "";
        endTimeInput.value = "";
        
        // The regular refresh will eventually replace the fake item with the real one.
        await refreshClips(token, downloadId);

    } catch (err) {
        errorDiv.textContent = "Error: " + err.message;
        // If there was an error, refresh to remove the fake item.
        await refreshClips(token, downloadId);
    }
}

async function clearQueue(token, downloadId) {
    if (!confirm("Are you sure you want to delete all clips and cancel any pending jobs? This cannot be undone.")) {
        return;
    }
    showSpinner(true);
    try {
        await apiCall(`/api/download/${downloadId}/clips`, 'DELETE', null, token);
        await refreshClips(token, downloadId);
    } catch (err) {
        alert("Failed to clear queue: " + err.message);
    } finally {
        showSpinner(false);
    }
}


async function refreshClips(token, downloadId) {
    try {
        const data = await apiCall(`/api/download/${downloadId}/details`, "GET", null, token);
        if (!data || !data.clips) {
            renderClips([], token);
            return;
        }

        const pendingClips = data.clips.filter(c => c.status === 'PENDING' || c.status === 'PROCESSING');
        
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