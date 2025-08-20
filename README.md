# Y-Scraper - Video Downloader

Welcome to Y-Scraper, a web application for downloading and clipping videos.

## How to Use

Follow these simple steps to get the application up and running on your computer.

### Prerequisites

1.  **Python**: Make sure you have Python installed. If not, download it from the [official Python website](https://www.python.org/downloads/). During installation, be sure to check the box that says "Add Python to PATH".
2.  **FFmpeg**: This tool is required for clipping videos.
    * Download it from the [official FFmpeg website](https://ffmpeg.org/download.html).
    * Follow a guide to install it and add it to your system's PATH.

> **Note**: This application uses vanilla HTML, CSS, and JavaScript for the frontend. You **do not** need to install Node.js or use `npm`.

### Step 1: Configure the Application

Before running the app, you need to set up your configuration.

1.  In the `backend` folder, find the file named `.env.example`.
2.  Make a copy of this file and rename the copy to `.env`.
3.  Open the new `.env` file in a text editor (like Notepad).
4.  You **must** fill in the `SECRET_KEY` and `JWT_SECRET_KEY` with random, secret text.
5.  To enable Google Login, you will need to get a `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` from the [Google Cloud Console](https://console.cloud.google.com/) and add them to the file.

### Step 2: Install Dependencies

Now, you need to install the required Python packages for the backend.

1.  Double-click on the `install_dependencies.bat` file.
2.  A command prompt window will open and install everything needed.
3.  Once finished, press any key to close the window.

### Step 3: Run the Application

You are now ready to run the application.

1.  Double-click on the `run_app.bat` file.
2.  Two new command prompt windows will open: one for the "Backend Server" and one for the "Frontend Server".
3.  **Do not close these windows**, as they are required for the application to function correctly.

### Step 4: Access the Web App

1.  Open your web browser (e.g., Chrome, Firefox, or Edge).
2.  Go to the following address: [http://localhost:8000](http://localhost:8000)
3.  You should now see the Y-Scraper login page.

Enjoy using the application!