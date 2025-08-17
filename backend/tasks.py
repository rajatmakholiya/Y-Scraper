# code/backend/tasks.py
import os
import subprocess
from celery import Celery

# Configure Celery to use environment variables for the broker and backend
celery = Celery(
    "tasks",
    broker=os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0"),
    backend=os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0"),
)

@celery.task
def create_clip(
    input_path: str, output_path: str, start_time: str, end_time: str
) -> str:
    """
    Creates a video clip using ffmpeg in a background task.
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    # Ensure the output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Construct the ffmpeg command for clipping
    # -ss: start time, -to: end time, -c copy: avoids re-encoding for speed
    cmd = [
        "ffmpeg",
        "-i",
        input_path,
        "-ss",
        start_time,
        "-to",
        end_time,
        "-c",
        "copy",
        "-y",  # Overwrite output file if it exists
        output_path,
    ]

    try:
        # Execute the command
        subprocess.run(
            cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        return output_path
    except subprocess.CalledProcessError as e:
        # If ffmpeg fails, raise a descriptive error
        error_message = e.stderr.decode("utf-8")
        raise RuntimeError(f"ffmpeg failed: {error_message}")
    except Exception as e:
        # Catch any other unexpected errors
        raise RuntimeError(f"An unexpected error occurred during clipping: {str(e)}")