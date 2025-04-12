# Log File Analyzer Web UI

A web-based tool built with Python and Streamlit to help engineers analyze application log files quickly and efficiently.

## Description

This application provides a user-friendly web interface for parsing log files. Instead of manually searching through large files or using complex command-line tools, users can upload their logs, specify analysis parameters, and view a summarized report directly in their browser.

## Features

* **File Upload:** Upload one or more log files (`.log`, `.txt`, or any text-based format).
* **Log Level Counting:** Select specific log levels (e.g., ERROR, WARN, INFO) to count their occurrences.
* **Custom Pattern Search:** Define custom regular expression (regex) patterns to search for specific events or messages within the logs.
* **Error Summary:** Automatically identifies and counts common error messages.
* **Aggregated Reports:** Generates a summary report including:
  * Total lines processed per file and overall.
  * Counts for selected log levels.
  * Counts for matched custom patterns.
  * Top error messages found.
* **Download Report:** Download the generated analysis report as a text file.

## Requirements

* Python 3.7+
* Packages listed in `requirements.txt` (primarily Streamlit).

## Installation

1. **Clone the repository or download the files:**

   ```bash
   # If using git
   git clone <repository_url>
   cd <repository_directory>

   # Or simply download log_analyzer_app.py and requirements.txt
   ```
2. **Create and activate a virtual environment (Recommended):**

   ```bash
   python -m venv venv
   # On Windows
   venv\Scripts\activate
   # On macOS/Linux
   source venv/bin/activate
   ```
3. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. **Run the Streamlit application:**

   ```bash
   streamlit run log_analyzer_app.py
   ```

   This will start the web server and should automatically open the application in your default web browser. If not, navigate to the local URL provided in the terminal (usually `http://localhost:8501`).
2. **Use the Web Interface:**

   * Use the sidebar to upload one or more log files.
   * Select the log levels you want to count (e.g., ERROR, WARN).
   * Enter any custom regex patterns (one per line) you want to search for.
   * Click the "Analyze Logs" button.
   * View the generated report in the main area.
   * Use the "Download Report" button to save the report locally.

## Contributing

Contributions are welcome! Please feel free to submit bug reports, feature requests, or pull requests.
