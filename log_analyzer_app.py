"""
Project: Log File Analyzer Web UI
Language: Python with Streamlit
Description: A web-based UI for the Log File Analyzer tool. Allows users to
             upload log files, specify patterns and levels, and view the
             analysis report in the browser.
"""

import streamlit as st
import re
from collections import Counter
import os
import tempfile # To handle uploaded files

# --- Core Log Analysis Logic (adapted from the previous CLI version) ---

def analyze_log_file(file_path, custom_patterns=None, levels_to_count=None):
    """
    Analyzes a single log file. (Slightly adapted for broader compatibility)

    Args:
        file_path (str): The path to the log file.
        custom_patterns (list, optional): List of custom regex patterns to search for. Defaults to None.
        levels_to_count (list, optional): List of log levels (e.g., 'ERROR') to count. Defaults to None.

    Returns:
        dict: A dictionary containing analysis results (line count, error count, etc.)
              Returns None if the file cannot be processed.
    """
    # Ensure levels_to_count contains uppercase strings if provided
    if levels_to_count:
        levels_to_count = [level.upper() for level in levels_to_count]

    if not os.path.exists(file_path):
        st.error(f"Error: File not found during analysis - {file_path}") # Use st.error for UI feedback
        return None

    results = {
        'file_path': file_path, # Store original name if possible, or temp path
        'total_lines': 0,
        'level_counts': Counter(),
        'custom_pattern_counts': Counter({pattern: 0 for pattern in custom_patterns or []}),
        'errors_summary': Counter() # To store counts of specific error messages
    }

    # Basic regex to capture common log formats (adapt if needed)
    # Example format: 2023-10-27 10:00:00,123 - LEVEL - Message
    # Making it slightly more flexible for different separators and optional milliseconds
    log_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{3,6})?\s*[-:]?\s*(\w+)\s*[-:]?\s+(.*)")
    error_pattern = re.compile(r"error", re.IGNORECASE) # General error keyword search

    processed_levels_on_line = set() # Track levels found on the current line

    try:
        # Use 'ignore' for errors to handle potential encoding issues in log files
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                results['total_lines'] += 1
                line = line.strip()
                if not line:
                    continue

                processed_levels_on_line.clear() # Reset for the new line
                line_matched_level = False

                # 1. Check against the structured log pattern first
                match = log_pattern.match(line)
                if match:
                    level = match.group(1).upper()
                    message = match.group(2)
                    if levels_to_count and level in levels_to_count:
                        results['level_counts'][level] += 1
                        processed_levels_on_line.add(level)
                        line_matched_level = True
                    if level == 'ERROR':
                        error_key = message.split('.')[0].split(':')[0].strip()[:100] # Limit key length
                        results['errors_summary'][error_key] += 1
                        if 'ERROR' not in processed_levels_on_line and levels_to_count and 'ERROR' in levels_to_count:
                             results['level_counts']['ERROR'] += 1 # Ensure counted if specified
                             processed_levels_on_line.add('ERROR')


                # 2. Fallback: If no structured match, check for level keywords directly
                #    Only count if levels_to_count is specified
                if not line_matched_level and levels_to_count:
                    for level_keyword in levels_to_count:
                        # Use word boundaries to avoid matching substrings (e.g., "INFORMATION" for "INFO")
                        if re.search(r'\b' + re.escape(level_keyword) + r'\b', line, re.IGNORECASE):
                             # Check if this level was already counted via structured parse (unlikely here, but safe)
                             if level_keyword not in processed_levels_on_line:
                                results['level_counts'][level_keyword] += 1
                                processed_levels_on_line.add(level_keyword)
                                line_matched_level = True
                                # Capture error summary if it's an ERROR level keyword match
                                if level_keyword == 'ERROR':
                                    error_key = line.split('.')[0].split(':')[0].strip()[:100] # Basic summary
                                    results['errors_summary'][error_key] += 1
                                # Optimization: If we only care about specific levels,
                                # and found one, maybe break if only one level per line expected.
                                # For now, continue checking in case multiple keywords are present.


                # 3. Search for custom patterns (independent of level counting)
                if custom_patterns:
                    for pattern in custom_patterns:
                         try:
                            # Use re.IGNORECASE for case-insensitivity
                            if re.search(pattern, line, re.IGNORECASE):
                                results['custom_pattern_counts'][pattern] += 1
                         except re.error as re_err:
                             # Show regex error in UI only once per pattern
                             if f"regex_error_{pattern}" not in st.session_state:
                                 st.warning(f"Invalid regex pattern '{pattern}': {re_err}. Skipping this pattern.")
                                 st.session_state[f"regex_error_{pattern}"] = True # Mark as warned


                # 4. General Error Keyword Search (Only if ERROR level wasn't explicitly requested/counted)
                #    This catches lines containing "error" that might not fit the format or level list.
                if error_pattern.search(line):
                    is_error_level_requested = levels_to_count and 'ERROR' in levels_to_count
                    # Count as general error if ERROR wasn't requested OR if it was requested but not found yet on this line
                    if not is_error_level_requested or 'ERROR' not in processed_levels_on_line:
                         results['level_counts']['ERROR'] += 1 # Increment general error count if not already counted
                         processed_levels_on_line.add('ERROR') # Mark as counted
                         # Also add to summary if not already added by structured match
                         if not match or match.group(1).upper() != 'ERROR':
                              error_key = line.split('.')[0].split(':')[0].strip()[:100] # Basic summary
                              results['errors_summary'][error_key] += 1


    except Exception as e:
        st.error(f"Error processing file {file_path}: {e}")
        return None

    return results

def generate_report(analysis_results_list):
    """
    Generates a formatted report string from the analysis results.
    (Identical to the CLI version's report generation)

    Args:
        analysis_results_list (list): A list of dictionaries, where each dictionary
                                     is the result from analyze_log_file.

    Returns:
        str: A formatted report string.
    """
    report = "--- Log Analysis Report ---\n\n"

    total_lines_all_files = 0
    aggregated_level_counts = Counter()
    aggregated_custom_counts = Counter()
    aggregated_errors_summary = Counter()

    # Filter out None results in case of file processing errors
    valid_results = [res for res in analysis_results_list if res is not None]

    if not valid_results:
        return "No log files were successfully analyzed."

    for results in valid_results:
        # Use the original uploaded file name if available in results, else use the path
        file_identifier = results.get('original_file_name', results['file_path'])
        report += f"File: {file_identifier}\n"
        report += f"  Total Lines Processed: {results['total_lines']}\n"
        total_lines_all_files += results['total_lines']

        if results['level_counts']:
            report += "  Log Level Counts:\n"
            # Sort levels for consistent reporting order
            for level, count in sorted(results['level_counts'].items()):
                report += f"    - {level}: {count}\n"
                aggregated_level_counts[level] += count

        if results['custom_pattern_counts']:
             report += "  Custom Pattern Counts:\n"
             # Sort patterns for consistent reporting order
             for pattern, count in sorted(results['custom_pattern_counts'].items()):
                 if count > 0: # Only report patterns that were found
                     report += f"    - '{pattern}': {count}\n"
                     aggregated_custom_counts[pattern] += count

        if results['errors_summary']:
            report += f"  Specific Error Message Counts (Top {min(5, len(results['errors_summary']))}):\n"
            for error_msg, count in results['errors_summary'].most_common(5):
                 report += f"    - \"{error_msg}\": {count}\n"
                 aggregated_errors_summary[error_msg] += count # Aggregate all specific errors found

        report += "-" * 30 + "\n\n"

    # Aggregated Summary
    report += "--- Aggregated Summary ---\n"
    report += f"Total Files Analyzed: {len(valid_results)}\n"
    report += f"Total Lines Across All Files: {total_lines_all_files}\n"

    if aggregated_level_counts:
        report += "Total Log Level Counts:\n"
        for level, count in sorted(aggregated_level_counts.items()):
            report += f"  - {level}: {count}\n"

    if aggregated_custom_counts:
        report += "Total Custom Pattern Counts:\n"
        for pattern, count in sorted(aggregated_custom_counts.items()):
             report += f"  - '{pattern}': {count}\n"

    if aggregated_errors_summary:
        report += f"Overall Specific Error Message Counts (Top {min(10, len(aggregated_errors_summary))}):\n"
        for error_msg, count in aggregated_errors_summary.most_common(10):
            report += f"  - \"{error_msg}\": {count}\n"

    report += "--- End of Report ---\n"
    return report

# --- Streamlit UI ---

def run_streamlit_app():
    """Sets up and runs the Streamlit web interface."""
    st.set_page_config(page_title="Log Analyzer", layout="wide")
    st.title("📄 Log File Analyzer")
    st.write("Upload log files, specify patterns/levels, and get an analysis report.")

    # Initialize session state for report
    if 'report' not in st.session_state:
        st.session_state.report = ""
    if 'analyzed_files_count' not in st.session_state:
        st.session_state.analyzed_files_count = 0


    # --- Input Area ---
    with st.sidebar:
        st.header("Configuration")

        # File Uploader
        uploaded_files = st.file_uploader(
            "Choose log files",
            accept_multiple_files=True,
            # FIX: Removed None from the type list
            type=['log', 'txt']
        )

        # Log Levels Selection
        available_levels = ['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL']
        levels_to_count = st.multiselect(
            "Select log levels to count:",
            options=available_levels,
            # default=['ERROR', 'WARN'] # Optional default selection
        )

        # Custom Patterns Input
        st.write("Enter custom regex patterns (one per line):")
        custom_patterns_input = st.text_area(
            "Custom Patterns",
            height=100,
            placeholder="e.g.,\nException:.*\nTimeout waiting for response\nUser.*logged out"
        )
        # Split patterns by newline and remove empty lines
        custom_patterns = [p.strip() for p in custom_patterns_input.split('\n') if p.strip()]

        # Analyze Button
        analyze_button = st.button("Analyze Logs", type="primary", disabled=(not uploaded_files))

    # --- Analysis and Report Display Area ---
    st.header("Analysis Report")

    if analyze_button and uploaded_files:
        all_results = []
        # Use a temporary directory context manager for cleaner handling
        with tempfile.TemporaryDirectory() as temp_dir:
            file_details = [] # Store tuples of (temp_path, original_name)

            try:
                # Save uploaded files temporarily
                for uploaded_file in uploaded_files:
                    # Sanitize filename slightly to avoid issues, though tempfile handles uniqueness
                    safe_filename = os.path.basename(uploaded_file.name)
                    temp_file_path = os.path.join(temp_dir, safe_filename)
                    with open(temp_file_path, "wb") as f:
                        f.write(uploaded_file.getbuffer())
                    file_details.append({'path': temp_file_path, 'name': uploaded_file.name})

                # Analyze each saved file
                with st.spinner(f"Analyzing {len(file_details)} file(s)..."):
                    for file_info in file_details:
                        st.write(f"Processing: {file_info['name']}...") # Show progress
                        # Pass original name for better reporting
                        analysis_result = analyze_log_file(
                            file_info['path'],
                            custom_patterns,
                            levels_to_count
                        )
                        if analysis_result:
                             analysis_result['original_file_name'] = file_info['name'] # Add original name to results
                             all_results.append(analysis_result)

                # Generate and store the report
                st.session_state.report = generate_report(all_results)
                st.session_state.analyzed_files_count = len(all_results)


            except Exception as e:
                st.error(f"An error occurred during the analysis process: {e}")
                st.session_state.report = "Analysis failed due to an error."
                st.session_state.analyzed_files_count = 0
            # No finally needed for cleanup, TemporaryDirectory handles it

    # Display the report if available
    if st.session_state.report:
        st.success(f"Analysis complete. {st.session_state.analyzed_files_count} file(s) analyzed successfully.")
        st.text_area("Report", st.session_state.report, height=500)

        # Add a download button for the report
        st.download_button(
            label="Download Report",
            data=st.session_state.report,
            file_name="log_analysis_report.txt",
            mime="text/plain"
        )
    elif analyze_button and not uploaded_files:
         st.warning("Please upload at least one log file.")
    else:
        st.info("Upload log files and configure options in the sidebar, then click 'Analyze Logs'.")


if __name__ == "__main__":
    run_streamlit_app()
