import pytsk3
import sqlite3
import pandas as pd
from datetime import datetime, timedelta
from jinja2 import Environment, FileSystemLoader
import matplotlib.pyplot as plt

# Directories
TEMPLATE_DIR = 'C:/Users/karan/OneDrive/Desktop/Cyber_techniques Project/templates'
TIMELINE_REPORT_FILE = 'timeline_report.html'
TIMELINE_CSV_FILE = 'timeline_output.csv'


# Step 1: Extract File Metadata using pytsk3 (SleuthKit)
def extract_file_metadata(image_file,offset):
    print("[INFO] Extracting file metadata...")
    img = pytsk3.Img_Info(image_file)
    fs = pytsk3.FS_Info(img, offset=offset * 512)
    file_events = []

    for f in fs.open_dir(path='/'):
        if f.info.meta:
            timestamp = datetime.fromtimestamp(f.info.meta.mtime)
            file_name = f.info.name.name.decode('utf-8')
            event = {"timestamp": timestamp, "event_type": "File Access", "details": file_name}
            file_events.append(event)

    with open('file_metadata.txt', 'w',encoding='utf-8') as f:
        for event in file_events:
            f.write(f"{event['timestamp']}, {event['event_type']}, {event['details']}\n")

    print("[INFO] File metadata extraction complete!")
    return file_events


# Step 2: Parse Browser History (SQLite)

def parse_browser_history(db_path):
    print("[INFO] Parsing browser history...")
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Make sure this table name matches your database schema
        cursor.execute("SELECT url, title, last_visit_time FROM urls")  
        history_events = []

        for row in cursor.fetchall():
            # Convert last_visit_time from microseconds to seconds
            # The timestamp is in microseconds since 1601-01-01
            last_visit_time_microseconds = row[2]

            if last_visit_time_microseconds:
                timestamp_seconds = last_visit_time_microseconds / 1_000_000  # Convert microseconds to seconds
                epoch = datetime(1601, 1, 1)  # Windows epoch
                timestamp = epoch + timedelta(seconds=timestamp_seconds)  # Calculate the actual timestamp
                
                # Format the datetime object to 'YYYY-MM-DD HH:MM:SS'
                formatted_timestamp = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                
                event = {
                    "timestamp": formatted_timestamp,  # Use the formatted timestamp
                    "event_type": "Browser Visit",
                    "details": f"Visited {row[1]} ({row[0]})"
                }
                history_events.append(event)
            else:
                print("[WARNING] Found a null last_visit_time, skipping this entry.")

        # Writing output to a text file with UTF-8 encoding
        with open('browser_history.txt', 'w', encoding='utf-8') as f:
            for event in history_events:
                f.write(f"{event['timestamp']}, {event['event_type']}, {event['details']}\n")

        print("[INFO] Browser history parsing complete!")
    except sqlite3.Error as e:
        print(f"[ERROR] SQLite error: {e}")
        return []
    finally:
        conn.close()  # Ensure the connection is closed

    return history_events



# Step 3: Extract Windows Event Logs (Security Logs)
def extract_event_logs(log_type='Security'):
    print("[INFO] Extracting Windows event logs...")
    import win32evtlog

    handle = win32evtlog.OpenEventLog('localhost', log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = win32evtlog.ReadEventLog(handle, flags, 0)
    log_events = []

    for event in events:
        timestamp = event.TimeGenerated.Format()  # This should be properly formatted if needed
        event_id = event.EventID
        event_description = f"Event ID {event_id}"
        log_events.append({"timestamp": timestamp, "event_type": "System Event", "details": event_description})

    with open('memory_analysis.txt', 'w',encoding='utf-8') as f:
        for event in log_events:
            f.write(f"{event['timestamp']}, {event['event_type']}, {event['details']}\n")

    print("[INFO] Windows event log extraction complete!")
    return log_events


# Step 4: Create Timeline and Save to CSV
def create_timeline(event_data):
    print("[INFO] Creating timeline...")
    df = pd.DataFrame(event_data)

    # Convert timestamp to datetime, handle errors if necessary
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

    # Drop rows where timestamp conversion failed
    df.dropna(subset=['timestamp'], inplace=True)

    # Sort the DataFrame by timestamp
    df.sort_values('timestamp', inplace=True)

    # Save to CSV
    df.to_csv(TIMELINE_CSV_FILE, index=False)
    print(f"[INFO] Timeline saved to {TIMELINE_CSV_FILE}")
    return df



# Step 5: Generate HTML Timeline Report
def generate_timeline_report(timeline_df):
    print("[INFO] Generating HTML timeline report...")

    # Load the Jinja2 template
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template('timeline_template.html')

    # Render the HTML report
    output = template.render(timeline_data=timeline_df.to_dict('records'))

    # Save the report to an HTML file
    with open(TIMELINE_REPORT_FILE, 'w',encoding='utf-8') as f:
        f.write(output)
    print(f"[INFO] Timeline report generated: {TIMELINE_REPORT_FILE}")


# Step 6: Visualize Timeline Data
def visualize_timeline(df):
    print("[INFO] Visualizing timeline data...")
    df['event_type'].value_counts().plot(kind='bar')
    plt.title("Timeline Event Summary")
    plt.xlabel("Event Type")
    plt.ylabel("Count")
    plt.show()
    print("[INFO] Data visualization complete!")


# Main pipeline function to execute all steps
def main_timeline_pipeline(disk_image, browser_db):
    print("[INFO] Starting timeline reconstruction pipeline...")

    # Step 1: Extract file metadata
    file_metadata_events = extract_file_metadata(disk_image,8192)

    # Step 2: Parse browser history
    browser_history_events = parse_browser_history(browser_db)

    # Step 3: Extract Windows event logs (or any other system logs)
    log_events = extract_event_logs()

    # Step 4: Combine all events into a single timeline
    all_events = file_metadata_events + browser_history_events + log_events
    timeline_df = create_timeline(all_events)

    # Step 5: Generate HTML timeline report
    generate_timeline_report(timeline_df)

    # Step 6: Visualize timeline events
    visualize_timeline(timeline_df)


if __name__ == "__main__":
    # Example file paths (update with your own file paths)
    DISK_IMAGE_PATH = "C:/Users/karan/OneDrive/Desktop/Cyber_techniques Project/datasets/disk_img.img"
    BROWSER_HISTORY_DB = "C:/Users/karan/OneDrive/Desktop/Cyber_techniques Project/datasets/History.db"  # Example browser history SQLite database

    # Run the full pipeline
    main_timeline_pipeline(DISK_IMAGE_PATH, BROWSER_HISTORY_DB)
