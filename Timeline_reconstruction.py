import os
import pytsk3
import sqlite3
import pandas as pd
from datetime import datetime, timedelta
from jinja2 import Environment, FileSystemLoader
import matplotlib.pyplot as plt

# ===========================================================
# CONFIGURATION (Change these paths as per your system)
# ===========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
TIMELINE_REPORT_FILE = os.path.join(BASE_DIR, "timeline_report.html")
TIMELINE_CSV_FILE = os.path.join(BASE_DIR, "timeline_output.csv")

# ===========================================================
# STEP 1: EXTRACT FILE METADATA USING pytsk3 (SleuthKit)
# ===========================================================

def extract_file_metadata(image_file, offset):
    print("[INFO] Extracting file metadata...")
    img = pytsk3.Img_Info(image_file)
    fs = pytsk3.FS_Info(img, offset=offset * 512)
    file_events = []

    try:
        directory = fs.open_dir(path="/")
        for f in directory:
            if f.info.meta:
                file_name = f.info.name.name.decode("utf-8", errors="ignore")
                mtime = f.info.meta.mtime
                if mtime:
                    timestamp = datetime.fromtimestamp(mtime)
                    event = {
                        "timestamp": timestamp,
                        "event_type": "File Access",
                        "details": file_name
                    }
                    file_events.append(event)

        with open("file_metadata.txt", "w", encoding="utf-8") as f:
            for event in file_events:
                f.write(f"{event['timestamp']}, {event['event_type']}, {event['details']}\n")

        print(f"[INFO] File metadata extraction complete! {len(file_events)} events found.")

    except Exception as e:
        print(f"[ERROR] File metadata extraction failed: {e}")

    return file_events


# ===========================================================
# STEP 2: PARSE BROWSER HISTORY (SQLite)
# ===========================================================

def parse_browser_history(db_path):
    print("[INFO] Parsing browser history...")
    history_events = []

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT url, title, last_visit_time FROM urls")
        rows = cursor.fetchall()

        for row in rows:
            last_visit_time = row[2]
            if last_visit_time:
                # Convert from microseconds since 1601-01-01
                timestamp = datetime(1601, 1, 1) + timedelta(seconds=last_visit_time / 1_000_000)
                formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                event = {
                    "timestamp": formatted_time,
                    "event_type": "Browser Visit",
                    "details": f"Visited {row[1]} ({row[0]})"
                }
                history_events.append(event)

        with open("browser_history.txt", "w", encoding="utf-8") as f:
            for event in history_events:
                f.write(f"{event['timestamp']}, {event['event_type']}, {event['details']}\n")

        print(f"[INFO] Browser history parsed successfully! {len(history_events)} entries found.")

    except sqlite3.Error as e:
        print(f"[ERROR] SQLite error: {e}")

    finally:
        if 'conn' in locals():
            conn.close()

    return history_events


# ===========================================================
# STEP 3: EXTRACT WINDOWS EVENT LOGS
# ===========================================================

def extract_event_logs(log_type="Security"):
    print("[INFO] Extracting Windows event logs...")
    log_events = []

    try:
        import win32evtlog  # Only available on Windows
        handle = win32evtlog.OpenEventLog("localhost", log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(handle, flags, 0)

        for event in events:
            timestamp = event.TimeGenerated.Format()
            event_id = event.EventID
            log_events.append({
                "timestamp": timestamp,
                "event_type": "System Event",
                "details": f"Event ID {event_id}"
            })

        with open("memory_analysis.txt", "w", encoding="utf-8") as f:
            for event in log_events:
                f.write(f"{event['timestamp']}, {event['event_type']}, {event['details']}\n")

        print(f"[INFO] Extracted {len(log_events)} system events.")

    except ImportError:
        print("[WARNING] pywin32 is not available (likely not Windows). Skipping event logs.")
    except Exception as e:
        print(f"[ERROR] Could not read event logs: {e}")

    return log_events


# ===========================================================
# STEP 4: CREATE TIMELINE AND SAVE TO CSV
# ===========================================================

def create_timeline(event_data):
    print("[INFO] Creating timeline...")
    df = pd.DataFrame(event_data)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df.dropna(subset=["timestamp"], inplace=True)
    df.sort_values("timestamp", inplace=True)
    df.to_csv(TIMELINE_CSV_FILE, index=False)
    print(f"[INFO] Timeline saved to {TIMELINE_CSV_FILE}")
    return df


# ===========================================================
# STEP 5: GENERATE HTML TIMELINE REPORT
# ===========================================================

def generate_timeline_report(timeline_df):
    print("[INFO] Generating HTML timeline report...")
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("timeline_template.html")

    output = template.render(timeline_data=timeline_df.to_dict("records"))

    with open(TIMELINE_REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(output)

    print(f"[INFO] Timeline report generated successfully: {TIMELINE_REPORT_FILE}")


# ===========================================================
# STEP 6: VISUALIZE TIMELINE DATA
# ===========================================================

def visualize_timeline(df):
    print("[INFO] Visualizing timeline data...")
    df["event_type"].value_counts().plot(kind="bar")
    plt.title("Timeline Event Summary")
    plt.xlabel("Event Type")
    plt.ylabel("Count")
    plt.show()
    print("[INFO] Data visualization complete!")


# ===========================================================
# MAIN PIPELINE
# ===========================================================

def main_timeline_pipeline(disk_image, browser_db):
    print("[INFO] Starting timeline reconstruction pipeline...")

    file_metadata_events = extract_file_metadata(disk_image, 8192)
    browser_history_events = parse_browser_history(browser_db)
    log_events = extract_event_logs()

    all_events = file_metadata_events + browser_history_events + log_events
    timeline_df = create_timeline(all_events)
    generate_timeline_report(timeline_df)
    visualize_timeline(timeline_df)

    print("[INFO] Timeline reconstruction pipeline complete!")


# ===========================================================
# ENTRY POINT
# ===========================================================

if __name__ == "__main__":
    # ---- CHANGE THESE PATHS TO YOUR LOCAL FILES ----
    DISK_IMAGE_PATH = "/content/df-timeline/datasets/disk_img.img"
    BROWSER_HISTORY_DB = "/content/df-timeline/datasets/History.db"
    # ------------------------------------------------

    main_timeline_pipeline(DISK_IMAGE_PATH, BROWSER_HISTORY_DB)


