import os
import subprocess
import pandas as pd
import matplotlib.pyplot as plt
import requests
import time
from jinja2 import Environment, FileSystemLoader
import pytsk3
from pytsk3 import Img_Info, FS_Info
from datetime import datetime

# ===========================================================
# CONFIGURATION (Change these paths as per your environment)
# ===========================================================

TEMPLATE_DIR = "templates"  # Folder containing report_template.html
REPORT_FILE = "forensics_report.html"  # Output HTML report

MEMORY_IMAGE_PATH = "datasets/memdump.raw"
PCAP_FILE_PATH = "datasets/traffic.pcap"
DISK_IMAGE_PATH = "datasets/disk_image.E01"
SCAN_PATH = "datasets/sample.exe"  # File to scan for malware
API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"  # Replace with your VirusTotal API key


# ===========================================================
# STEP 1: MEMORY ANALYSIS (Volatility)
# ===========================================================

def run_volatility(memory_image):
    """
    Example memory analysis function using Volatility 3.
    Modify this command as per your volatility setup.
    """
    print("[INFO] Running memory analysis using Volatility...")
    try:
        cmd = f"volatility3 -f {memory_image} windows.pslist.PsList"
        output = subprocess.check_output(cmd, shell=True).decode()
        with open("memory_analysis.txt", "w") as f:
            f.write(output)
        print("[INFO] Memory analysis complete! Saved to memory_analysis.txt")
    except Exception as e:
        print(f"[ERROR] Volatility failed: {e}")


# ===========================================================
# STEP 2: NETWORK ANALYSIS (PCAP)
# ===========================================================

def analyze_pcap(pcap_file):
    print("[INFO] Running network analysis on PCAP file...")
    try:
        cmd = f'tshark -r "{pcap_file}" -q -z "io,stat,1"'
        output = subprocess.check_output(cmd, shell=True).decode()
        with open("network_analysis.txt", "w") as f:
            f.write(output)
        print("[INFO] Network analysis complete! Saved to network_analysis.txt")
    except Exception as e:
        print(f"[ERROR] Tshark analysis failed: {e}")


# ===========================================================
# STEP 3: DISK IMAGE ANALYSIS (SleuthKit)
# ===========================================================

def analyze_disk_image(image_path, offset):
    print("[INFO] Running detailed disk image analysis...")
    try:
        img = Img_Info(image_path)
        fs = FS_Info(img, offset=offset * 512)  # Convert sector offset to bytes
        file_data = []

        def traverse_directory(directory, parent_path=""):
            for entry in directory:
                if entry.info.name.name in [b'.', b'..']:
                    continue

                file_path = f"{parent_path}/{entry.info.name.name.decode('utf-8', 'ignore')}"

                if entry.info.meta:
                    file_size = entry.info.meta.size
                    creation_time = datetime.fromtimestamp(entry.info.meta.crtime).isoformat() if entry.info.meta.crtime else "N/A"
                    modification_time = datetime.fromtimestamp(entry.info.meta.mtime).isoformat() if entry.info.meta.mtime else "N/A"
                    access_time = datetime.fromtimestamp(entry.info.meta.atime).isoformat() if entry.info.meta.atime else "N/A"

                    file_data.append({
                        "path": file_path,
                        "size": file_size,
                        "created": creation_time,
                        "modified": modification_time,
                        "accessed": access_time
                    })

                if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    sub_directory = entry.as_directory()
                    traverse_directory(sub_directory, parent_path=file_path)

        root_dir = fs.open_dir("/")
        traverse_directory(root_dir)

        with open("disk_analysis.txt", "w") as f:
            f.write("Detailed Disk Analysis Report\n")
            f.write("=" * 50 + "\n")
            f.write(f"Disk Image: {image_path}\n")
            f.write(f"Partition Offset: {offset}\n\n")
            f.write("File Metadata:\n")
            f.write("-" * 50 + "\n")

            for entry in file_data:
                f.write(f"Path: {entry['path']}\n")
                f.write(f"Size: {entry['size']} bytes\n")
                f.write(f"Created: {entry['created']}\n")
                f.write(f"Modified: {entry['modified']}\n")
                f.write(f"Accessed: {entry['accessed']}\n")
                f.write("-" * 50 + "\n")

        print("[INFO] Disk image analysis complete! Saved to disk_analysis.txt")

    except Exception as e:
        print(f"[ERROR] Disk analysis failed: {e}")


# ===========================================================
# STEP 4: MALWARE ANALYSIS (VirusTotal API)
# ===========================================================

def analyze_malware(api_key, file_path):
    print("[INFO] Running malware scan via VirusTotal API...")
    base_url = "https://www.virustotal.com/api/v3"
    headers = {"x-apikey": api_key}

    try:
        with open(file_path, "rb") as file:
            response = requests.post(f"{base_url}/files", headers=headers, files={"file": file})

        if response.status_code != 200:
            print("Failed to upload file:", response.json())
            return

        file_analysis = response.json()
        analysis_id = file_analysis['data']['id']
        print(f"File uploaded successfully. Analysis ID: {analysis_id}")

        while True:
            report_response = requests.get(f"{base_url}/analyses/{analysis_id}", headers=headers)
            report_data = report_response.json()
            status = report_data['data']['attributes']['status']
            if status == 'completed':
                print("[INFO] Malware analysis completed!")
                break
            else:
                print("[INFO] Waiting for report...")
                time.sleep(10)

        results = report_data['data']['attributes']['results']
        with open("malware_analysis.txt", "w") as report_file:
            report_file.write(f"Malware Analysis Report for {file_path}\n")
            report_file.write("=" * 60 + "\n\n")

            for engine, details in results.items():
                report_file.write(f"Engine: {engine}\n")
                report_file.write(f"Category: {details['category']}\n")
                report_file.write(f"Result: {details['result']}\n")
                report_file.write("-" * 40 + "\n")

        print("[INFO] Malware analysis complete! Saved to malware_analysis.txt")

    except Exception as e:
        print(f"[ERROR] Malware scan failed: {e}")


# ===========================================================
# STEP 5: AGGREGATE DATA
# ===========================================================

def aggregate_data():
    print("[INFO] Aggregating forensic data...")
    files = ["memory_analysis.txt", "network_analysis.txt", "disk_analysis.txt", "malware_analysis.txt"]
    sources = ["Memory", "Network", "Disk", "Malware"]

    data = []
    for src, file in zip(sources, files):
        if os.path.exists(file):
            with open(file, "r") as f:
                content = f.read()
            data.append({"source": src, "analysis": content})
        else:
            data.append({"source": src, "analysis": "No data found."})

    df = pd.DataFrame(data)
    print("[INFO] Data aggregation complete!")
    return df


# ===========================================================
# STEP 6: GENERATE FORENSIC REPORT (HTML)
# ===========================================================

def generate_report(aggregated_df):
    print("[INFO] Generating forensic report...")
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("report_template.html")

    output = template.render(aggregated_data=aggregated_df.to_dict("records"))

    with open(REPORT_FILE, "w") as f:
        f.write(output)
    print(f"[INFO] Report generated successfully: {REPORT_FILE}")


# ===========================================================
# STEP 7: VISUALIZATION
# ===========================================================

def visualize_data(df):
    print("[INFO] Visualizing data summary...")
    df['length'] = df['analysis'].apply(len)
    df.plot(kind="bar", x="source", y="length", legend=False)
    plt.title("Forensic Data Volume by Source")
    plt.ylabel("Characters")
    plt.show()


# ===========================================================
# MAIN PIPELINE
# ===========================================================

def main_pipeline():
    print("[INFO] Starting forensic analysis pipeline...")

    run_volatility(MEMORY_IMAGE_PATH)
    analyze_pcap(PCAP_FILE_PATH)
    analyze_disk_image(DISK_IMAGE_PATH, offset=8192)
    analyze_malware(API_KEY, SCAN_PATH)

    aggregated_df = aggregate_data()
    generate_report(aggregated_df)
    visualize_data(aggregated_df)

    print("[INFO] Forensic analysis pipeline complete!")


# ===========================================================
# ENTRY POINT
# ===========================================================

if __name__ == "__main__":
    main_pipeline()
