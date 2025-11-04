import subprocess
import pandas as pd
from jinja2 import Environment, FileSystemLoader
import matplotlib.pyplot as plt
import os

# Directories
TEMPLATE_DIR = 'C:/Users/karan/OneDrive/Desktop/Cyber_techniques Project/templates'
REPORT_FILE = 'forensics_report.html'


# Step 1: Run Memory Analysis (Volatility)
import subprocess

def run_volatility(image_path):
    print("[INFO] Running memory analysis with Volatility 3...")

    # Specify the Volatility 3 command and plugin
    cmd = f'python "C:/Users/karan/Downloads/volatility3-develop/vol.py" -f "{image_path}" windows.pslist.PsList'
    
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode()
        with open('memory_analysis.txt', 'w') as f:
            f.write(output)
        print("[INFO] Memory analysis complete!")
    except subprocess.CalledProcessError as e:
        print("Volatility command failed with the following error:\n", e.output.decode())



# Step 2: Run Network Analysis (tshark/PCAP)
def analyze_pcap(pcap_file):
    print("[INFO] Running network analysis on PCAP file...")
    cmd = f'tshark -r "{pcap_file}" -q -z "io,stat,1"'
    output = subprocess.check_output(cmd, shell=True).decode()
    with open('network_analysis.txt', 'w') as f:
        f.write(output)
    print("[INFO] Network analysis complete!")


# Step 3: Disk Image Analysis (SleuthKit)
import pytsk3
from pytsk3 import Img_Info, FS_Info, Directory, File
from datetime import datetime

def analyze_disk_image(image_path,offset):
    from pytsk3 import Img_Info, FS_Info, Directory, File
    from datetime import datetime
    print("[INFO] Running detailed disk image analysis...")
    
    # Load the disk image
    img = Img_Info(image_path)
    
    # Open the file system using the offset for the FAT32 partition
    fs = FS_Info(img, offset=offset * 512)  # Offset in bytes
    
    # Initialize an empty list to hold file data
    file_data = []

    # Function to recursively traverse directories
    def traverse_directory(directory, parent_path=""):
        for entry in directory:
            if entry.info.name.name in [b'.', b'..']:
                continue
            
            # Build the file path
            file_path = f"{parent_path}/{entry.info.name.name.decode('utf-8', 'ignore')}"
            
            if entry.info.meta:
                # Collect file metadata
                file_size = entry.info.meta.size
                creation_time = datetime.fromtimestamp(entry.info.meta.crtime).isoformat() if entry.info.meta.crtime else "N/A"
                modification_time = datetime.fromtimestamp(entry.info.meta.mtime).isoformat() if entry.info.meta.mtime else "N/A"
                access_time = datetime.fromtimestamp(entry.info.meta.atime).isoformat() if entry.info.meta.atime else "N/A"
                
                # Append file metadata to list
                file_data.append({
                    "path": file_path,
                    "size": file_size,
                    "created": creation_time,
                    "modified": modification_time,
                    "accessed": access_time
                })
                
            # If the entry is a directory, recurse into it
            if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                sub_directory = entry.as_directory()
                traverse_directory(sub_directory, parent_path=file_path)

    # Start traversal from the root directory
    root_dir = fs.open_dir("/")
    traverse_directory(root_dir)
    
    # Write collected data to disk_analysis.txt
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
    
    print("[INFO] Disk image analysis complete! Data written to disk_analysis.txt")

import requests
import time

def analyze_malware(api_key, file_path):
    
    base_url = "https://www.virustotal.com/api/v3"
    headers = {
        "x-apikey": api_key
    }

    # Upload the file
    with open(file_path, "rb") as file:
        response = requests.post(
            f"{base_url}/files",
            headers=headers,
            files={"file": file}
        )

    if response.status_code != 200:
        print("Failed to upload file:", response.json())
        return

    file_analysis = response.json()
    analysis_id = file_analysis['data']['id']
    print(f"File uploaded successfully. Analysis ID: {analysis_id}")

    # Poll the analysis status
    while True:
        report_response = requests.get(
            f"{base_url}/analyses/{analysis_id}",
            headers=headers
        )
        report_data = report_response.json()

        status = report_data['data']['attributes']['status']
        if status == 'completed':
            print("Analysis completed!")
            break
        else:
            print("Analysis in progress, waiting...")
            time.sleep(10)  # Poll every 10 seconds

    # Get the scan results
    results = report_data['data']['attributes']['results']

    # Write the results to a text file
    with open('malware_analysis.txt', "w") as report_file:
        report_file.write(f"Malware Analysis Report for {file_path}\n")
        report_file.write("=" * 60 + "\n\n")

        for engine, details in results.items():
            report_file.write(f"Engine: {engine}\n")
            report_file.write(f"Category: {details['category']}\n")
            report_file.write(f"Result: {details['result']}\n")
            report_file.write("-" * 40 + "\n")

    print(f"Report saved to malware_analysis.txt ")





# Step 5: Aggregate Data
def aggregate_data():
    print("[INFO] Aggregating forensic data...")
    memory_data = open('memory_analysis.txt').readlines()
    network_data = open('network_analysis.txt').readlines()
    disk_data = open('disk_analysis.txt').readlines()
    malware_data = open('malware_analysis.txt').readlines()

    aggregated_data = [
        {"source": "Memory", "analysis": " ".join(memory_data)},
        {"source": "Network", "analysis": " ".join(network_data)},
        {"source": "Disk", "analysis": " ".join(disk_data)},
        {"source": "Malware", "analysis": " ".join(malware_data)}
    ]
    
    df = pd.DataFrame(aggregated_data)
    print("[INFO] Data aggregation complete!")
    return df, memory_data, network_data, disk_data, malware_data

# Step 6: Generate Forensic Report (HTML Report)
def generate_report(aggregated_df, memory_data, network_data, disk_data, malware_data):
    print("[INFO] Generating forensic report...")

    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template('report_template.html')

    output = template.render(
        aggregated_data=aggregated_df.to_dict('records'),
        memory_data="".join(memory_data),
        network_data="".join(network_data[:50]),
        disk_data="".join(disk_data),
        malware_data="".join(malware_data)
    )

    with open(REPORT_FILE, 'w') as f:
        f.write(output)
    print(f"[INFO] Report generated: {REPORT_FILE}")


# Step 6: Visualize Data (Optional)
def visualize_data(df):
    print("[INFO] Visualizing data...")
    df.groupby('source')['analysis'].count().plot(kind='bar')
    plt.title("Forensic Data Summary")
    plt.show()
    print("[INFO] Data visualization complete!")


# Main pipeline function to execute all steps
def main_pipeline(memory_image, pcap_file, disk_image, scan_path,api_key):
    print("[INFO] Starting forensic analysis pipeline...")

    # Step 1: Run memory analysis
    run_volatility(memory_image)

    # Step 2: Run network analysis
    analyze_pcap(pcap_file)

    # Step 3: Run disk analysis
    analyze_disk_image(disk_image,offset=8192)

    # Step 4: Run malware analysis
    # Replace with the path to save the report
    analyze_malware(api_key, scan_path)

    # Step 5: Aggregate data
    aggregated_df, memory_data, network_data, disk_data, malware_data = aggregate_data()

    # Step 6: Generate HTML report
    generate_report(aggregated_df, memory_data, network_data, disk_data, malware_data)

    # Step 7: Visualize data
    visualize_data(aggregated_df)



if __name__ == "__main__":
    # Example file paths (update with your own file paths)
    MEMORY_IMAGE_PATH = "C:/Users/karan/OneDrive/Desktop/Cyber_techniques Project/datasets/Challenge.raw"
    PCAP_FILE_PATH = "C:/Users/karan/OneDrive/Desktop/Cyber_techniques Project/datasets/traffic.pcap"
    DISK_IMAGE_PATH = "C:/Users/karan/OneDrive/Desktop/Cyber_techniques Project/datasets/disk_img.img"
    # YARA_RULES_PATH = "C:/Users/karan/yara/rules.yar"
    SCAN_PATH = r"C:/Users/karan/OneDrive/Desktop/Cyber_techniques Project/sample_malware.bat"
    api_key = "ebaa3bd3665a81f726cabf2ca8a60b0a8bbff83e7d72f4f782be6a15bd42d010"  
    # Run the full pipeline
    main_pipeline(MEMORY_IMAGE_PATH, PCAP_FILE_PATH, DISK_IMAGE_PATH, SCAN_PATH,api_key)
    