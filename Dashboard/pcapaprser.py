import os
import subprocess
import pandas as pd
import glob

# 1. Define your folders (Using your exact Windows path)
PCAP_FOLDER = r"Bulk PCAPS"
TEMP_CSV_FOLDER = "Temp_CSVs"
MASTER_CSV = "master_behavioral_dataset.csv"

# Create a temporary folder for the individual CSVs
if not os.path.exists(TEMP_CSV_FOLDER):
    os.makedirs(TEMP_CSV_FOLDER)

# Find PCAP files, but ONLY grab the first 2 for our Dry Run!
all_pcap_files = glob.glob(f"{PCAP_FOLDER}\\*.pcap")
pcap_files = all_pcap_files[:2] 

print(f"Found {len(all_pcap_files)} total PCAP files in your folder.")
print(f"SAFETY SWITCH ON: Only extracting features from {len(pcap_files)} files for the dry run...\n")

# 2. Extract features using tshark
# Explicitly define the path to tshark.exe to fix the [WinError 2] FileNotFoundError
tshark_path = r"C:\Program Files\Wireshark\tshark.exe"

for pcap in pcap_files:
    base_name = os.path.basename(pcap).replace('.pcap', '')
    output_csv = f"{TEMP_CSV_FOLDER}/{base_name}.csv"
    
    print(f"Extracting features from {base_name}.pcap...")
    
    # Using the explicit tshark_path here
    tshark_command = [
        tshark_path, "-r", pcap, 
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport",
        "-e", "_ws.col.Protocol", "-e", "frame.len",
        "-E", "header=y", "-E", "separator=,", "-E", "quote=d"
    ]
    
    with open(output_csv, "w") as outfile:
        subprocess.run(tshark_command, stdout=outfile, stderr=subprocess.DEVNULL)

# 3. Merge into a single Master Dataset
print("\nExtraction complete. Merging with Pandas...")
all_csv_files = glob.glob(f"{TEMP_CSV_FOLDER}/*.csv")

dataframe_list = []
for csv_file in all_csv_files:
    try:
        df = pd.read_csv(csv_file, on_bad_lines='skip')
        dataframe_list.append(df)
    except Exception as e:
        pass

# Check if we successfully extracted any data
if dataframe_list:
    master_df = pd.concat(dataframe_list, ignore_index=True)
    master_df.columns = ["Timestamp", "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Packet Size"]
    
    # Clean the data (Drop rows where IP is missing)
    master_df.dropna(subset=['Source IP', 'Destination IP'], inplace=True)
    
    # Save the final CSV
    master_df.to_csv(MASTER_CSV, index=False)
    print(f"\nSUCCESS! Master dataset saved as '{MASTER_CSV}' with {len(master_df)} rows.")
else:
    print("\nError: No data could be extracted. Please verify your tshark path and that the PCAP files are valid.")