import os
import subprocess
import pandas as pd
import glob
import warnings

# Suppress pandas warnings for cleaner terminal output
warnings.filterwarnings("ignore")

# 1. Define your folders
PCAP_FOLDER = r"Bulk PCAPS"
TEMP_CSV_FOLDER = "Temp_CSVs"
MASTER_CSV = "master_advanced_dataset.csv"
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

if not os.path.exists(TEMP_CSV_FOLDER):
    os.makedirs(TEMP_CSV_FOLDER)

# Find PCAP files (Remove the '[:2]' when you want to parse ALL 15GB)
all_pcap_files = glob.glob(f"{PCAP_FOLDER}\\*.pcap")
pcap_files = all_pcap_files[:2] 

print(f"Found {len(all_pcap_files)} total PCAP files.")
print("Starting ADVANCED Deep-Packet Extraction...\n")

# 2. Extract Deep Features using tshark
for pcap in pcap_files:
    base_name = os.path.basename(pcap).replace('.pcap', '')
    output_csv = f"{TEMP_CSV_FOLDER}/{base_name}.csv"
    
    print(f"Ripping deep features from {base_name}.pcap...")
    
    # We are now asking tshark for TCP Flags, Windows Sizes, TTL, and both TCP/UDP ports
    tshark_command = [
        TSHARK_PATH, "-r", pcap, 
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "udp.srcport",
        "-e", "tcp.dstport", "-e", "udp.dstport",
        "-e", "_ws.col.Protocol", "-e", "frame.len",
        "-e", "tcp.flags.syn", "-e", "tcp.flags.ack", 
        "-e", "tcp.flags.fin", "-e", "tcp.flags.reset",
        "-e", "ip.ttl", "-e", "tcp.window_size",
        "-E", "header=y", "-E", "separator=,", "-E", "quote=d"
    ]
    
    with open(output_csv, "w") as outfile:
        subprocess.run(tshark_command, stdout=outfile, stderr=subprocess.DEVNULL)

# 3. Merge and Clean with Pandas
print("\nExtraction complete. Merging and cleaning massive dataset...")
all_csv_files = glob.glob(f"{TEMP_CSV_FOLDER}/*.csv")

dataframe_list = []
for csv_file in all_csv_files:
    try:
        df = pd.read_csv(csv_file, on_bad_lines='skip')
        
        # Rename columns from tshark's raw output to something readable
        df.columns = [
            "Timestamp", "Source IP", "Dest IP", 
            "TCP Src", "UDP Src", "TCP Dst", "UDP Dst", 
            "Protocol", "Packet Size", 
            "SYN Flag", "ACK Flag", "FIN Flag", "RST Flag", 
            "TTL", "Window Size"
        ]
        dataframe_list.append(df)
    except Exception as e:
        pass

if dataframe_list:
    master_df = pd.concat(dataframe_list, ignore_index=True)
    
    # CLEANING LOGIC: Combine TCP and UDP ports into a single 'Source Port' and 'Dest Port' column
    master_df['Source Port'] = master_df['TCP Src'].fillna(master_df['UDP Src']).fillna(0)
    master_df['Dest Port'] = master_df['TCP Dst'].fillna(master_df['UDP Dst']).fillna(0)
    
    # Drop the now-useless split port columns
    master_df.drop(columns=['TCP Src', 'UDP Src', 'TCP Dst', 'UDP Dst'], inplace=True)
    
    # Fill empty TCP flags, TTLs, and Window sizes with 0 (For non-TCP packets)
    fill_cols = ["SYN Flag", "ACK Flag", "FIN Flag", "RST Flag", "TTL", "Window Size"]
    master_df[fill_cols] = master_df[fill_cols].fillna(0)
    
    # Drop corrupted rows missing IP addresses
    master_df.dropna(subset=['Source IP', 'Dest IP'], inplace=True)
    
    # Save the final Super-Dataset
    master_df.to_csv(MASTER_CSV, index=False)
    print(f"\nSUCCESS! Advanced Master dataset saved as '{MASTER_CSV}' with {len(master_df)} rows and 13 data points per row!")
else:
    print("\nError: No data could be extracted.")