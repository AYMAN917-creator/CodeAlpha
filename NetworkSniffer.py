import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

# Global dictionary to track packet counts
stats = {
    "total": 0,
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "Other": 0
}

LOG_FILE = "packet_log.txt"

def packet_callback(packet):
    global stats
    # Get the current time of capture
    now = datetime.now().strftime("%H:%M:%S")

    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        stats["total"] += 1
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol_num = packet[IP].proto
        
        # Determine the protocol name
        protocol_name = "Other"
        if protocol_num == 6:
            protocol_name = "TCP"
            stats["TCP"] += 1
        elif protocol_num == 17:
            protocol_name = "UDP"
            stats["UDP"] += 1
        elif protocol_num == 1:
            protocol_name = "ICMP"
            stats["ICMP"] += 1
        else:
            stats["Other"] += 1

        # Format the output for console and file
        output = f"[{now}] {protocol_name:5} | {src_ip:15} -> {dst_ip:15}"

        # Analyze the Payload content
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            # Display the first 30 characters to avoid clutter
            output += f" | Payload: {str(payload)[:30]}..."
        else:
            output += " | No Raw Payload"

        # Print to terminal
        print(output)

        # Logging to File: Append each packet info to the log file
        with open(LOG_FILE, "a") as f:
            f.write(output + "\n")

def print_summary():
    """Prints final statistics summary before exiting"""
    print("\n" + "="*60)
    print("           NETWORK SNIFFER SUMMARY")
    print("="*60)
    print(f" Total Packets Captured: {stats['total']}")
    print("-" * 30)
    print(f" TCP Packets:  {stats['TCP']}")
    print(f" UDP Packets:  {stats['UDP']}")
    print(f" ICMP Packets: {stats['ICMP']}")
    print(f" Others:       {stats['Other']}")
    print("="*60)
    print(f" Log saved to: {LOG_FILE}")
    print("="*60)

def main():
    print("="*60)
    print("      CODEALPHA - NETWORK SNIFFER")
    print(f"      Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
    print(f"{'TIME':10} | {'PROTO':5} | {'SOURCE IP':15} -> {'DEST IP':15} | {'PAYLOAD'}")
    print("-" * 80)

    try:
        # Run the sniffer (store=False saves memory)
        sniff(prn=packet_callback, store=False)
    except PermissionError:
        print("\n[!] Error: Please run this script as Administrator/Root.")
    except KeyboardInterrupt:
        # Show summary statistics on exit
        print_summary()
        print("\n[!] Stopping Sniffer... Program exited.")
        sys.exit(0)

if __name__ == "__main__":
    main()