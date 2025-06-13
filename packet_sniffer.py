import scapy.all as scapy
import time
from datetime import datetime
import matplotlib.pyplot as plt
import sys
from collections import Counter
import logging
import argparse

# Set up logging to save analysis to a file
logging.basicConfig(filename='packet_sniffer.log', level=logging.INFO, 
                    format='%(asctime)s - %(message)s')

# Global variables to track packet counts for visualization
packet_counts = Counter()
start_time = time.time()

def setup_argument_parser():
    """Set up command-line argument parser."""
    parser = argparse.ArgumentParser(description="Packet Sniffer for Network Traffic Analysis")
    parser.add_argument("-i", "--interface", default=None, 
                        help="Network interface to sniff (e.g., eth0). If None, uses default.")
    parser.add_argument("-c", "--count", type=int, default=100, 
                        help="Number of packets to capture (default: 100)")
    parser.add_argument("-f", "--filter", default="tcp port 80 or udp port 53", 
                        help="BPF filter for packets (default: HTTP and DNS)")
    return parser.parse_args()

def log_packet_info(packet, packet_type):
    """Log packet details to file and print to console."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip = packet[scapy.IP].src if scapy.IP in packet else "Unknown"
    dst_ip = packet[scapy.IP].dst if scapy.IP in packet else "Unknown"
    log_message = f"{timestamp} - {packet_type} - Source: {src_ip}, Destination: {dst_ip}"
    
    if packet_type == "HTTP Request":
        if packet[scapy.TCP].payload:
            payload = str(packet[scapy.TCP].payload)
            if "HTTP" in payload:
                log_message += f", Payload: {payload[:50]}..."  # Truncate for brevity
    elif packet_type == "DNS Query":
        if packet.haslayer(scapy.DNS):
            query = packet[scapy.DNS].qname.decode() if packet[scapy.DNS].qname else "Unknown"
            log_message += f", Query: {query}"
    
    print(log_message)
    logging.info(log_message)

def detect_suspicious_activity(packet):
    """Detect suspicious activity like multiple failed HTTP login attempts."""
    if scapy.IP in packet and scapy.TCP in packet:
        src_ip = packet[scapy.IP].src
        if packet.haslayer(scapy.Raw):
            payload = str(packet[scapy.Raw])
            # Simple heuristic: look for "401 Unauthorized" in HTTP responses
            if "401" in payload:
                packet_counts[src_ip] += 1
                if packet_counts[src_ip] > 5:  # Threshold for failed attempts
                    alert = f"ALERT: Potential brute-force from {src_ip} (Failed attempts: {packet_counts[src_ip]})"
                    print(alert)
                    logging.info(alert)

def packet_callback(packet):
    """Process each captured packet."""
    global packet_counts
    packet_counts['total'] += 1
    
    # Check for HTTP requests (TCP port 80)
    if packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == 80:
        log_packet_info(packet, "HTTP Request")
        detect_suspicious_activity(packet)
    
    # Check for DNS queries (UDP port 53)
    elif packet.haslayer(scapy.DNS) and packet[scapy.DNS].qr == 0:
        log_packet_info(packet, "DNS Query")
    
    # Update packet count for visualization
    packet_counts[time.strftime("%H:%M:%S")] += 1

def plot_traffic_volume():
    """Plot packet volume over time."""
    times = list(packet_counts.keys())[1:]  # Skip 'total'
    counts = list(packet_counts.values())[1:]  # Skip 'total'
    
    plt.figure(figsize=(10, 5))
    plt.plot(times, counts, marker='o', color='#FF6B6B')
    plt.title("Network Traffic Volume Over Time")
    plt.xlabel("Time")
    plt.ylabel("Packet Count")
    plt.xticks(rotation=45)
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("traffic_volume.png")
    plt.close()
    print("Traffic volume plot saved as 'traffic_volume.png'")

def main():
    """Main function to start packet sniffing."""
    args = setup_argument_parser()
    
    print(f"Starting packet sniffer on interface {args.interface or 'default'}...")
    print(f"Capturing {args.count} packets with filter: {args.filter}")
    print("Press Ctrl+C to stop early.")
    
    try:
        # Sniff packets with specified filter and count
        scapy.sniff(
            iface=args.interface,
            filter=args.filter,
            prn=packet_callback,
            count=args.count,
            timeout=60  # Stop after 60 seconds if count not reached
        )
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    # Generate visualization
    plot_traffic_volume()
    
    # Summary
    print(f"\nTotal packets captured: {packet_counts['total']}")
    print("Results logged to 'packet_sniffer.log'")
    print("Check 'traffic_volume.png' for traffic visualization")

if __name__ == "__main__":
    main()