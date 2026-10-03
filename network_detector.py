import time
import logging
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP
import psutil

# Configure Logging
logging.basicConfig(
    filename='network_security_alerts.log',
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s'
)

# Configuration Thresholds
BANDWIDTH_THRESHOLD_MB = 50.0  # Alert if interface traffic spikes by this amount in a check interval
SCAN_THRESHOLD_CONNECTIONS = 20  # Number of unique ports contacted in a short window to trigger scan alert
SCAN_TIME_WINDOW = 5.0  # Time window in seconds for scan detection

# Tracking dictionaries for scan detection
port_scan_tracker = defaultdict(lambda: {"ports": set(), "start_time": time.time()})

def log_alert(level, message):
    """Prints and logs security or bandwidth alerts."""
    formatted_msg = f"*** ALERT [{level}]: {message} ***"
    print(formatted_msg)
    if level == "CRITICAL":
        logging.critical(message)
    elif level == "WARNING":
        logging.warning(message)
    else:
        logging.info(message)

def check_bandwidth_usage():
    """Monitors network interfaces for excessive data usage."""
    print("[*] Checking network bandwidth and data consumption...")
    initial_stats = psutil.net_io_counters(pernic=True)
    time.sleep(3)  # Sample over 3 seconds
    final_stats = psutil.net_io_counters(pernic=True)

    for interface, final in final_stats.items():
        initial = initial_stats.get(interface)
        if initial:
            bytes_sent = final.bytes_sent - initial.bytes_sent
            bytes_recv = final.bytes_recv - initial.bytes_recv
            total_mb = (bytes_sent + bytes_recv) / (1024 * 1024)

            if total_mb > BANDWIDTH_THRESHOLD_MB:
                log_alert(
                    "WARNING", 
                    f"High Bandwidth Usage on interface '{interface}': "
                    f"{total_mb:.2f} MB transferred in the last interval "
                    f"(Sent: {bytes_sent/1024/1024:.2f}MB, Recv: {bytes_recv/1024/1024:.2f}MB)"
                )

def analyze_packet(packet):
    """Inspects live packets for penetration attempts and misconfigurations."""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # 1. Detect Port Scans (TCP SYN packets targeting multiple ports)
        if TCP in packet and packet[TCP].flags == 'S':
            dst_port = packet[TCP].dport
            current_time = time.time()
            
            tracker = port_scan_tracker[src_ip]
            
            # Reset window if expired
            if current_time - tracker["start_time"] > SCAN_TIME_WINDOW:
                tracker["ports"] = set()
                tracker["start_time"] = current_time

            tracker["ports"].add(dst_port)

            if len(tracker["ports"]) > SCAN_THRESHOLD_CONNECTIONS:
                log_alert(
                    "CRITICAL", 
                    f"Potential Port Scan / Reconnaissance detected from IP {src_ip}! "
                    f"Targeted {len(tracker['ports'])} unique ports within {SCAN_TIME_WINDOW} seconds."
                )
                tracker["ports"].clear()  # Reset after alert

        # 2. Detect ICMP Floods / Misconfigurations (Ping storms)
        elif ICMP in packet:
            # Simple heuristic: excessive ICMP requests could indicate misconfigured network loops or ping sweeps
            if packet[ICMP].type == 8:  # Echo Request
                pass  # Can be expanded with rate limiting counters

def start_sniffer(interface=None):
    """Starts live packet sniffing for anomaly and penetration detection."""
    print(f"[*] Starting packet sniffer on interface: {interface or 'default'}")
    try:
        sniff(iface=interface, prn=analyze_packet, store=False)
    except PermissionError:
        print("[-] Error: Packet sniffing requires administrator/root privileges. Please run with sudo/Administrator.")
    except Exception as e:
        print(f"[-] Sniffer error: {e}")

if __name__ == "__main__":
    print("==================================================")
    print("   Starting Network & Penetration Detector       ")
    print("==================================================")
    
    try:
        while True:
            # Check bandwidth metrics periodically
            check_bandwidth_usage()
            
            # Note: For continuous multi-threading, sniffer can be run in a separate thread.
            # Here we run a short burst sniff cycle combined with bandwidth checks.
            print("[*] Sniffing traffic for anomalies (press Ctrl+C to stop)...")
            sniff(prn=analyze_packet, timeout=5, store=False)
            
    except KeyboardInterrupt:
        print("\n[!] Detector stopped by user. Exiting safely.")
