import argparse
import datetime
import time
from scapy.all import IP, TCP, sniff


class DDoSMonitor:

  def __init__(
      self,
      pps_threshold=30,
      syn_ratio_threshold=0.7,
      window_duration=2.0,
      interface="lo",
  ):
    self.pps_threshold = pps_threshold
    self.syn_ratio_threshold = syn_ratio_threshold
    self.window_duration = window_duration
    self.interface = interface

    self.packet_count = 0
    self.syn_count = 0
    self.source_ips = {}
    self.start_time = time.time()

  def log_alert(self, message):
    """Logs alerts to the terminal with timestamps and saves to a log file."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}"

    # Print to terminal
    print(f"\n🚨 {log_entry}")

    # Append to persistent alert log file for project evidence
    with open("ddos_alerts.log", "a") as f:
      f.write(f"{log_entry}\n")

  def packet_callback(self, packet):
    current_time = time.time()
    elapsed = current_time - self.start_time

    # Track overall packets
    if IP in packet:
      src_ip = packet[IP].src
      self.source_ips[src_ip] = self.source_ips.get(src_ip, 0) + 1
      self.packet_count += 1

      # Check for TCP SYN packets
      if TCP in packet:
        flags = packet[TCP].flags
        # 'S' flag check (SYN flag value is usually 2 or contains 'S')
        if flags & 0x02:
          self.syn_count += 1

    # Evaluate window once window duration is reached
    if elapsed >= self.window_duration:
      pps = self.packet_count / elapsed

      print(
          f"[*] Analyzing Window... Traffic Rate: {pps:.2f} packets/sec"
          f" (SYN Ratio: {self.syn_count / max(1, self.packet_count):.2f})"
      )

      # Layer 1: Volumetric PPS Check
      if pps > self.pps_threshold:
        self.log_alert(
            f"High Traffic Volume Detected! Rate: {pps:.2f} pps (Threshold:"
            f" {self.pps_threshold})"
        )

        # Identify top offending IP in this window
        if self.source_ips:
          top_ip = max(self.source_ips, key=self.source_ips.get)
          ip_pps = self.source_ips[top_ip] / elapsed
          if ip_pps > self.pps_threshold:
            self.log_alert(
                f"Potential Source Flood from IP: {top_ip} ({ip_pps:.2f} pps)"
            )

      # Layer 2: SYN Ratio Check
      if self.packet_count > 10:  # Avoid division anomalies on low traffic
        syn_ratio = self.syn_count / self.packet_count
        if syn_ratio > self.syn_ratio_threshold:
          self.log_alert(
              f"Potential SYN Flood Attack! SYN Ratio: {syn_ratio:.2f}"
              f" (Threshold: {self.syn_ratio_threshold})"
          )

      # Reset counters for the next window
      self.packet_count = 0
      self.syn_count = 0
      self.source_ips.clear()
      self.start_time = time.time()

  def start_monitoring(self):
    print(f"[*] Starting Network Monitor on interface: {self.interface}")
    print(
        f"[*] Thresholds -> PPS: {self.pps_threshold}, SYN Ratio:"
        f" {self.syn_ratio_threshold}"
    )
    print(f"[*] Logging alerts to 'ddos_alerts.log'...\n")

    try:
      sniff(iface=self.interface, prn=self.packet_callback, store=False)
    except KeyboardInterrupt:
      print("\n[!] Monitoring stopped by user.")


if __name__ == "__main__":
  # Command-Line Arguments configuration
  parser = argparse.ArgumentParser(
      description="Professional Python DDoS Network Monitor & Alerting Tool"
  )
  parser.add_argument(
      "-i",
      "--interface",
      default="lo",
      help="Network interface to monitor (default: lo)",
  )
  parser.add_argument(
      "-t",
      "--threshold",
      type=int,
      default=30,
      help="Packets-per-second (PPS) threshold for alerts (default: 30)",
  )
  parser.add_argument(
      "-s",
      "--syn-ratio",
      type=float,
      default=0.7,
      help="SYN packet ratio threshold (default: 0.7)",
  )

  args = parser.parse_args()

  # Initialize and run monitor with parsed arguments
  monitor = DDoSMonitor(
      pps_threshold=args.threshold,
      syn_ratio_threshold=args.syn_ratio,
      interface=args.interface,
  )
  monitor.start_monitoring()
