#!/usr/bin/env python3
"""
Simple UDP packet sender/receiver for testing the ALB.
Sends packets to dtap0 (ALB input) and listens on dtap1 (ALB output).
"""
import socket
import struct
import time
import sys
import threading
import argparse

def create_udp_packet(src_ip, dst_ip, src_port, dst_port, payload):
    """Create a raw UDP packet with IP header."""
    # IP Header
    version_ihl = 0x45
    tos = 0
    total_length = 20 + 8 + len(payload)  # IP + UDP + payload
    identification = 54321
    flags_fragment = 0
    ttl = 64
    protocol = 17  # UDP
    checksum = 0
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)
    
    ip_header = struct.pack('!BBHHHBBH4s4s',
        version_ihl, tos, total_length, identification,
        flags_fragment, ttl, protocol, checksum,
        src_addr, dst_addr)
    
    # UDP Header
    udp_length = 8 + len(payload)
    udp_checksum = 0
    udp_header = struct.pack('!HHHH', src_port, dst_port, udp_length, udp_checksum)
    
    return ip_header + udp_header + payload

class PacketReceiver:
    def __init__(self):
        self.packets = []
        self.lock = threading.Lock()

    def add_packet(self, dst_ip, dst_port, dst_mac):
        with self.lock:
            self.packets.append({'dst_ip': dst_ip, 'dst_port': dst_port, 'dst_mac': dst_mac})

    def get_packets(self):
        with self.lock:
            return list(self.packets)

receiver_data = PacketReceiver()

def receiver_thread(iface, stop_event):
    """Listen for packets on interface."""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        sock.bind((iface, 0))
        sock.settimeout(0.5)
        
        print(f"[RX] Listening on {iface}...")
        count = 0
        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(65535)
                eth_dst = ':'.join(f'{b:02x}' for b in data[0:6])
                eth_src = ':'.join(f'{b:02x}' for b in data[6:12])
                eth_type = struct.unpack('!H', data[12:14])[0]
                
                if eth_type == 0x0800:  # IPv4
                    ip_data = data[14:]
                    src_ip = socket.inet_ntoa(ip_data[12:16])
                    dst_ip = socket.inet_ntoa(ip_data[16:20])
                    protocol = ip_data[9]
                    
                    if protocol == 17:  # UDP
                        ihl = (ip_data[0] & 0x0F) * 4
                        udp_data = ip_data[ihl:]
                        src_port = struct.unpack('!H', udp_data[0:2])[0]
                        dst_port = struct.unpack('!H', udp_data[2:4])[0]
                        
                        count += 1
                        receiver_data.add_packet(dst_ip, dst_port, eth_dst)
                        print(f"[RX #{count}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                              f"(dst_mac={eth_dst})")
            except socket.timeout:
                continue
        print(f"[RX] Received {count} packets total")
    except PermissionError:
        print("[RX] Error: Need root privileges to capture packets")
    except OSError as e:
        print(f"[RX] Error binding to {iface}: {e}")

def sender(iface, dst_ip, dst_port, count, interval):
    """Send UDP packets to interface."""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((iface, 0))
        
        # Get interface MAC
        import fcntl
        info = fcntl.ioctl(sock.fileno(), 0x8927, struct.pack('256s', iface.encode()[:15]))
        src_mac = info[18:24]
        
        print(f"[TX] Sending {count} packets to {dst_ip}:{dst_port} via {iface}")
        
        for i in range(count):
            payload = f"packet-{i:04d}".encode()
            
            # Ethernet header (broadcast dst, our src mac, IPv4 type)
            eth_header = b'\xff\xff\xff\xff\xff\xff' + src_mac + struct.pack('!H', 0x0800)
            
            # IP + UDP packet
            ip_udp = create_udp_packet("10.0.0.1", dst_ip, 12345, dst_port, payload)
            
            packet = eth_header + ip_udp
            sock.send(packet)
            print(f"[TX] Sent packet {i+1}/{count}")
            
            if interval > 0:
                time.sleep(interval)
        
        print(f"[TX] Done sending {count} packets")
        
    except PermissionError:
        print("[TX] Error: Need root privileges to send raw packets")
    except OSError as e:
        print(f"[TX] Error binding to {iface}: {e}")

def verify_round_robin(packets, expected_backends):
    """Verify packets were distributed round-robin across backends."""
    if not packets:
        print("[VERIFY] FAIL: No packets received")
        return False

    dst_ips = [p['dst_ip'] for p in packets]
    unique_ips = set(dst_ips)

    print(f"\n[VERIFY] Received {len(packets)} packets")
    print(f"[VERIFY] Unique destination IPs: {sorted(unique_ips)}")

    from collections import Counter
    distribution = Counter(dst_ips)
    print(f"[VERIFY] Distribution: {dict(distribution)}")

    if expected_backends:
        expected_set = set(expected_backends)
        if unique_ips != expected_set:
            missing = expected_set - unique_ips
            extra = unique_ips - expected_set
            if missing:
                print(f"[VERIFY] FAIL: Missing backends: {missing}")
            if extra:
                print(f"[VERIFY] FAIL: Unexpected backends: {extra}")
            return False

        for i, ip in enumerate(dst_ips):
            expected_ip = expected_backends[i % len(expected_backends)]
            if ip != expected_ip:
                print(f"[VERIFY] FAIL: Packet {i} went to {ip}, expected {expected_ip} (round-robin)")
                return False

        print("[VERIFY] PASS: Round-robin distribution verified")
        return True

    if len(unique_ips) < 2:
        print("[VERIFY] FAIL: All packets went to same backend (no load balancing)")
        return False

    print("[VERIFY] PASS: Packets distributed across multiple backends")
    return True


def main():
    parser = argparse.ArgumentParser(description='UDP packet sender/receiver for ALB testing')
    parser.add_argument('--tx-iface', default='dtap0', help='Interface to send packets (default: dtap0)')
    parser.add_argument('--rx-iface', default='dtap1', help='Interface to receive packets (default: dtap1)')
    parser.add_argument('--dst-ip', default='192.168.1.1', help='Destination IP (default: 192.168.1.1)')
    parser.add_argument('--dst-port', type=int, default=5678, help='Destination port (default: 5678)')
    parser.add_argument('--count', '-c', type=int, default=5, help='Number of packets (default: 5)')
    parser.add_argument('--interval', '-i', type=float, default=0.5, help='Interval between packets in seconds (default: 0.5)')
    parser.add_argument('--rx-only', action='store_true', help='Only receive, do not send')
    parser.add_argument('--tx-only', action='store_true', help='Only send, do not receive')
    parser.add_argument('--verify-round-robin', action='store_true', help='Verify round-robin distribution')
    parser.add_argument('--expected-backends', nargs='+', help='Expected backend IPs in round-robin order')
    args = parser.parse_args()
    
    stop_event = threading.Event()
    rx_thread = None
    
    # Start receiver thread
    if not args.tx_only:
        rx_thread = threading.Thread(target=receiver_thread, args=(args.rx_iface, stop_event))
        rx_thread.start()
        time.sleep(0.5)  # Let receiver start
    
    # Send packets
    if not args.rx_only:
        sender(args.tx_iface, args.dst_ip, args.dst_port, args.count, args.interval)
    
    # Wait a bit for any delayed packets
    if rx_thread:
        if args.rx_only:
            try:
                print("Press Ctrl+C to stop...")
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
        else:
            time.sleep(2)
        
        stop_event.set()
        rx_thread.join()

    # Verify round-robin if requested
    if args.verify_round_robin and not args.tx_only:
        packets = receiver_data.get_packets()
        if not verify_round_robin(packets, args.expected_backends):
            sys.exit(1)


if __name__ == '__main__':
    main()
