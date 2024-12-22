import threading
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import psutil
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

sniffing = False
packet_count = 0
sniff_thread = None  
packet_sizes = []  # 패킷 크기 데이터를 저장하는 리스트
bandwidth_usage = []  # 대역폭 사용량 데이터를 저장하는 리스트


def label_packet(packet):  # 위험성 있는 네트워크 포트 점검
    if TCP in packet or UDP in packet:
        port = packet[TCP].dport if TCP in packet else packet[UDP].dport
        if port in [22, 23, 80, 443, 445, 3389, 1433, 1900, 6666, 8080, 21]:  # 일반적으로 위험한 포트들
            return '***'  # 매우 위험한 포트
        elif port in range(1024, 49152):  # 비표준 포트, 추가로 경계할 포트
            return '**'  # 경고 레벨
        elif port in [53, 67, 68]:  # DNS 및 DHCP 포트
            return '*'  # 상대적으로 안전하지만 관찰 필요
    return ''  # 아무런 문제 없음을 표시


def packet_callback(packet):
    global packet_count, packet_sizes, bandwidth_usage
    packet_count += 1
    packet_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    label = label_packet(packet)
    packet_size = len(packet)
    packet_sizes.append(packet_size)  # 패킷 크기 저장
    bandwidth_usage.append(packet_size * 8)  # 바이트를 비트로 변환하여 대역폭 사용량 저장
    
    if IP in packet:
        ip_source = packet[IP].src
        ip_destination = packet[IP].dst

        if TCP in packet:
            output = (f"{packet_count}. {packet_time} {label} - TCP Packet: {ip_source} -> {ip_destination} | "
                      f"Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}, Packet Size: {packet_size} 바이트")
        elif UDP in packet:
            output = (f"{packet_count}. {packet_time} {label} - UDP Packet: {ip_source} -> {ip_destination} | "
                      f"Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport}, Packet Size: {packet_size} 바이트")
        else:
            output = (f"{packet_count}. {packet_time} {label} - Other IP Packet: {ip_source} -> {ip_destination} | "
                      f"Packet Size: {packet_size} 바이트")
        
        print(output)


def get_network_stats():
    stats = psutil.net_io_counters()
    return stats.packets_sent, stats.packets_recv


def analyze_packet_data():
    global packet_sizes, bandwidth_usage
    if len(packet_sizes) == 0:
        print("분석할 패킷 데이터가 없습니다.")
        return

    # 패킷 크기 분석
    avg_packet_size = np.mean(packet_sizes)
    min_packet_size = np.min(packet_sizes)
    max_packet_size = np.max(packet_sizes)
    std_packet_size = np.std(packet_sizes)
    total_data_transferred = np.sum(packet_sizes)  # 총 데이터 전송량 (바이트 단위)

    # 대역폭 사용량 분석
    total_bandwidth_used = np.sum(bandwidth_usage)  # 총 대역폭 사용량 (비트 단위)
    avg_bandwidth_usage = np.mean(bandwidth_usage)  # 평균 대역폭 사용량

    print("\n--- 📊 데이터 분석 결과 ---")
    print(f"1️⃣ 총 패킷 수: {len(packet_sizes)} 개")
    print(f"2️⃣ 평균 패킷 크기: {avg_packet_size:.2f} 바이트")
    print(f"3️⃣ 최소 패킷 크기: {min_packet_size} 바이트")
    print(f"4️⃣ 최대 패킷 크기: {max_packet_size} 바이트")
    print(f"5️⃣ 표준 편차: {std_packet_size:.2f}")
    print(f"6️⃣ 총 전송된 데이터 크기: {total_data_transferred} 바이트 ({total_data_transferred / 1024:.2f} KB)")
    print(f"7️⃣ 총 대역폭 사용량: {total_bandwidth_used} 비트 ({total_bandwidth_used / (1024 * 1024):.2f} Mbit)")
    print(f"8️⃣ 평균 대역폭 사용량: {avg_bandwidth_usage:.2f} 비트\n")

    # Seaborn 시각화
    plt.figure(figsize=(10, 6))
    sns.histplot(packet_sizes, kde=True, color='blue', bins=30)
    plt.title('Packet Size Distribution')
    plt.xlabel('Packet Size (bytes)')
    plt.ylabel('Frequency')
    plt.show()

    plt.figure(figsize=(10, 6))
    sns.lineplot(x=range(len(bandwidth_usage)), y=bandwidth_usage, color='red')
    plt.title('Bandwidth Usage Over Time')
    plt.xlabel('Packet Index')
    plt.ylabel('Bandwidth Usage (bits)')
    plt.show()


def start_sniffing():
    global sniffing
    sniffing = True
    print("패킷 점검 시작...")
    sniff(prn=packet_callback, filter="ip", store=0, stop_filter=lambda x: not sniffing)
    print("패킷 점검 마치기...")


def manage_sniffing():
    global sniffing, sniff_thread
    while True:
        user_input = input("네트워크 점검 시작하고 싶으면 'start' 멈추고 싶으면 'stop' 데이터 분석을 원하면 'analyze': ").strip().lower()
        if user_input == 'start' and not sniffing:
            sniff_thread = threading.Thread(target=start_sniffing)
            sniff_thread.start()
        elif user_input == 'stop' and sniffing:
            sniffing = False
            sniff_thread.join()
            sniff_thread = None  # 스레드 값을 리셋하기
            packets_sent, packets_received = get_network_stats()
            print(f"보낸 패킷 갯수: {packets_sent} 개, 받은 패킷 갯수: {packets_received} 개")
        elif user_input == 'analyze':
            analyze_packet_data()


if __name__ == "__main__":
    manage_sniffing()
