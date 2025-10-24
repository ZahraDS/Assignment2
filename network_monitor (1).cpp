/*
This program requires a valid network interface to capture packets. 
  The interface must exist on your system; otherwise, you will get an error like:
      Error: Interface 'wlan0' not found

  On this VM, the only available interface is 'enp0s3', so all commands should use it:
      sudo ./monitoring enp0s3 <source_addr> <dest_addr>

  Examples: Run as Command ;
      sudo ./monitoring enp0s3 10.0.2.15 10.0.2.15
     */

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>      
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>      
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <net/if.h>

using namespace std;

// System Configuration Parameters
#define BUFFER_CAPACITY 65536
#define MTU_LIMIT 1500
#define MAX_SEND_ATTEMPTS 2
#define LARGE_PKT_LIMIT 10
#define RUNTIME_PERIOD 60

// Utility Functions
static string getCurrentTimestamp() {
    time_t current = time(nullptr);
    char buffer[64];
    struct tm *time_data = localtime(&current);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", time_data);
    return string(buffer);
}

static string convertIPv4(uint32_t addr_network_order) {
    struct in_addr address;
    address.s_addr = addr_network_order;
    char str_buffer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &address, str_buffer, sizeof(str_buffer));
    return string(str_buffer);
}

static string convertIPv6(const struct in6_addr &ipv6_addr) {
    char str_buffer[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ipv6_addr, str_buffer, sizeof(str_buffer));
    return string(str_buffer);
}

static bool validateIPAddress(const string &ip_str) {
    struct in_addr ipv4_test;
    struct in6_addr ipv6_test;
    if (inet_pton(AF_INET, ip_str.c_str(), &ipv4_test) == 1) return true;
    if (inet_pton(AF_INET6, ip_str.c_str(), &ipv6_test) == 1) return true;
    return false;
}

/* Protocol Stack Implementation */
struct ProtocolEntry {
    char *protocol_name;
    ProtocolEntry *previous;
};

struct ProtocolChain {
    ProtocolEntry *head;
   
    ProtocolChain() : head(nullptr) {}
   
    ~ProtocolChain() {
        while (head) { removeTop(); }
    }

    bool addProtocol(const char *name) {
        ProtocolEntry *entry = (ProtocolEntry*)malloc(sizeof(ProtocolEntry));
        if (!entry) return false;
        size_t name_len = strlen(name) + 1;
        entry->protocol_name = (char*)malloc(name_len);
        if (!entry->protocol_name) {
            free(entry);
            return false;
        }
        memcpy(entry->protocol_name, name, name_len);
        entry->previous = head;
        head = entry;
        return true;
    }

    char* removeTop() {
        if (!head) return nullptr;
        ProtocolEntry *entry = head;
        head = entry->previous;
        char *result = entry->protocol_name;
        free(entry);
        return result;
    }

    bool hasEntries() const { return head != nullptr; }
};

// Network Frame Structure
struct NetworkFrame {
    unsigned long long frame_id;
    char capture_time[64];
    int frame_length;
    unsigned char raw_bytes[BUFFER_CAPACITY];
    int transmission_attempts;

    // Protocol Information
    bool ipv4_present;
    bool ipv6_present;
    char source_address[INET6_ADDRSTRLEN];
    char destination_address[INET6_ADDRSTRLEN];
    unsigned short source_port_num;
    unsigned short destination_port_num;
    char transport_protocol[16];

    NetworkFrame() {
        frame_id = 0;
        capture_time[0] = '\0';
        frame_length = 0;
        transmission_attempts = 0;
        ipv4_present = false;
        ipv6_present = false;
        source_address[0] = '\0';
        destination_address[0] = '\0';
        source_port_num = 0;
        destination_port_num = 0;
        transport_protocol[0] = '\0';
        memset(raw_bytes, 0, sizeof(raw_bytes));
    }
};

// Frame Buffer Implementation
struct BufferElement {
    NetworkFrame frame_data;
    BufferElement *next_element;
};

struct FrameBuffer {
    BufferElement *front;
    BufferElement *rear;
    int element_count;

    FrameBuffer() : front(nullptr), rear(nullptr), element_count(0) {}

    ~FrameBuffer() {
        while (front) {
            BufferElement *temp = front;
            front = front->next_element;
            free(temp);
        }
    }

    bool insert(const NetworkFrame &frame) {
        BufferElement *elem = (BufferElement*)malloc(sizeof(BufferElement));
        if (!elem) return false;
        elem->frame_data = frame;
        elem->next_element = nullptr;
        if (!rear) {
            front = rear = elem;
        } else {
            rear->next_element = elem;
            rear = elem;
        }
        ++element_count;
        return true;
    }

    bool remove(NetworkFrame &output) {
        if (!front) return false;
        BufferElement *elem = front;
        output = elem->frame_data;
        front = elem->next_element;
        if (!front) rear = nullptr;
        free(elem);
        --element_count;
        return true;
    }

    bool empty() const { return front == nullptr; }
    int length() const { return element_count; }
};

// Global Statistics
unsigned long long frame_counter = 1;
int large_frames_dropped = 0;
int large_frames_detected = 0;
unsigned long long frames_received = 0;
unsigned long long frames_analyzed = 0;
unsigned long long frames_matched = 0;
unsigned long long frames_transmitted = 0;

FrameBuffer transmit_buffer;
FrameBuffer overflow_buffer;

// Network Interface Utilities
int retrieveInterfaceID(int socket_fd, const string &if_name) {
    struct ifreq interface_req;
    memset(&interface_req, 0, sizeof(interface_req));
    strncpy(interface_req.ifr_name, if_name.c_str(), IFNAMSIZ - 1);
    if (ioctl(socket_fd, SIOCGIFINDEX, &interface_req) < 0) return -1;
    return interface_req.ifr_ifindex;
}

bool retrieveInterfaceHardwareAddr(int socket_fd, const string &if_name, unsigned char hw_addr[6]) {
    struct ifreq interface_req;
    memset(&interface_req, 0, sizeof(interface_req));
    strncpy(interface_req.ifr_name, if_name.c_str(), IFNAMSIZ - 1);
    if (ioctl(socket_fd, SIOCGIFHWADDR, &interface_req) < 0) return false;
    memcpy(hw_addr, interface_req.ifr_hwaddr.sa_data, 6);
    return true;
}

// Frame Analysis Function
void analyzeNetworkFrame(NetworkFrame &frame) {
    ProtocolChain chain;
    chain.addProtocol("Ethernet");

    if (frame.frame_length < (int)sizeof(struct ethhdr)) {
        printf("[%s] Frame %llu: insufficient data for Ethernet header\n",
               getCurrentTimestamp().c_str(), frame.frame_id);
        return;
    }

    struct ethhdr *ethernet = (struct ethhdr*)frame.raw_bytes;
    uint16_t ether_type = ntohs(ethernet->h_proto);

    size_t byte_offset = sizeof(struct ethhdr);

    if (ether_type == ETH_P_IP) {
        chain.addProtocol("IPv4");
        if (frame.frame_length >= (int)(byte_offset + sizeof(struct iphdr))) {
            struct iphdr *ip_header = (struct iphdr*)(frame.raw_bytes + byte_offset);
            frame.ipv4_present = true;
            string src = convertIPv4(ip_header->saddr);
            string dst = convertIPv4(ip_header->daddr);
            strncpy(frame.source_address, src.c_str(), sizeof(frame.source_address)-1);
            strncpy(frame.destination_address, dst.c_str(), sizeof(frame.destination_address)-1);
            int header_len = ip_header->ihl * 4;
            byte_offset += header_len;

            if (ip_header->protocol == IPPROTO_TCP) {
                chain.addProtocol("TCP");
                strncpy(frame.transport_protocol, "TCP", sizeof(frame.transport_protocol)-1);
                if (frame.frame_length >= (int)(byte_offset + sizeof(struct tcphdr))) {
                    struct tcphdr *tcp_header = (struct tcphdr*)(frame.raw_bytes + byte_offset);
                    frame.source_port_num = ntohs(tcp_header->source);
                    frame.destination_port_num = ntohs(tcp_header->dest);
                }
            } else if (ip_header->protocol == IPPROTO_UDP) {
                chain.addProtocol("UDP");
                strncpy(frame.transport_protocol, "UDP", sizeof(frame.transport_protocol)-1);
                if (frame.frame_length >= (int)(byte_offset + sizeof(struct udphdr))) {
                    struct udphdr *udp_header = (struct udphdr*)(frame.raw_bytes + byte_offset);
                    frame.source_port_num = ntohs(udp_header->source);
                    frame.destination_port_num = ntohs(udp_header->dest);
                }
            } else {
                strncpy(frame.transport_protocol, "Other", sizeof(frame.transport_protocol)-1);
            }
        } else {
            printf("[%s] Frame %llu: corrupted IPv4 header\n",
                   getCurrentTimestamp().c_str(), frame.frame_id);
        }
    } else if (ether_type == ETH_P_IPV6) {
        chain.addProtocol("IPv6");
        if (frame.frame_length >= (int)(byte_offset + sizeof(struct ip6_hdr))) {
            struct ip6_hdr *ipv6_header = (struct ip6_hdr*)(frame.raw_bytes + byte_offset);
            frame.ipv6_present = true;
            string src = convertIPv6(ipv6_header->ip6_src);
            string dst = convertIPv6(ipv6_header->ip6_dst);
            strncpy(frame.source_address, src.c_str(), sizeof(frame.source_address)-1);
            strncpy(frame.destination_address, dst.c_str(), sizeof(frame.destination_address)-1);
            byte_offset += sizeof(struct ip6_hdr);

            uint8_t next_header = ipv6_header->ip6_nxt;
            if (next_header == IPPROTO_TCP) {
                chain.addProtocol("TCP");
                strncpy(frame.transport_protocol, "TCP", sizeof(frame.transport_protocol)-1);
                if (frame.frame_length >= (int)(byte_offset + sizeof(struct tcphdr))) {
                    struct tcphdr *tcp_header = (struct tcphdr*)(frame.raw_bytes + byte_offset);
                    frame.source_port_num = ntohs(tcp_header->source);
                    frame.destination_port_num = ntohs(tcp_header->dest);
                }
            } else if (next_header == IPPROTO_UDP) {
                chain.addProtocol("UDP");
                strncpy(frame.transport_protocol, "UDP", sizeof(frame.transport_protocol)-1);
                if (frame.frame_length >= (int)(byte_offset + sizeof(struct udphdr))) {
                    struct udphdr *udp_header = (struct udphdr*)(frame.raw_bytes + byte_offset);
                    frame.source_port_num = ntohs(udp_header->source);
                    frame.destination_port_num = ntohs(udp_header->dest);
                }
            } else {
                strncpy(frame.transport_protocol, "Other", sizeof(frame.transport_protocol)-1);
            }
        } else {
            printf("[%s] Frame %llu: corrupted IPv6 header\n",
                   getCurrentTimestamp().c_str(), frame.frame_id);
        }
    } else {
        strncpy(frame.transport_protocol, "Non-IP", sizeof(frame.transport_protocol)-1);
    }

    // Display Analysis Results
    printf("[%s] ======= Frame Analysis #%llu =======\n",
           getCurrentTimestamp().c_str(), frame.frame_id);
    printf("    Timestamp: %s\n", frame.capture_time);
    printf("    Length: %d bytes\n", frame.frame_length);
    printf("    Protocol Stack (top-down):\n");
   
    int layer_num = 0;
    while (chain.hasEntries()) {
        char *protocol = chain.removeTop();
        if (!protocol) break;
        printf("      Layer %d: %s\n", ++layer_num, protocol);
        free(protocol);
    }
   
    if (frame.ipv4_present || frame.ipv6_present) {
        printf("    Route: %s -> %s [%s]\n",
               frame.source_address, frame.destination_address, frame.transport_protocol);
        if (frame.source_port_num || frame.destination_port_num) {
            printf("    Port mapping: %u -> %u\n",
                   frame.source_port_num, frame.destination_port_num);
        }
    }
    printf("\n");

    ++frames_analyzed;
}

// Filter Configuration
string source_filter;
string destination_filter;

bool matchesFilterCriteria(const NetworkFrame &frame) {
    if ((frame.ipv4_present || frame.ipv6_present) &&
        frame.source_address[0] && frame.destination_address[0]) {
        if (source_filter == string(frame.source_address) &&
            destination_filter == string(frame.destination_address)) {
            return true;
        }
    }
    return false;
}

// Transmission Logic
bool executeFrameTransmission(int tx_socket, struct sockaddr_ll *device_addr, NetworkFrame &frame) {
    for (int try_num = 0; try_num <= MAX_SEND_ATTEMPTS; ++try_num) {
        ssize_t bytes_sent = sendto(tx_socket, frame.raw_bytes, frame.frame_length, 0,
                                     (struct sockaddr*)device_addr, sizeof(*device_addr));
        if (bytes_sent == frame.frame_length) {
            printf("[%s] TRANSMITTED: Frame #%llu on attempt %d/%d\n",
                   getCurrentTimestamp().c_str(), frame.frame_id,
                   try_num+1, MAX_SEND_ATTEMPTS+1);
            ++frames_transmitted;
            return true;
        } else {
            fprintf(stderr, "[%s] TRANSMISSION FAILED: attempt %d/%d for Frame #%llu (error=%d)\n",
                    getCurrentTimestamp().c_str(), try_num+1, MAX_SEND_ATTEMPTS+1,
                    frame.frame_id, errno);
            usleep(100 * 1000);
        }
    }
    return false;
}

// Main Program Entry Point
int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: sudo %s <network_if> <source_addr> <dest_addr>\n", argv[0]);
        return 1;
    }

    string network_interface = argv[1];
    source_filter = string(argv[2]);
    destination_filter = string(argv[3]);

    if (!validateIPAddress(source_filter) || !validateIPAddress(destination_filter)) {
        fprintf(stderr, "Error: Invalid IP address format in filter parameters\n");
        return 1;
    }

    printf("\n");
    printf("========================================\n");
    printf("    NETWORK TRAFFIC ANALYZER v2.0\n");
    printf("========================================\n");
    printf("  Active Interface: %s\n", network_interface.c_str());
    printf("  Traffic Filter: %s --> %s\n", source_filter.c_str(), destination_filter.c_str());
    printf("  Monitoring Duration: %d seconds\n", RUNTIME_PERIOD);
    printf("========================================\n");
    printf("\n");

    // Initialize capture socket
    int capture_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (capture_socket < 0) {
        perror("Failed to create capture socket");
        return 1;
    }

    struct sockaddr_ll socket_addr;
    memset(&socket_addr, 0, sizeof(socket_addr));
    socket_addr.sll_family = AF_PACKET;
    socket_addr.sll_protocol = htons(ETH_P_ALL);
    int interface_id = retrieveInterfaceID(capture_socket, network_interface);
    if (interface_id < 0) {
        fprintf(stderr, "Error: Interface '%s' not found\n", network_interface.c_str());
        close(capture_socket);
        return 1;
    }
    socket_addr.sll_ifindex = interface_id;

    if (bind(capture_socket, (struct sockaddr*)&socket_addr, sizeof(socket_addr)) < 0) {
        perror("Socket binding failed");
        close(capture_socket);
        return 1;
    }

    // Configure socket timeout
    struct timeval timeout_val;
    timeout_val.tv_sec = 1;
    timeout_val.tv_usec = 0;
    setsockopt(capture_socket, SOL_SOCKET, SO_RCVTIMEO,
               (const char*)&timeout_val, sizeof(timeout_val));

    printf("[%s] Initiating packet capture on %s...\n",
           getCurrentTimestamp().c_str(), network_interface.c_str());

    time_t start_timestamp = time(nullptr);
    unsigned char receive_buffer[BUFFER_CAPACITY];

    // Main capture loop
    while (difftime(time(nullptr), start_timestamp) < RUNTIME_PERIOD) {
        ssize_t received_bytes = recvfrom(capture_socket, receive_buffer,
                                          BUFFER_CAPACITY, 0, nullptr, nullptr);
        if (received_bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            } else {
                perror("Receive error");
                continue;
            }
        }

        // Construct frame object
        NetworkFrame captured_frame;
        captured_frame.frame_id = frame_counter++;
        string timestamp = getCurrentTimestamp();
        strncpy(captured_frame.capture_time, timestamp.c_str(),
                sizeof(captured_frame.capture_time)-1);
        captured_frame.frame_length = (int)received_bytes;
        if (captured_frame.frame_length > BUFFER_CAPACITY)
            captured_frame.frame_length = BUFFER_CAPACITY;
        memcpy(captured_frame.raw_bytes, receive_buffer, captured_frame.frame_length);

        ++frames_received;

        // Handle oversized frames
        if (captured_frame.frame_length > MTU_LIMIT) {
            ++large_frames_detected;
            if (large_frames_dropped >= LARGE_PKT_LIMIT) {
                printf("[%s] DROPPED: Oversized Frame #%llu (size=%d, threshold exceeded)\n",
                       getCurrentTimestamp().c_str(), captured_frame.frame_id,
                       captured_frame.frame_length);
                continue;
            } else {
                ++large_frames_dropped;
                printf("[%s] WARNING: Oversized Frame #%llu (size=%d, drop count=%d)\n",
                       getCurrentTimestamp().c_str(), captured_frame.frame_id,
                       captured_frame.frame_length, large_frames_dropped);
            }
        }

        printf("[%s] RECEIVED: Frame #%llu [%d bytes]\n",
               getCurrentTimestamp().c_str(), captured_frame.frame_id,
               captured_frame.frame_length);

        // Analyze frame
        analyzeNetworkFrame(captured_frame);

        // Apply filter and queue for transmission
        if (matchesFilterCriteria(captured_frame)) {
            double estimated_delay = ((double)captured_frame.frame_length) / 1000.0;
            printf("[%s] FILTER MATCH: Frame #%llu [%s -> %s] (%s) | Est. delay: %.2f ms\n",
                   getCurrentTimestamp().c_str(), captured_frame.frame_id,
                   captured_frame.source_address, captured_frame.destination_address,
                   captured_frame.transport_protocol, estimated_delay);
            ++frames_matched;

            if (!transmit_buffer.insert(captured_frame)) {
                fprintf(stderr, "[%s] Primary buffer full for Frame #%llu, using overflow\n",
                        getCurrentTimestamp().c_str(), captured_frame.frame_id);
                overflow_buffer.insert(captured_frame);
            }
        }
    }

    printf("\n[%s] Capture phase complete. Processing transmission queue...\n",
           getCurrentTimestamp().c_str());

    // Initialize transmission socket
    int transmit_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (transmit_socket < 0) {
        perror("Failed to create transmission socket");
    } else {
        int tx_interface_id = retrieveInterfaceID(transmit_socket, network_interface);
        if (tx_interface_id < 0) {
            fprintf(stderr, "Error: Cannot resolve interface '%s' for transmission\n",
                    network_interface.c_str());
            close(transmit_socket);
            transmit_socket = -1;
        } else {
            struct sockaddr_ll tx_device;
            memset(&tx_device, 0, sizeof(tx_device));
            tx_device.sll_family = AF_PACKET;
            tx_device.sll_ifindex = tx_interface_id;
            tx_device.sll_halen = ETH_ALEN;
            tx_device.sll_protocol = htons(ETH_P_ALL);

            unsigned char hw_address[6];
            if (!retrieveInterfaceHardwareAddr(transmit_socket, network_interface, hw_address)) {
                fprintf(stderr, "Warning: Could not retrieve hardware address for %s\n",
                        network_interface.c_str());
            }

            // Process transmission queue
            NetworkFrame tx_frame;
            while (transmit_buffer.remove(tx_frame)) {
                if (tx_frame.frame_length >= (int)sizeof(struct ethhdr)) {
                    struct ethhdr *eth_hdr = (struct ethhdr*)tx_frame.raw_bytes;
                    memcpy(tx_device.sll_addr, eth_hdr->h_dest, ETH_ALEN);
                } else {
                    memset(tx_device.sll_addr, 0xff, ETH_ALEN);
                }

                bool success = executeFrameTransmission(transmit_socket, &tx_device, tx_frame);
                if (!success) {
                    tx_frame.transmission_attempts = MAX_SEND_ATTEMPTS + 1;
                    printf("[%s] Frame #%llu moved to overflow after transmission failure\n",
                           getCurrentTimestamp().c_str(), tx_frame.frame_id);
                    overflow_buffer.insert(tx_frame);
                }
            }
        }
    }

    // Process overflow buffer
    if (!overflow_buffer.empty() && transmit_socket >= 0) {
        printf("\n[%s] Attempting recovery for overflow buffer (%d frames)...\n",
               getCurrentTimestamp().c_str(), overflow_buffer.length());
        NetworkFrame recovery_frame;
        int recovery_attempts = 0;
        while (overflow_buffer.remove(recovery_frame)) {
            ++recovery_attempts;
            struct sockaddr_ll recovery_device;
            memset(&recovery_device, 0, sizeof(recovery_device));
            recovery_device.sll_family = AF_PACKET;
            recovery_device.sll_ifindex = interface_id;
            recovery_device.sll_halen = ETH_ALEN;
           
            if (recovery_frame.frame_length >= (int)sizeof(struct ethhdr)) {
                struct ethhdr *eth_hdr = (struct ethhdr*)recovery_frame.raw_bytes;
                memcpy(recovery_device.sll_addr, eth_hdr->h_dest, ETH_ALEN);
            } else {
                memset(recovery_device.sll_addr, 0xff, ETH_ALEN);
            }
           
            ssize_t sent = sendto(transmit_socket, recovery_frame.raw_bytes,
                                  recovery_frame.frame_length, 0,
                                  (struct sockaddr*)&recovery_device, sizeof(recovery_device));
            if (sent == recovery_frame.frame_length) {
                printf("[%s] RECOVERY SUCCESS: Frame #%llu transmitted\n",
                       getCurrentTimestamp().c_str(), recovery_frame.frame_id);
                ++frames_transmitted;
            } else {
                fprintf(stderr, "[%s] RECOVERY FAILED: Frame #%llu (error=%d). Discarded.\n",
                        getCurrentTimestamp().c_str(), recovery_frame.frame_id, errno);
            }
        }
    }

    if (transmit_socket >= 0) close(transmit_socket);
    close(capture_socket);

    // Display final statistics
    printf("\n");
    printf("      MONITORING SESSION COMPLETE\n");
    printf("\n");
    printf("  Packets Received:       %llu\n", frames_received);
    printf("  Packets Analyzed:       %llu\n", frames_analyzed);
    printf("  Packets Matched Filter: %llu\n", frames_matched);
    printf("  Packets Transmitted:    %llu\n", frames_transmitted);
    printf("  Large Packets Detected: %d\n", large_frames_detected);
    printf("  Large Packets Dropped:  %d\n", large_frames_dropped);
    printf("  Overflow Buffer Size:  %d\n", overflow_buffer.length());
    printf("\n");


    return 0;
}
