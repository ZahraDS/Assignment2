#  DSA Assignment 2 — Live Packet Monitoring

This project is my DSA Assignment 2 where I implemented a live network packet monitoring system in C++. It captures and analyzes packets in real time using raw sockets. The purpose of this assignment was to understand low-level network operations and packet structures.

---

##  Requirements

This program requires a valid network interface to capture packets.  
The interface must exist on your system; otherwise, you will get an error like:
Error: Interface 'wlan0' not found

kotlin
Copy code

On this VM, the only available interface is **`enp0s3`**, so all commands should use it:
sudo ./monitoring enp0s3 <source_addr> <dest_addr>

yaml
Copy code

---

##  Example Usage

Run the program as:
sudo ./monitoring enp0s3 10.0.2.15 10.0.2.15

yaml
Copy code

---

## How to Run the Program (Ubuntu Guide)

### 1. Open Terminal and navigate to the folder where `packet.cpp` is located:
```bash
cd ~/Downloads/DSA_Assignment2
2. Check your network interfaces (so you know which one to capture):
bash
Copy code
ip a
3. Compile the program using g++:
bash
Copy code
g++ packet.cpp -o pac -std=c++11
4. If you get errors about missing headers:
bash
Copy code
sudo apt update
sudo apt install build-essential linux-headers-$(uname -r)
5. Run the program as root (required for packet capture):
bash
Copy code
sudo ./pac <interface> <target_IP> <gateway_IP>
Example:
bash
Copy code
sudo ./pac enp0s3 192.168.1.11 8.8.8.8
enp0s3 → Your network interface

192.168.1.11 → Target IP to capture packets from

8.8.8.8 → Gateway or DNS IP





Safety Note
Replay (resending frames) can affect the network and other hosts.
Only run this program in a controlled environment (like Ubuntu VM) or with explicit permission.
Use responsibly.

File Structure
bash
Copy code
DSA_Assignment2/
│
├── packet.cpp        # Main source code
└── README.md         # Project documentation (this file)

Author

Zahra Abbas
