DSA Assignment 2 — Live Packet Monitoring

This project is my DSA Assignment 2 where I implemented a live network packet monitoring system in C++. It captures and analyzes packets in real time using raw sockets. The purpose of this assignment was to understand low-level network operations and packet structures.

Requirements

This program requires a valid network interface to capture packets.
The interface must exist on your system; otherwise, you will get an error like:
Error: Interface 'wlan0' not found

On this VM, the only available interface is ‘enp0s3’, so all commands should use it:
sudo ./monitoring enp0s3 <source_addr> <dest_addr>

Example Usage

Run the program as:
sudo ./monitoring enp0s3 10.0.2.15 10.0.2.15

How to Run the Program (Ubuntu Guide)

Open Terminal and navigate to the folder where packet.cpp is located:
cd ~/Downloads/DSA_Assignment2

Check your network interfaces (so you know which one to capture):
ip a

Compile the program using g++:
g++ packet.cpp -o pac -std=c++11

If you get errors about missing headers:
sudo apt update
sudo apt install build-essential linux-headers-$(uname -r)

Run the program as root (required for packet capture):
sudo ./pac <interface> <target_IP> <gateway_IP>

Example:
sudo ./pac enp0s3 192.168.1.11 8.8.8.8

enp0s3 → Your network interface
192.168.1.11 → Target IP to capture packets from
8.8.8.8 → Gateway or DNS IP

Safety Note

Replay (resending frames) can affect the network and other hosts.
Only run this program in a controlled environment (like Ubuntu VM) or with explicit permission.
Use responsibly.

File Structure

DSA_Assignment2/

packet.cpp (Main source code)

Makefile (Compilation automation file)

README.md (Project documentation)

Author

Zahra Abbas
