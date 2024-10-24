# Packet Sniffer Project

## Project Overview
This project focuses on developing a **packet sniffer** to capture and analyze network packets in real-time. It inspects Ethernet frames and identifies various IP and transport layer protocols such as UDP, TCP, and ICMP using a Python script. The project consists of two parts:

1. **sniffer.py**: Captures and dissects network traffic.
2. **info2.py & selenium1.py**: Analyzes UDP packets (particularly DNS requests) and captures screenshots of web pages using Selenium.

## How the Code Works

### **First Part: sniffer.py**
This Python script captures and analyzes network traffic:

1. **Socket Creation**: Establishes a socket to capture raw network traffic.
2. **Traffic Capture**: Listens to and captures packets from the network.
3. **Ethernet Frame Unpacking**: Extracts and decodes Ethernet frame information.
4. **Protocol Analysis**: Determines the protocol used (TCP, UDP, ICMP, etc.) and analyzes each packet.
5. **Output Formatting**: Displays packet details such as Ethernet frame, IPv4 packet data, and protocol-specific details like TCP flags or UDP data.

### **Second Part: info2.py & selenium1.py**
- **info2.py**: Sniffs UDP traffic (specifically DNS requests) and logs URLs from the packet payloads into a file.
- **selenium1.py**: Automates the browser using Selenium to take screenshots of the web pages corresponding to the captured URLs.

## How to Run the Code

### **First Program (sniffer.py)**
1. Install the required library:

    ```bash
    pip install socket
    ```

2. Run the script with administrator privileges:

    ```bash
    sudo python sniffer.py
    ```

3. While the script is running, generate network traffic by browsing different websites.

### **Second Program (info2.py & selenium1.py)**
1. Place the folder `sniffer` in your main user home directory:

    ```bash
    cd $HOME
    cd sniffer
    ```

2. Run the following command:

    ```bash
    ./start.sh
    ```

   This will install all necessary dependencies and start the program.
   
If you wish to contribute to this project, feel free to fork the repository and submit a pull request with your improvements.

This project is licensed under the MIT License. See the LICENSE file for more details.
