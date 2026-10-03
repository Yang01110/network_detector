Step 1: Install Python
Ensure Python 3.x is installed on your system. You can verify your installation by opening your terminal or command prompt and running:

Bash
python --version
Step 2: Install Required Dependencies
The script relies on psutil (for system/interface stats and bandwidth monitoring) and scapy (for packet sniffing and intrusion detection). Install them using pip:

Bash
pip install psutil scapy
Note for Linux / macOS Users: Packet sniffing with Scapy requires root/administrator permissions to access raw sockets. On Linux/macOS, you may also need libpcap installed on your system if Scapy reports missing packet capture dependencies:

Ubuntu/Debian: sudo apt install libpcap-dev

Fedora: sudo dnf install libpcap

Step 3: Create the Script File
Create a new file named network_detector.py.

Copy and paste the Python detection code provided earlier into the file and save it.

Step 4: Run the Program with Administrator/Root Privileges
Because the program sniffs live network packets, it must be executed with elevated privileges:

On Linux / macOS:

Bash
sudo python network_detector.py
On Windows:
Open Command Prompt or PowerShell as Administrator, then run:

DOS
python network_detector.py
What to Expect Once Running:
Console Output: The program will loop continuously, checking bandwidth metrics across your network interfaces and sniffing live traffic packets for anomalies like port scans.

Log File Generation: Any high bandwidth warnings or critical intrusion alerts will be printed to your console and automatically recorded into a log file named network_security_alerts.log in the same directory.

Stopping the Program: You can safely stop the detector at any time by pressing Ctrl + C.
