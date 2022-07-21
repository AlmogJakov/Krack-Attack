# Krack-Attack


Sources:    
[https://github.com/vanhoefm/krackattacks](https://github.com/vanhoefm/krackattacks)      
[https://github.com/vanhoefm/krackattacks-scripts](https://github.com/vanhoefm/krackattacks-scripts)      
https://github.com/lucascouto/krackattack-all-zero-tk-key    
https://github.com/kristate/krackinfo    
https://github.com/fwalloe/KrackPlus   


<b>Note! In order for the scripts to work properly, execution permission must be given to the 'hostapd' file located in the 'hostapd' folder</b>  
(for example navigate to the hostapd folder and run: sudo chmod 777 hostapd)

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
</br>
tp-link-wn821n driver:    
https://askubuntu.com/questions/879868/tp-link-wn821n-23570107-not-working
</br>
mitm-channel-based:    
https://pypi.org/project/mitm-channel-based/
</br>
pip for python2:  
https://linuxize.com/post/how-to-install-pip-on-ubuntu-18.04/


python2 -m pip install scapy==2.4.4
