# Krack-Attack


Sources:    
[https://github.com/vanhoefm/krackattacks](https://github.com/vanhoefm/krackattacks)      
[https://github.com/vanhoefm/krackattacks-scripts](https://github.com/vanhoefm/krackattacks-scripts)      
https://github.com/lucascouto/krackattack-all-zero-tk-key    
https://github.com/kristate/krackinfo    
https://github.com/fwalloe/KrackPlus   


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
