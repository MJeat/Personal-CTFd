# SSH Communication 

First, make sure both Virtual Machines are on the same network. Preferably, Bridge Network.
Second, ping each other's IP address. Make sure both machines respond to each other's requests.

# From Machine B (Docker Instance Host)
```
sudo apt update
sudo apt install openssh-server openssh-client -y
sudo systemctl enable --now ssh
sudo systemctl status ssh
```

You need to zip the ctfd-certs/ folder
```
zip -r ctfd-certs .
```
## Transfer
```
scp ctfd-certs.zip {Machine-Username}@{CTFd-Host-IP}:/home/ubun
```
Example: ```scp ctfd-certs.zip ubun@192.168.100.84:/home/ubun ```

# From Machine A (CTFd Host)
You should see a zip file in /home/ubun

```
unzip ctfd-certs.zip
```
