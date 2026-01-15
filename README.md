Hello this will be a tutorial on how to set up CTFd as well as to modify it to make it look "Good Enough"

Started Date:
27th, December 2025

Ended Date:
15th, January 2026

========================================== <br/>
I will explain each file's purpose. You need:
## [Docker-Installation.md](https://github.com/MJeat/Modified-CTFd-Framework/blob/main/Docker-Installation.md)
Learn how to set up Docker on Linux machines.

## [SSH-Communication.md](https://github.com/MJeat/Modified-CTFd-Framework/blob/main/SSH-Communication.md)
Learn how to set up SSH communication to send TLS keys from Machine B (Docker Instance Host) to Machine A (CTFd Host). You need these keys to set up dynamic instances.

## [Setting-Up-CTFd.md](https://github.com/MJeat/Modified-CTFd-Framework/blob/main/Setting-Up-CTFd.md)
This is a simple CTFd framework setup.

# [CTFd-Instance/](https://github.com/MJeat/Modified-CTFd-Framework/tree/main/CTFd-Instance)
The folder consists of:
## [CTFd-Static-Instance.md](https://github.com/MJeat/Modified-CTFd-Framework/blob/main/CTFd-Instance/CTFd-Static-Instance.md)
This covers the static and beginner instances and how the containers work. One sample web-challenge will be given to set up for testing and learning.

# [Dynamic-Instance/](https://github.com/MJeat/Modified-CTFd-Framework/tree/main/CTFd-Instance/Dynamic-Instance)
This folder will cover the modified files necessary to modify. Not to modify all files from the CTFd framework and the CTFd Docker Challenges Plugin.

## [Modified-Files](https://github.com/MJeat/Modified-CTFd-Framework/tree/main/CTFd-Instance/Dynamic-Instance/Modifed-Files)
Covers the needed modification files. Here are the files:

- [`__init__.py`](https://github.com/MJeat/Modified-CTFd-Framework/blob/main/CTFd-Instance/Dynamic-Instance/Modifed-Files/__init__.py)
- [docker-compose.yml](https://github.com/MJeat/Modified-CTFd-Framework/blob/main/CTFd-Instance/Dynamic-Instance/Modifed-Files/docker-compose.yml)
- [fixed_plugins.py](https://github.com/MJeat/Modified-CTFd-Framework/blob/main/CTFd-Instance/Dynamic-Instance/Modifed-Files/fixed_plugins.py)
- [view.html](https://github.com/MJeat/Modified-CTFd-Framework/blob/main/CTFd-Instance/Dynamic-Instance/Modifed-Files/view.html)
- [view.js](https://github.com/MJeat/Modified-CTFd-Framework/blob/main/CTFd-Instance/Dynamic-Instance/Modifed-Files/view.js)

## [CTFd-Dynamic-Instance.md](https://github.com/MJeat/Modified-CTFd-Framework/blob/main/CTFd-Instance/Dynamic-Instance/CTFd-Dynamic-Instance.md)
Learn how to set up instances to host any challenges that require links, such as web, crypto, and rev. It will mention how to set up a TLS connection for the instances to work. Most importantly, this is the part where the "Start Instance" button is covered/created. 

## [Issues-Encountered.md](https://github.com/MJeat/Modified-CTFd-Framework/blob/main/CTFd-Instance/Issues-Encountered.md)
This will cover the issue I encountered and the solutions to resolve.

## [Troubleshoot.md](https://github.com/MJeat/Modified-CTFd-Framework/blob/main/CTFd-Instance/Troubleshoot.md)
This will cover the troubleshooting or a checklist to monitor if anything goes wrong. This would be nice to check if you have no idea what's going on. 

