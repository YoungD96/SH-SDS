SH-SDS
======
SH-SDS: a new static-dynamic strategy for substation host security detection

What is SH-SDS
==============
SH-SDS conducts the network security detection of hosts and outputs the result as reports, consisting of five modules: (1) Data Generation Module, (2) Strategy Generation Module, (3) Detection Module, (4) Report Module, and (5) User Interaction Module.

Environment
===========
Operating system: Ubuntu 16.04.7, Ubuntu 22.04.1, or Kylin 3.3

Operation Guide
==================
1. Installing an operating system in PC or virtual machine.
2. Copy the SH-SDS (SH-SDS-GUI) to taget host.
3. Start a terminal.
4. Input command './SH-SDS-GUI' to run the SH-SDS.
5. The main interface of SH-SDS is shown below. Click the 'Scan' ("扫描") button to start the detection task.  
![main interface](https://github.com/YoungD96/SH-SDS/tree/main/UI/main.jpg)
6. The detection result is shown as the follow figure.  
![operation interface](https://github.com/YoungD96/SH-SDS/tree/main/UI/operation.jpg)
* Click the 'Export' ("导出") button to output the results in xlsx format.
* Click the 'Back' ("返回") button to return to the main interface.

Experiments
==================
1. Add '#' in front of different user in '/etc/passwd', testing the detection of user management.
2. Edit the value of 'PASS_MIN_LEN' in '/etc/login.defs', testing the detection of restriction of password length.
3. Edit value of 'dcredit', 'ucredit', 'lcredit', 'ocredit' separately, testing the detection of restrition of password composition.
4. Edit the value of 'PASS_MAX_DAYS' in '/etc/login.defs', testing the detection of restrition of the updating cycle of password.
5. Edit the value of 'TMOUT' in '/etc/profile', testing the detection of lock time of host.
6. Shut down ports 135, 137, 138, 139 and 3389 separately, testing the detection of ports status.
7. Shut donw services like E-Mail, FTP, telnet, rlogin, NetBIOS, DHCP, rsyslog, auditd, testing the detection of services status.
8. Edit the value of 'Port' in '/etc/ssh/sshd_config', testing the detection of ssh port.
9. Add '#' in front of 'SyslogFacility AUTH' in '/etc/ssh/sshd_config', testing the detection of ssh logs audit.
10. Edit the value of 'rotate' in '/etc/logrotate.conf', testing the detection of the retention period of audit content.
11. Edit the ip in '/etc/sysconfig/iptables', testing the detection of white list.
12. Edit the value of 'HISTSIZE' and 'HISTFILESIZE', testing the detection of 'his' command.  
...

Appendix
==========
SH-SDS-GUI: The software with interface.  
Others: Source code of SH-SDS.

Citation
========
A related paper is submitted to PeerJ Computer Science.
