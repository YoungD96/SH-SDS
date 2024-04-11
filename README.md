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
![main interface](https://github.com/YoungD96/SH-SDS/tree/main/UI/main.png)
6. The detection result is shown as the follow figure.  
![operation interface](https://github.com/YoungD96/SH-SDS/tree/main/UI/operation.png)
* Click the 'Export' ("导出") button to output the results in xlsx format.
* Click the 'Back' ("返回") button to return to the main interface.

Experiments
==================
1. Add '#' in front of different user in '/etc/passwd', testing user management.
2. Edit the 'PASS_MIN_LEN' in '/etc/login.defs', testing the restriction of password length.
3. Edit 'dcredit', 'ucredit', 'lcredit', 'ocredit' separately, testing the restrition of password composition.
4. Edit 'PASS_MAX_DAYS' in '/etc/login.defs', testing the restrition of the updating cycle of password.
5. 


Appendix
==========
SH-SDS-GUI: The software with interface.  
Others: Source code of SH-SDS.

Citation
========
A related paper is submitted to PeerJ Computer Science.
