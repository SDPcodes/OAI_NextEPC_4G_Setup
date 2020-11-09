# OAI_NextEPC_4G_Setup

 
Table of Contents
`1.	Preparing the environment	2
`2.	Prepare the EPC with NextEPC	3
```2.1.	NextEPC Installation	3
```2.2.	NextEPC Configuration	4
``````2.2.1.	Network Settings	4
``````2.2.2.	LTE Settings	6
``````2.2.3.	Add a UE	6
`3.	Setup OAI eNB	8
```3.1.	Setup of the Configuration files	8
```3.2.	The eNB Configuration file	8
```3.3.	Build the eNB	9
```3.4.	Start the eNB	10
`4.	Setup OAI UE	10
```4.1.	Setup of the USIM information in UE folder	10
```4.2.	The UE Configuration file	11
```4.3.	Build the UE	12
```4.4.	Initialize the NAS UE Layer	12
```4.5.	Start the UE	12
`5.	Test with ping	13

Appendix A	14
Appendix B	16

 
Build your own simulated LTE Network with NextEPC and OpenAirInterface5G
This document was prepared based on the following links.
•	NextEPC Setup: https://nextepc.org/installation/ 
•	OAI eNB/UE Setup: https://gitlab.eurecom.fr/oai/openairinterface5g/-/wikis/l2-nfapi-simulator/l2-nfapi-simulator-w-S1-same-machine

1.	Preparing the environment
Three Virtual Machines were used in this deployment.  
(This can be tested on the VMs created on personnel PC via any Hypervisor software like VirtualBox / VMWare. See Appendix A for creating VMs via virtual box.)
•	Machine A contains the EPC.
•	Machine B contains the OAI eNB 
•	Machine C contains the OAI UE(s)
 
Note that the IP addresses are indicative and need to be adapted to your environment.



EPC and Components 
•	MME (Mobility Management Entity)
In charge of all the control plane functions related to subscriber and session management. In that perspective MME supports the following. 
	Security procedures – End user authentication as well as initiation and negotiation of ciphering and integrity protection algorithms.

	Terminal to network session handling - Relates to all the signaling procedures used to set up Packet Data context and negotiate associated parameters like the Quality of Service.

	Idle terminal location management - Relates to the tracking area update process used in order for the network to be able to join terminals in case of incoming sessions.

•	HSS (Home Subscriber Server) 
Concatenation of the HLR (Home Location Register) and the AuC (Authentication Center). 
HLR: Storing and updating user subscription information (IMSI, MSISDN, QoS Information, service subscription states)
AuC: Generating security information from user identity keys to use in mutual network-terminal authentication and to ensure data and signaling transmitted between the network and the terminal is neither eavesdropped nor altered.
•	Serving Gateway (S-GW) 
Termination point of the packet data interface towards E-UTRAN. The main function is routing and forwarding of user data packets. It is also responsible for inter eNB handovers in the U-plane and provide mobility between LTE and other type of networks (2G/3G) and P-GW. 
•	PDN Gateway (P-GW)
This is the connecting node between UEs and external networks. It is the entry point of data traffic for UEs. In order to access multiple PDNs UEs can connect to several PGWs at the same time. The functions of the PGW include policy enforcement, packet filtering, charging support, lawful interception, and packet screening. Another important role of the PGW is to provide mobility between 3GPP and non-3GPP networks.
•	Policy and Charging Rules Functions (PCRF)
The network entity where the policy decisions are made. This manages the service policy and sends QoS setting information for each user session and accounting rule information. It provides,
	The ability to manage network and subscriber policy in real time. 
	Key input to revenue assurance and bandwidth management 
The ability to efficiently and dynamically route and prioritize network traffic.
2.	Prepare the EPC with NextEPC
NextEPC can be installed using package manager or directly building the source code from git.
For this tutorial it has been used NextEPC with package manager in Ubuntu 18.04. 
Please find the detailed installation guide on https://nextepc.org/installation/ which includes installation instructions for other Operating Systems also. 
2.1.	NextEPC Installation
This section explains how to install NextEPC using the package manager apt. 
(You can use any SSH Clint (Eg:Putty) or directly log into the machine and use a terminal to execute below steps.)
•	Install NextEPC
Install NextEPC daemons which consist of nextepc-mmed, nextepc-sgwd, nextepc-pgwd, nextepc-hssd, and nextepc-pcrfd:
sudo apt-get update
sudo apt-get -y install software-properties-common
sudo add-apt-repository ppa:nextepc/nextepc
sudo apt-get update
sudo apt-get -y install nextepc
•	Install Web user interface
Install Web User Interface (WebUI) which supports the user subscription management:
sudo apt-get -y install curl
curl -sL https://deb.nodesource.com/setup_10.x | sudo -E bash -
curl -sL https://nextepc.org/static/webui/install | sudo -E bash -
•	Verify the installation
After the installation NextEPC daemons should be automatically started. Check the status with below commands.
NextEPC daemons are registered in systemd environment:
sudo systemctl status nextepc-mmed
● nextepc-mmed.service - NextEPC MME Daemon
   Loaded: loaded (/lib/systemd/system/nextepc-mmed.service; enabled; vendor preset: enabled)
   Active: active (running) since Thu 2019-02-21 19:29:43 MST; 27s ago
   ...

Check the status of the other daemons also.

sudo systemctl status nextepc-sgwd
   ...
sudo systemctl status nextepc-pgwd
   ...
sudo systemctl status nextepc-hssd
   ...
sudo systemctl status nextepc-pcrfd
   ...
•	Verify the tunnel interface creation
A virtual network interface, pgwtun, is also created:
ifconfig pgwtun
pgwtun    Link encap:UNSPEC  HWaddr 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  
          inet addr:45.45.0.1  P-t-P:45.45.0.1  Mask:255.255.0.0
          inet6 addr: fe80::50f6:182c:5aa3:16bb/64 Scope:Link
          inet6 addr: cafe::1/64 Scope:Global
          ...
2.2.	NextEPC Configuration 
•	When NextEPC is installed via the package manager mme.conf, sgw.conf, pgw.conf, hss.conf, and pcrf.conf should be modifed for the configuration. 
•	When NextEPC is installed via building the source code form the git, NextEPC shul be run with nextepc-epcd which is the daemon launching all necessary daemons automatically. Then all the required configuration should be done in nextepc.conf file.
•	When NextEPC is installed with package manager below file are created.
/etc/nextepc/ 
mme.conf           // nextepc-mmed
sgw.conf           // nextepc-sgwd
pgw.conf           // nextepc-pgwd
hss.conf           // nextepc-hssd
pcrf.conf          // nextepc-pcrfd


2.2.1.	Network Settings

IP Connectivity between Network Entities
The minimum requirement of having IP connectivity is to modify the configuration files of MME and SGW.
•	Modification of MME config
Open the file /etc/nextepc/mme.conf, with your favorite editor
sudo vim /etc/nextepc/mme.conf
(If vim is not intlled on your machine it can be instlled with sudo apt-get -t install vim)
Find the place mme → s1ap. Please set your IP address after addr: keyword:
(IP of your outgoing network – can be obtained with ifconfig command)

mme:
    freeDiameter: mme.conf
    s1ap:
      addr: <IP address>     
...

(Here <IP address> is 192.168.88.188, find your own one with ifconfig)

•	Modification of SGW config
In /etc/nextepc/sgw.conf, go to sgw → gtpu. Please set your IP address after addr: keyword.
sgw:
    gtpc:
      addr: 127.0.0.2
    gtpu:
      addr: <IP address>
...
(Here <IP address> is 192.168.88.188, find your own one with ifconfig)

•	Internet Access for UEs
First, please make sure that ip_forwarding = 1:
sysctl net.ipv4.ip_forward
net.ipv4.ip_forward = 0

sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
Second, either method A or B is required for UEs to have Internet connectivity.
•	Adding a route on the gateway router
By default, a LTE UE will receive a IP address with the network address of 45.45.0.0/16. If you have a NAT router (e.g., wireless router, cable modem, etc), the LTE UE can reach Internet in uplink, but it cannot in downlink. It's because the NAT router has no idea on 45.45.0.0/16, so adding a route is required. The following example shows adding two routes for 45.45.0.0/16 and cafe::0/64 in Linux:
sudo ip route add 45.45.0.0/16 via <'PGW IP address'>
sudo ip route add cafe::0/64 via <'PGW IP address'>

(Here <'PGW IP address'> is 192.168.88.188, find your own outgoing network IP with ifconfig)

•	B. NAT on PGW
NAT can be done on NextEPC's PGW. You execute the following command in PGW installed host. Please check your outgoing network interface name (e.g enp0s25, wls3):
sudo iptables -t nat -A POSTROUTING -o <'interface-name'> -j MASQUERADE
sudo iptables -I INPUT -i pgwtun -j ACCEPT


2.2.2.	LTE Settings
•	PLMN and TAC
PLMN (Public Land Mobile Network) consists of a MCC (Mobile Country Code) and MNC (Mobile Network Code), which is a five- or six-digit number identifying a country and a mobile network operator. TAC (Tracking Area Code) represents a geographical area of the network, the eNodeBs located in TAC are only accepted by the MME. In /etc/nextepc/mme.conf, please modify PLMN and TAC in mme → gummei and tai:
mme:
    gummei: 
      plmn_id:
        mcc: 001
        mnc: 01
      mme_gid: 2
      mme_code: 1
    tai:
      plmn_id:
        mcc: 001
        mnc: 01
      tac: 12345
•	Restarting NextEPC daemons.
After changing config files, please restart NextEPC daemons.
sudo systemctl restart nextepc-mmed
sudo systemctl restart nextepc-pgwd
sudo systemctl restart nextepc-sgwd
sudo systemctl restart nextepc-hssd
sudo systemctl restart nextepc-pcrfd
2.2.3.	Add a UE
Please note that nextepc.conf is used only if NextEPC is executed through nextepc-epcd. Otherwise, mme.conf, sgw.conf, pgw.conf, hss.conf, and pcrf.conf should be modifed for the configuration. 
Register a UE information
Open http://localhost:3000. Login with admin. Later, you can change the password in Account Menu.
  - Username : admin
  - Password : 1423
Using Web UI, you can add a subscriber without a Mongo DB client. 
  - Go to Subscriber Menu.
  - Click `+` Button to add a new subscriber.
  - Fill the IMSI, security context(K, OPc, AMF), and APN of the subscriber.
  - Click `SAVE` Button
This addition is applied immediately without restarting any NextEPC daemon.

 
3.	Setup OAI eNB
Connect to machine B with any SSH Client (Putty) or directly log into the VM and execute below steps.
$ cd /opt
$ git clone https://gitlab.eurecom.fr/oai/openairinterface5g/ enb_folder
$ cd enb_folder
$ git checkout -f v1.0.0
3.1.	Setup of the Configuration files
CAUTION: both proposed configuration files resides in the ci-scripts realm. You can copy them, but you CANNOT push any modification on these 2 files as part of an MR without informing the CI team.
3.2.	The eNB Configuration file
$ cd /opt/enb_folder
# Edit ci-scripts/conf_files/rcc.band7.tm1.nfapi.conf with your preferred editor
$ sudo vim ci-scripts/conf_files/rcc.band7.tm1.nfapi.conf

MACRLCs = (
        {
        num_cc = 1;
        local_s_if_name  = "lo:";          // <-- interface name here eg.enp0s3
        remote_s_address = "127.0.0.1";    // <-- UE(Machine C) 192.168.88.180
        local_s_address  = "127.0.0.2";    // <-- eNB(Machine B) 192.168.88.185
        local_s_portc    = 50001;
        remote_s_portc   = 50000;
        local_s_portd    = 50011;
        remote_s_portd   = 50010;
        tr_s_preference = "nfapi";
        tr_n_preference = "local_RRC";
        }
);
If you are testing more than 16 UEs, a proper setting on the RUs is necessary. Note that this part is NOT present in the original configuration file.
RUs = (
    {
       local_rf       = "yes"
         nb_tx          = 1
         nb_rx          = 1
         att_tx         = 20
         att_rx         = 0;
         bands          = [38];
         max_pdschReferenceSignalPower = -23;
         max_rxgain                    = 116;
         eNB_instances  = [0];
    }
);
The S1 interface shall be properly set.
    ////////// MME parameters:
    mme_ip_address      = ( { ipv4       = "CI_MME_IP_ADDR"; 
// replace with NextEPC mme 192.168.88.188
                              ipv6       = "192:168:30::17";
                              active     = "yes";
                              preference = "ipv4";
                            }
                          );

    NETWORK_INTERFACES :
    {
        ENB_INTERFACE_NAME_FOR_S1_MME            = "enp0s3";            
// replace with the proper interface name
        ENB_IPV4_ADDRESS_FOR_S1_MME              = "CI_ENB_IP_ADDR";  
// replace with your eNB IP, here 192.168.88.185
        ENB_INTERFACE_NAME_FOR_S1U               = "enp0s3";            
// replace with the proper interface name
        ENB_IPV4_ADDRESS_FOR_S1U                 = "CI_ENB_IP_ADDR";  
// replace with your eNB IP, here 192.168.88.185
        ENB_PORT_FOR_S1U                         = 2152; # Spec 2152
        ENB_IPV4_ADDRESS_FOR_X2C                 = "CI_ENB_IP_ADDR";  
// replace with your eNB IP, here 192.168.88.185
        ENB_PORT_FOR_X2C                         = 36422; # Spec 36422

    };


Last, configure the PLMN and TAC to match with NextEPC configuration. (mme.conf)

  // Tracking area code, 0x0000 and 0xfffe are reserved values
    tracking_area_code = 12345;

    plmn_list = ( { mcc = 001; mnc = 01; mnc_length = 2; } );


(Refer Appendix B for clarifications)


3.3.	Build the eNB
$ cd /opt/enb_folder
$ source oaienv
$ cd cmake_targets
# If you test less than 16 UEs, type below command.
$ ./build_oai --eNB -t ETHERNET -c
# If you test more than 16 UEs, type below command and this command also can be used in case of less than 16 UEs.
$ ./build_oai --eNB -t ETHERNET -c –mu

Note: For the first time build include the -I option which install all the required packeges. Build might take considerable time depending on your server performance and internet connectivity.
$ ./build_oai --eNB -I -t ETHERNET -c


3.4.	Start the eNB
$ cd /opt/enb_folder/cmake_targets
$ sudo -E ./lte_build_oai/build/lte-softmodem -O ../ci-scripts/conf_files/rcc.band7.tm1.nfapi.conf > enb.log 2>&1
If you don't use redirection, you can test but many logs are printed on the console and this may affect performance of the L2-nFAPI simulator.
We do recommend the redirection in steady mode once your setup is correct.
Tail the log to check everything goes well
$ tail -100f enb.log 
(Ctrl+c to quit the log)

4.	Setup OAI UE 
Connect to machine B with any SSH Client (Putty) or directly log into the VM and execute below steps.
ssh sudousername@machineC
$ cd /opt
$ git clone https://gitlab.eurecom.fr/oai/openairinterface5g/ ue_folder
$ cd ue_folder
$ git checkout -f v1.0.0


4.1.	Setup of the USIM information in UE folder
$ cd /opt/ue_folder
# Edit openair3/NAS/TOOLS/ue_eurecom_test_sfr.conf with your preferred editor
$ sudo vim openair3/NAS/TOOLS/ue_eurecom_test_sfr.conf
Edit the USIM information within this file in order to match the HSS database. They HAVE TO match:
•	PLMN+MSIN and IMSI of users table of HSS database SHALL be the same.
•	OPC of this file and OPC of users table of HSS database SHALL be the same.
•	USIM_API_K of this file and the key of users table of HSS database SHALL be the same.
(Refer Appendix B for more clarification.)
When testing multiple UEs, it is necessary to add other UEs information like described below for 2 Users. Only UE0 (first UE) information is written in the original file.
 
UE0:
{
    USER: {
        IMEI="356113022094149";
        MANUFACTURER="EURECOM";
        MODEL="LTE Android PC";
        PIN="0000";
    };

    SIM: {
        MSIN="0000000001";  // <-- Modify here
        USIM_API_K="8baf473f2f8fd09487cccbd7097c6862"; 
        OPC="e734f8734007d6c5ce7a0508809e7e9c";
        MSISDN="33611123456";
    };
...
};
// If need another UE copy the UE0 and edit
UE1: // <- Edit here
{
    USER: {
        IMEI="356113022094149";
        MANUFACTURER="EURECOM";
        MODEL="LTE Android PC";
        PIN="0000";
    };

    SIM: {
        MSIN="0000000002";  // <-- Modify here
        USIM_API_K="8baf473f2f8fd09487cccbd7097c6862";
        OPC="e734f8734007d6c5ce7a0508809e7e9c";
        MSISDN="33611123456";
    };
...
};
You can repeat the operation for as many users you want to test with.
4.2.	The UE Configuration file
$ cd /opt/ue_folder
# Edit ci-scripts/conf_files/ue.nfapi.conf with your preferred editor
Verify the nFAPI interface setup on the loopback interface. 
L1s = (
        {
        num_cc = 1;
        tr_n_preference = "nfapi";
        local_n_if_name  = "lo";         // <-- interface name here eg.enp0s3
        remote_n_address = "127.0.0.2";  // <- eNB(Machine B) 192.168.88.185
        local_n_address  = "127.0.0.1";  // <- UE(Machine C) 192.168.88.180
        local_n_portc    = 50000;
        remote_n_portc   = 50001;
        local_n_portd    = 50010;
        remote_n_portd   = 50011;
        }
);
4.3.	Build the UE
$ cd /opt/ue_folder
$ source oaienv
$ cd cmake_targets
# If you test less than 16 UEs, type below command.
$ ./build_oai --UE -t ETHERNET -c
# If you test more than 16 UEs, type below command and this command also can be used in case of less than 16 UEs.
$ ./build_oai --UE  -x -t ETHERNET -c --musim
After finishing building UE(s), some files are generated in ue_folder/targets/bin/ and these files are necessary in cmake_targets.
$ ssh sudousername@machineB
$ cd ue_folder/targets/bin/
$ cp .u* ../../cmake_targets/
$ cp usim ../../cmake_targets/
$ cp nvram ../../cmake_targets/
4.4.	Initialize the NAS UE Layer
$ ssh sudousername@machineB
$ cd ue_folder/cmake_targets/tools
$ source init_nas_s1 UE
And start the NextEPC on machine A.
$ ssh sudousername@machineA
# Start the EPC
4.5.	Start the UE
Important information: in an earlier version, it has been recommended to start as many UE threads as UEs present in the simulator. This is not recommended anymore, since multiple threads will execute the higher layers at the same time, leading to races and segfaults. Instead, you should only start one thread using the switch --nums_ue_thread 1 or leave it out as below since 1 is the default.
$ cd /opt/ue_folder/cmake_targets
# Test 64 UEs, 64 threads in FDD mode
$ sudo -E ./lte_build_oai/build/lte-uesoftmodem -O ../ci-scripts/conf_files/ue.nfapi.conf --L2-emul 3 --num-ues 64 > ue.log 2>&1
# Test 64 UEs, 64 threads in TDD mode
$ sudo -E ./lte_build_oai/build/lte-uesoftmodem -O ../ci-scripts/conf_files/ue.nfapi.conf --L2-emul 3 --num-ues 64 -T 1 > ue.log 2>&1
# The "-T 1" option means TDD config
•	The number of UEs can set by using --num-ues option and the maximum UE number is 255 (with the --mu* options, otherwise 16).
•	How many UE that can be tested depends on hardware (server , PC, etc) performance in your environment.

5.	Test with ping
In UE machine, in a terminal type ifconfig command find the interface names and IPs assigned for the UE devices.
If UE is successfully attached to eNB, oip0(or oip1/oaitun_ue1) interface should be assigned with the IP address given by the MME from which the ue_pool defined the pgw.conf file. 
(ip address show oip0)
When UE(s) are connected to the eNB test the setup.
Ping from machine A – EPC 
# Ping UE0 IP address based on the EPC pool used: in this example:
$ ping -c 20 45.45.0.3

Ping from machine C - UE 
Ping to any public IP/Google via UE oip0 interface
ping -I oip0 8.8.8.8 


•	Observe the traffic with Wireshark

 

 
Appendix A
•	Setup the environment with Virtual Machines created via VirtualBox. (You can use VMWare or any Hypervisor software)
•	Download and install VirtualBox :  https://www.virtualbox.org/wiki/Downloads
•	Find the Ubuntu 18.04 VirtualBox image (or your preferred OS image going to be used with NextEPC/ eNB/ UE Setup) : https://www.linuxvmimages.com/images/ubuntu-1804/
•	Import the image to VirtualBox.
 
•	Browse for the downloaded image. (In ova format)
 
 
•	Follow the next steps as suggested thorough the wizard.
•	It would be listed in left panel of the VirtualBox. 
•	Select the image and you can change the settings Name/Network/Memory/CPU etc. accordingly. 

 
 
Appendix B
 
In mme.conf
mme:
    gummei: 
      plmn_id:
        mcc: 001
        mnc: 01
      mme_gid: 2
      mme_code: 1
    tai:
      plmn_id:
        mcc: 001
        mnc: 01
      tac: 12345

In UE Configuration,
PLMN = 00101
MSIN= 0000000001

In eNB Configuration,
    tracking_area_code = 12345;

    plmn_list = ( { mcc = 001; mnc = 01; mnc_length = 2; } );
