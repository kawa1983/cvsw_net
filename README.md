## Co-Virtual Switch (CVSW) for SDN-enabled virtual networks


### Overview

CVSW is a vNIC driver designed for offloading packet processing of 
high functional virtual switches. CVSW enables per-VM packet processing, 
which reduces the load and simplifies the flow table of the virtual 
switch. CVSW's functionality can be managed by OpenFlow controllers or 
command-line shells. Here, supported functions are listed as follows:

* Para-virtualized network driver (virtio-net)
* OpenFlow 1.0 Match-Action
* MTU size setting
* Offload  setting
* VXLAN, NVGRE, STT, Geneve, and VXLAN over SCLP tunneling (cvsw-nvo3 branch)


=
### Branches

* cvsw-nvo3       : Supports VXLAN, NVGRE, STT, Geneve, and VXLAN over SCLP tunnels


=
### Files & Directories

* cvsw_net.h      : CVSW message definition

* openflow.h      : OpenFlow message definition

* cvsw_ctl.c      : CVSW message handling

* cvsw_table.c    : OpenFlow table management

* cvsw_data.c     : Data plane packet processing

* skb_util.c      : SKB handling utility

* distributions/  : virtio_net files for each distribution

* compat/         : Kernel provided files for upper compatibility

* test/           : Test programs (pre-defined flow table)

* test/entries/   : Flow entry samples

* ext/            : Tunnel processing (cvsw-nvo3 branch)


=
### Supported distributions

Currently CVSW has been tested with KVM on the following distributions.

 * Redhat Enterprise Linux 6.5, 6.6

 * Redhat Enterprise Linux 7.0, 7.1

 * Fedora 20

 * Ubuntu 14.04


=
### Install

See 'INSTALL.md'


=
### Papers

Overview and architectural details of CVSW are described in the following 
papers.

* R. Kawashima, S. Muramatsu, H. Nakayama, T. Hayashi, and H. Matsuo, 
"SCLP: Segment-oriented Connection-Less Protocol for High-Performance 
Software Tunneling in Datacenter Networks", Proc. 1st IEEE Network 
Softwarization (NetSoft 2015), pp.1-8, London, April 2015.

* R. Kawashima and H. Matsuo, "Implementing and Performance Analysis of 
STT Tunneling using vNIC Offloading Framework (CVSW)", 
Proceedings of IEEE 6th International Conference on Cloud Computing 
Technology and Science (CloudCom 2014), pp.929-934, Singapore, Dec. 2014.

* R. Kawashima and H. Matsuo, "Virtual NIC Offloading Approach for 
Improving Performance of Virtual Networks", The Transactions of 
Institute of Electronics Information and Communication Engineers B 
(IEICE), vol.J97-B, no.8, pp.639-647, 2014 (Japanese).


=
### Contact 

Ryota Kawashima &lt;kawa1983<span>@</span>ieee.org&gt;

