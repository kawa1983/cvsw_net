## NVO3 Tunneling


### Overview

Network Virtualization Overlay (NVO3) is a promising virtualization concept for 
SDN-enabled networks. Generally, (edge) virtual switches including Open vSwitch 
establish L2-in-L3 tunnels among them to make virtual networks share the same 
physical network resources. Here, CVSW can be used as a tunnel end point that 
performs packet encapsulation/decapsulation process. Since CVSW itself is 
an independent software component, various types of tunnel protocols can be 
supported without modifying kernel codes or vswitch codes.

Currently, CVSW supports following tunneling protocols in cvsw-nvo3 branch:

* VXLAN
* NVGRE
* STT
* Geneve



### Files & Directories (cvsw-nvo3 branch)

NVO3 related source files are listed as follows:

* ext/openflow_ext.h : Extended OpenFlow action structures for each tunnel
* ext/tunnel.h(c)    : Common tunnel processing
* ext/vxlan.h(c)     : VXLAN tunnel support
* ext/nvgre.h(c)     : NVGRE tunnel support
* ext/stt.h(c)       : STT tunnel support
* ext/geneve.h(c)    : Geneve tunnel support
* test/entries/ext   : Sample flow entries for each tunnel protocol



### TSO support

If you want TSO (TCP Segmentation Offload) feature of vNIC is enabled when VXLAN, NVGRE, 
or Geneve tunneling protocol is used, a dedicated tun/tap device should be installed instead 
of the original one. The custom tun/tap device arranges large encapsulated packets such that 
they are divided by GSO (Generic Segmentation Offload) properly before transmitting them to 
the physical network. Source code of the dedicated tun/tap device is available at GitHub.

	https://github.com/sdnnit/cvsw_tun

In addition, you have to add a loading parameter ('tun') of the CVSW module (See INSTALL.md) 
