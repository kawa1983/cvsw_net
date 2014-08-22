Co-Virtual Switch (CVSW) for SDN-enabled virtual networks


## Overview

CVSW is a vNIC driver designed for offloading packet processing of 
high functional virtual switches. CVSW enables per-VM packet processing, 
which reduces the load and simplifies the flow table of the virtual 
switch. CVSW's functionality can be managed by OpenFlow controllers or 
command-line shells. Here, supported functions are listed as follows:

* Para-virtualized network driver (virtio-net)
* OpenFlow 1.0 Match-Action
* MTU size setting
* GSO and H/W checksum setting
* VXLAN and STT tunneling (cvsw-nvo3 branch)


## Branches

* cvsw-nvo3       : Supports VXLAN and STT tunnels


## Files & Directories

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


## Supported distributions

Currently CVSW has been tested with KVM on the following distributions.

* Redhat Enterprise Linux 6.5

* Redhat Enterprise Linux 7.0

* Fedora 20

* Ubuntu 14.04


## Install

1. $ make

2. \# rmmod virtio_net

3. \# insmod cvsw-net.ko


### Install test modules

1. $ cd test

2. $ ln -s entries/&lt;entry file&gt; entry.c

3. $ make

4. \# rmmod virtio_net

5. \# insmod cvsw-test.ko


## Setup

TODO


## Papers

Overview and architectural details of CVSW are described in the following 
paper.

* R. Kawashima and H. Matsuo, "Virtual NIC Offloading Approach for 
Improving Performance of Virtual Networks", The Transactions of 
Institute of Electronics Information and Communication Engineers B 
(IEICE), vol. J97-B, no. 8, pp.639-647, 2014 (Japanese).


## Contact 

Ryota Kawashima &lt;kawa1983<span>@</span>nitech.ac.jp&gt;
