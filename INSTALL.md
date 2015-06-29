## How to build and install CVSW       


This document describes the way of building and installing the CVSW 
kernel module into Linux based virtual machine environment.


### 1. Getting source code of CVSW

You can download the code from GitHub repository.

    https://github.com/sdnnit/cvsw_net



### 2. Building CVSW kernel module

To build the module, you can simply use make system.

```sh
$ make
```

If the building process successes, 'cvsw-net.ko' file is created in the current directory.



### 3. Installing CVSW kernel module

Before installation, the existing network driver has to be unloaded.

```sh
# rmmod virtio_net
# insmod cvsw-net.ko [cvsw=<1|0>, tun=<1|0>]
```
The CVSW module supports some optional parameters as follows.

* cvsw: 
 * 1: All CVSW features are enabled (default)
 * 0: disabled

* tun: (cvsw-nvo3 branch only)
 * 1: Modified tun/tap device is used for VXLAN, NVGRE, and Geneve tunneling
 * 0: Original device is used (default)



### 4. Building CVSW test kernel module

CVSW test module supports pre-installed flow entries. You have to prepare 'entry.c' file before the make.

```sh
$ cd test
$ ln -s entries/<test entry file> entry.c
$ make
```
