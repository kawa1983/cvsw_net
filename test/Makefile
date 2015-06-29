# Makefile for cvsw_test driver
# 
# Copyright 2014 Ryota Kawashima <kawa1983@ieee.org> Nagoya Institute of Technology
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

#ifndef DIST_DIR
  DIST_DIR:= `../dist.sh`
#endif

TARGET:= cvsw_test.ko

EXTRA_CFLAGS := -I${PWD}/../compat/include

CFILES = cvsw_test_main.c cvsw_test.c ../cvsw_ctl.c ../cvsw_data.c ../cvsw_table.c ../skb_util.c ../ext/tunnel.c ../ext/vxlan.c ../ext/nvgre.c ../ext/stt.c ../ext/geneve.c ../ext/vxlan_sclp.c entry.c

cvsw-test-objs:= $(CFILES:.c=.o)

all: ${TARGET}

cvsw_test.ko: $(CFILES)
	make -C /lib/modules/`uname -r`/build M=`pwd` V=1 modules DIST_DIR=${DIST_DIR}

clean:
	make -C /lib/modules/`uname -r`/build M=`pwd` V=1 clean

obj-m:= cvsw-test.o

cvsw_test_main.c: cvsw_test.h ../distributions/*/cvsw_net.c
	cp -f ../distributions/${DIST_DIR}/cvsw_net.c cvsw_test_main.c
	patch -u cvsw_test_main.c < distributions/${DIST_DIR}/cvsw_test_main.c.patch

entry.c: entries/cvsw_test_flow_entry.h

cvsw_test.c: cvsw_test.h entries/cvsw_test_flow_entry.h ../cvsw_ctl.h ../cvsw_flow_entry.h

cvsw_ctl.c: ../cvsw_ctl.h ../cvsw_net.h ../cvsw_table.h

cvsw_data.c: ../cvsw_data.h ../cvsw_net.h ../cvsw_table.h ../cvsw_flow_entry.h ../skb_util.h ../ext/openflow_ext.h ../ext/tunnel.h ../ext/vxlan.h ../ext/nvgre.h ../ext/stt.h ../ext/geneve.h ../ext/vxlan_sclp.h

cvsw_table.c: ../cvsw_table.h ../cvsw_net.h ../cvsw_flow_entry.h ../ext/openflow_ext.h ../ext/vxlan.h ../ext/stt.h ../ext/vxlan_sclp.h

skb_util.c: ../skb_util.h ../ext/openflow_ext.h ../ext/vxlan.h ../ext/stt.h

ext/tunnel.c: ../cvsw_flow_entry.h ../skb_util.h ../ext/tunnel.h

ext/vxlan.c: ../cvsw_flow_entry.h ../skb_util.h ../ext/tunnel.h ../ext/vxlan.h

ext/nvgre.c: ../cvsw_flow_entry.h ../skb_util.h ../ext/tunnel.h ../ext/nvgre.h

ext/stt.c: ../cvsw_flow_entry.h ../skb_util.h ../ext/tunnel.h ../ext/stt.h

ext/geneve.c: ../cvsw_flow_entry.h ../skb_util.h ../ext/tunnel.h ../ext/geneve.h

ext/vxlan_sclp.c: ../cvsw_flow_entry.h ../skb_util.h ../ext/tunnel.h ../ext/vxlan_sclp.h

clean-files := *.o ../*.o *.ko *.mod.[co] *~ cvsw_test_main.c cvsw_test_main.c.orig entry.c

