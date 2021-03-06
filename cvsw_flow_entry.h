/*
 * cvsw_flow_entry.h : Flow entry structures
 * 
 * Copyright 2014 Ryota Kawashima <kawa1983@ieee.org> Nagoya Institute of Technology
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __CVSW_FLOW_ENTRY_H_INCLUDED__
#define __CVSW_FLOW_ENTRY_H_INCLUDED__

#include <linux/if_ether.h>

#define CVSW_INST_TYPE_DROP         0x01
#define CVSW_INST_TYPE_OUTPUT       0x02
#define CVSW_INST_TYPE_SET_VLAN_VID 0x11
#define CVSW_INST_TYPE_SET_VLAN_PCP 0x12
#define CVSW_INST_TYPE_STRIP_VLAN   0x13
#define CVSW_INST_TYPE_SET_DL_DST   0x21
#define CVSW_INST_TYPE_SET_DL_SRC   0x22
#define CVSW_INST_TYPE_SET_NW_DST   0x31
#define CVSW_INST_TYPE_SET_NW_SRC   0x32
#define CVSW_INST_TYPE_SET_NW_TOS   0x33
#define CVSW_INST_TYPE_SET_TP_DST   0x41
#define CVSW_INST_TYPE_SET_TP_SRC   0x42

struct cvsw_match
{
    __u32 wildcards;
    __u8  dl_src[ETH_ALEN];
    __u8  dl_dst[ETH_ALEN];
    __be16 dl_type;
    __be16 dl_vlan_vid;
    __u8  dl_vlan_pcp;
    __u8  nw_src[16];
    __u8  nw_dst[16];
    __u8  nw_tos;
    __u8  nw_proto;
    __be16 tp_src;
    __be16 tp_dst;
    __u16 in_port;
};

struct cvsw_instruction
{
    __u8 type;
    union {
	__u8  dl_addr[ETH_ALEN];
	__be16 dl_type;
	__u8  vlan_pcp;
	__be16 vlan_vid;
	__u8  nw_addr[16];
	__u8  nw_tos;
	__be16 tp_port;
	__u16 out_port;
    };
};

struct list_head;

struct cvsw_flow_entry
{
    __u16 priority;
    __u16 nr_insts;
    struct cvsw_match match;
    struct cvsw_instruction *instructions;
    struct list_head list;
};

#endif /* __CVSW_FLOW_ENTRY_H_INCLUDED__ */
