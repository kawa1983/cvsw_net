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
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/sclp.h>
#include "ext/vxlan.h"
#include "ext/nvgre.h"
#include "ext/stt.h"
#include "ext/geneve.h"
#include "ext/vxlan_sclp.h"

#define CVSW_INST_TYPE_DROP             0x01
#define CVSW_INST_TYPE_OUTPUT           0x02
#define CVSW_INST_TYPE_SET_VLAN_VID     0x11
#define CVSW_INST_TYPE_SET_VLAN_PCP     0x12
#define CVSW_INST_TYPE_STRIP_VLAN       0x13
#define CVSW_INST_TYPE_SET_DL_DST       0x21
#define CVSW_INST_TYPE_SET_DL_SRC       0x22
#define CVSW_INST_TYPE_SET_NW_DST       0x31
#define CVSW_INST_TYPE_SET_NW_SRC       0x32
#define CVSW_INST_TYPE_SET_NW_TOS       0x33
#define CVSW_INST_TYPE_SET_TP_DST       0x41
#define CVSW_INST_TYPE_SET_TP_SRC       0x42
#define CVSW_INST_TYPE_SET_VXLAN        0x81
#define CVSW_INST_TYPE_STRIP_VXLAN      0x82
#define CVSW_INST_TYPE_SET_NVGRE        0x83
#define CVSW_INST_TYPE_STRIP_NVGRE      0x84
#define CVSW_INST_TYPE_SET_STT          0x85
#define CVSW_INST_TYPE_STRIP_STT        0x86
#define CVSW_INST_TYPE_SET_GENEVE       0x87
#define CVSW_INST_TYPE_STRIP_GENEVE     0x88
#define CVSW_INST_TYPE_SET_VXLAN_SCLP   0x89
#define CVSW_INST_TYPE_STRIP_VXLAN_SCLP 0x8A

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
    __u32 tun_id;
};

struct inst_tunnel
{
    struct ethhdr   ether;
    struct iphdr    ip;
} __attribute__ ((packed));

struct inst_vxlan
{
    struct ethhdr   ether;
    struct iphdr    ip;
    struct udphdr   udp;
    struct vxlanhdr vxlan;
} __attribute__ ((packed));

struct inst_nvgre
{
    struct ethhdr   ether;
    struct iphdr    ip;
    struct nvgrehdr nvgre;
} __attribute__ ((packed));

struct inst_stt
{
    struct ethhdr   ether;
    struct iphdr    ip;
    struct ptcphdr  ptcp;
    struct stthdr   stt;
} __attribute__ ((packed));

struct inst_geneve
{
    struct ethhdr    ether;
    struct iphdr     ip;
    struct udphdr    udp;
    struct genevehdr geneve;
} __attribute__ ((packed));

struct inst_vxlan_sclp
{
    struct ethhdr   ether;
    struct iphdr    ip;
    struct sclphdr  sclp;
    struct vxlanhdr vxlan;
} __attribute__ ((packed));

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
	struct inst_vxlan      tun_vxlan;
	struct inst_nvgre      tun_nvgre;
	struct inst_stt        tun_stt;
	struct inst_geneve     tun_geneve;
	struct inst_vxlan_sclp tun_vxlan_sclp;
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
