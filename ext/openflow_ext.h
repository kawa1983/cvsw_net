/*
 * openflow_ext.h : OpenFlow extension for tunnel
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

#ifndef __CVSW_OFP_EXT_H_INCLUDED__
#define __CVSW_OFP_EXT_H_INCLUDED__

#include "../openflow.h"

enum ofp_ext_flow_wildcards {
    OFPFW_EXT_TUN_VXLAN_VNI      = 1 << 16,
    OFPFW_EXT_TUN_NVGRE_VSID     = 1 << 17,
    OFPFW_EXT_TUN_STT_CID        = 1 << 18,
    OFPFW_EXT_TUN_GENEVE_VNI     = 1 << 19,
    OFPFW_EXT_TUN_VXLAN_SCLP_VNI = 1 << 20,
};

enum ofp_ext_action_type {
    OFPAT_EXT_SET_VXLAN          = 0x1001,
    OFPAT_EXT_STRIP_VXLAN        = 0x1002,
    OFPAT_EXT_SET_NVGRE          = 0x1003,
    OFPAT_EXT_STRIP_NVGRE        = 0x1004,
    OFPAT_EXT_SET_STT            = 0x1005,
    OFPAT_EXT_STRIP_STT          = 0x1006,
    OFPAT_EXT_SET_GENEVE         = 0x1007,
    OFPAT_EXT_STRIP_GENEVE       = 0x1008,
    OFPAT_EXT_SET_VXLAN_SCLP     = 0x1009,
    OFPAT_EXT_STRIP_VXLAN_SCLP   = 0x100A,
};

struct ofp_ext_action_tunnel {
    __u16 type;
    __u16 len;
    __u8  dl_dest[ETH_ALEN];
    __u8  dl_src[ETH_ALEN];
    __u8  nw_dest[16];
    __u8  nw_src[16];
    __u64 tun_id;
    __u8  pad[8];
};
OFP_ASSERT(sizeof(struct ofp_ext_action_tunnel) == 64);

struct ofp_ext_action_vxlan {
    __u16 type;
    __u16 len;
    __u8  dl_dest[ETH_ALEN];
    __u8  dl_src[ETH_ALEN];
    __u8  nw_dest[16];
    __u8  nw_src[16];
    __u8  pad[4];
    __u32 vxlan_vni;
    __u8  pad2[8];
};
OFP_ASSERT(sizeof(struct ofp_ext_action_vxlan) == 64);

struct ofp_ext_action_nvgre {
    __u16 type;
    __u16 len;
    __u8  dl_dest[ETH_ALEN];
    __u8  dl_src[ETH_ALEN];
    __u8  nw_dest[16];
    __u8  nw_src[16];
    __u8  pad[4];
    __u32 vsid;
    __u8  pad2[8];
};
OFP_ASSERT(sizeof(struct ofp_ext_action_nvgre) == 64);

struct ofp_ext_action_stt {
    __u16 type;
    __u16 len;
    __u8  dl_dest[ETH_ALEN];
    __u8  dl_src[ETH_ALEN];
    __u8  nw_dest[16];
    __u8  nw_src[16];
    __u64 context_id;
    __u8  pad[8];
};
OFP_ASSERT(sizeof(struct ofp_ext_action_stt) == 64);

struct ofp_ext_action_geneve {
    __u16 type;
    __u16 len;
    __u8  dl_dest[ETH_ALEN];
    __u8  dl_src[ETH_ALEN];
    __u8  nw_dest[16];
    __u8  nw_src[16];
    __u8  pad[4];
    __u32 geneve_vni;
    __u8  pad2[8];
};
OFP_ASSERT(sizeof(struct ofp_ext_action_geneve) == 64);

struct ofp_ext_action_vxlan_sclp {
    __u16 type;
    __u16 len;
    __u8  dl_dest[ETH_ALEN];
    __u8  dl_src[ETH_ALEN];
    __u8  nw_dest[16];
    __u8  nw_src[16];
    __u8  pad[4];
    __u32 vxlan_sclp_vni;
    __u8  pad2[8];
};
OFP_ASSERT(sizeof(struct ofp_ext_action_vxlan_sclp) == 64);

#endif /* __CVSW_OFP_EXT_H_INCLUDED__ */
