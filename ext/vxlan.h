/*
 * vxlan.h : VXLAN related definition
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

#ifndef __CVSW_EXT_VXLAN_H_INCLUDED__
#define __CVSW_EXT_VXLAN_H_INCLUDED__

#define VXLAN_PORT          4789

#define VXLAN_HDR_LEN       8

#define VXLAN_HEADROOM_LEN  50

#define VXLAN_FLAGS_HAS_VNI 0x08

#define VXLAN_VNI_MASK      0xFFFFFF00

#define VXLAN_VNI_SHIFT     8

struct vxlanhdr
{
    __u8   flags;
    __u8   reserved1[3];
    __be32 vni:      24,
           reserved: 8;
} __attribute__ ((packed));


struct sk_buff;
struct inst_vxlan;
extern void cvsw_apply_set_vxlan(struct sk_buff *skb, const struct inst_vxlan *vxlan);
extern bool cvsw_apply_strip_vxlan(struct sk_buff *skb);

#endif /* __CVSW_EXT_VXLAN_H_INCLUDED__ */
