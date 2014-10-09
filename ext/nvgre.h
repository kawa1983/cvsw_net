/*
 * nvgre.h : NVGRE related definition
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

#ifndef __CVSW_EXT_NVGRE_H_INCLUDED__
#define __CVSW_EXT_NVGRE_H_INCLUDED__

#ifndef IPPROTO_GRE
#define IPPROTO_GRE         47
#endif

#ifndef NEXTHDR_GRE
#define NEXTHDR_GRE         47
#endif


#define NVGRE_HDR_LEN       8

#define NVGRE_HEADROOM_LEN  42

#define NVGRE_VSID_MASK     0xFFFFFF00

#define NVGRE_VSID_SHIFT    8


struct nvgrehdr
{
#ifdef __LITTLE_ENDIAN_BITFIELD
    __u16 reserved0: 4,
	  S:         1,
	  K:         1,
	  Z:         1,
	  C:         1,
	  version:   3,
	  reserved1: 5;
#else
    __u16 C:         1,
	  Z:         1,
	  K:         1,
	  S:         1,
	  reserved0: 4,
	  reserved1: 5,
	  version:   3;
#endif
    __be16 type;
    __be32 vsid:     24,
	   flowid:   8;
} __attribute__ ((packed));


struct sk_buff;
struct inst_nvgre;
extern void cvsw_apply_set_nvgre(struct sk_buff *skb, const struct inst_nvgre *nvgre);
extern bool cvsw_apply_strip_nvgre(struct sk_buff *skb);

#endif /* __CVSW_EXT_NVGRE_H_INCLUDED__ */
