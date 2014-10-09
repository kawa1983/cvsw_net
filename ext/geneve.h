/*
 * geneve.h : Geneve related definition
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

#ifndef __CVSW_EXT_GENEVE_H_INCLUDED__
#define __CVSW_EXT_GENEVE_H_INCLUDED__

#define GENEVE_PORT         6081

#define GENEVE_HDR_LEN      8

#define GENEVE_HEADROOM_LEN 50

#define GENEVE_VNI_MASK     0xFFFFFF00

#define GENEVE_VNI_SHIFT    8

#define GENEVE_VERSION      0


struct genevehdr
{
#ifdef __LITTLE_ENDIAN_BITFIELD
    __u16  opt_len:   6,
           version:   2,
           reserved0: 6,
           critical:  1,
           oam:       1;
#else
    __u16  version:   2,
           opt_len:   6,
           oam:       1,
           critical:  1,
           reserved0: 6;
#endif
    __be16 type;
    __be32 vni:       24,
	   reserved1: 8;
} __attribute__ ((packed));


struct sk_buff;
struct inst_geneve;
extern void cvsw_apply_set_geneve(struct sk_buff *skb, const struct inst_geneve *geneve);
extern bool cvsw_apply_strip_geneve(struct sk_buff *skb);

#endif /* __CVSW_EXT_GENEVE_H_INCLUDED__ */
