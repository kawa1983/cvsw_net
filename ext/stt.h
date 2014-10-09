/*
 * stt.h : STT related definition
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

#ifndef __CVSW_EXT_STT_H_INCLUDED__
#define __CVSW_EXT_STT_H_INCLUDED__

#define STT_PORT            7471

#define STT_HDR_LEN         18

#define STT_HEADROOM_LEN    72

#define STT_VERSION         0


struct ptcphdr
{
    __be16 source;
    __be16 dest;
    __be16 len;
    __be16 offset;
    __be32 id;
#ifdef __LITTLE_ENDIAN_BITFIELD
    __u16  res1: 4,
           doff: 4,
           fin:  1,
           syn:  1,
           rst:  1,
           psh:  1,
           ack:  1,
           urg:  1,
           ece:  1,
           cwr:  1;
#else
    __u16  doff: 4,
           res1: 4,
           cwr:  1,
           ece:  1,
           urg:  1,
           ack:  1,
           psh:  1,
           rst:  1,
           syn:  1,
           fin:  1;
#endif
    __be16  window;
    __sum16 check;
    __be16  urg_ptr;
} __attribute__ ((packed));


struct stthdr
{
    __u8   version;
#ifdef __LITTLE_ENDIAN_BITFIELD
    __u8   csum_verified: 1, csum_partial: 1, ipv4: 1, tcp: 1, reserved: 4;
#else
    __u8   reserved: 4, tcp: 1, ipv4: 1, csum_partial: 1, csum_verified: 1;
#endif
    __u8   offset;
    __u8   unused;
    __be16 mss;
#ifdef __LITTLE_ENDIAN_BITFIELD
    __be16 vid: 12, v: 1, pcp: 3;
#else
    __be16 pcp: 3, v: 1, vid: 12;
#endif
    __be64 context_id;
    __be16 pad;
} __attribute__ ((packed));


struct sk_buff;
struct inst_stt;
extern void cvsw_apply_set_stt(struct sk_buff *skb, const struct inst_stt *stt);
extern bool cvsw_apply_strip_stt(struct sk_buff *skb);

#endif /* __CVSW_EXT_STT_H_INCLUDED__ */
