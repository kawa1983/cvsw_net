/*
 * cvsw_net.h : CVSW message definition
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

#ifndef __CVSW_NET2_INCLUDED__
#define __CVSW_NET2_INCLUDED__

#include <linux/if_ether.h>

/* CVSW version */
#define CVSW_VERSION               0x2

/* Ethernet type */
#define CVSW_ETH_TYPE              0xABBA

/* Ingress ports */
#define CVSW_PORT_HOST             0x1
#define CVSW_PORT_NET              0x2

/* CVSW message type */
#define CVSW_TYPE_HELLO            0x01
#define CVSW_TYPE_REGISTER         0x02
#define CVSW_TYPE_SET_ENTRY        0x03
#define CVSW_TYPE_DELETE_ENTRY     0x04
#define CVSW_TYPE_CHANGE_MTU       0x05
#define CVSW_TYPE_CHANGE_OFFLOAD   0x06

/* Offloading features */
#define CVSW_OFFLOAD_CSUM          (1 << 0)
#define CVSW_OFFLOAD_TSO           (1 << 1)
#define CVSW_OFFLOAD_UFO           (1 << 2)
#define CVSW_OFFLOAD_GSO           (1 << 3)
#define CVSW_OFFLOAD_GRO           (1 << 4)

/* CVSW states */
enum cvsw_st {
    CVSW_STATE_DISCONNECTED      = 0x00,
    CVSW_STATE_CONNECTING        = 0x01,
    CVSW_STATE_CONNECTED         = 0x02,
};

extern enum cvsw_st cvsw_state;

struct cvsw_fields {
#ifdef __LITTLE_ENDIAN_BITFIELD
    __u8 type:4, version:4;
#else
    __u8 version:4, type:4;
#endif
    __u8 pad;
    __be16 len;
    __be16 data;
} __attribute__ ((__packed__));

struct cvsw_hdr {
    __u8 dst_mac[ETH_ALEN];
    struct cvsw_fields cvsw;
    __be16 ether_type;
} __attribute__ ((__packed__));


#define CVSW_HEADER(skb)  (struct cvsw_hdr*)eth_hdr((skb))

struct sk_buff;
struct net_device;

extern bool cvsw_xmit_skb(struct sk_buff *skb);
extern bool cvsw_change_mtu(struct net_device *dev, const int mtu);
extern void cvsw_change_offload(struct net_device *dev, const __u16 offload);

#endif /* __CVSW_NET2_INCLUDED__ */
