/*
 * skb_util.c : Utility functions for SKB
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

#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <linux/in.h>
#include "skb_util.h"


static bool skb_util_make_space(struct sk_buff *skb, const size_t size, const off_t offset)
{
    size_t headroom;
    size_t tailroom;
    size_t packet_len;

    headroom = skb_headroom(skb);
    tailroom = skb_tailroom(skb);

    if (headroom + tailroom < size) {
	if (unlikely(pskb_expand_head(skb, size - headroom, 0, GFP_ATOMIC))) {
	    return false;
	}
	headroom = skb_headroom(skb);
	tailroom = skb_tailroom(skb);
    }

    packet_len = skb->len;

    if (headroom >= size) {
	skb_push(skb, size);
	if (offset) {
	    memmove(skb->data, &skb->data[size], offset);
	}
    } else {
	off_t move_back_len;
	
	if (tailroom >= size) {
	    move_back_len = size;
	    skb_put(skb, move_back_len);
	    memmove(&skb->data[offset + move_back_len], &skb->data[offset], packet_len - offset);
	} else { /* headroom + tailroom >= size */
	    move_back_len = tailroom;
	    skb_push(skb, size - move_back_len);
	    skb_put(skb, move_back_len);
	    if (offset) {
		memmove(skb->data, &skb->data[size - move_back_len], offset);
	    }
	    memmove(&skb->data[offset + size], 
		    &skb->data[offset + size - move_back_len], 
		    packet_len - offset);
	}
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
	    skb->csum_start += move_back_len;
	}
    }

    return true;
}

static inline void skb_util_remove_space(struct sk_buff *skb, const size_t size, const off_t offset)
{
    if (skb->len - offset >= size) {
	if (offset) {
	    memmove(&skb->data[size], skb->data, offset);
	}
	skb_pull(skb, size);
    }
}

extern bool skb_util_make_vlan_space(struct sk_buff *skb)
{
    if (unlikely(! skb_util_make_space(skb, VLAN_HLEN, 12))) {
	return false;
    }

    skb_reset_mac_header(skb);
    skb_reset_network_header(skb);
    skb_reset_transport_header(skb);

    ((struct vlan_ethhdr*)eth_hdr(skb))->h_vlan_TCI = 0;

    return true;
}

extern void skb_util_remove_vlan_space(struct sk_buff *skb)
{
    skb_util_remove_space(skb, VLAN_HLEN, 12);

    skb_reset_mac_header(skb);
    skb_reset_network_header(skb);
    skb_reset_transport_header(skb);
}

extern __u8 *skb_util_get_network_header(const struct sk_buff *skb)
{
    struct ethhdr *hdr;
    hdr = eth_hdr(skb);

    if (hdr->h_proto == htons(ETH_P_8021Q)) {
	/* Has VLAN tag */
	hdr = (struct ethhdr*)(skb_mac_header(skb) + 4);
    }

    if ((hdr->h_proto == htons(ETH_P_IP)) || 
	(hdr->h_proto == htons(ETH_P_IPV6))) {
	return (__u8*)(hdr + 1);
    }

    return NULL;
}

static __u8 skb_util_get_upper_proto_v6(const struct ipv6hdr *ipv6, size_t *len)
{
    __u8 *hdr;
    __u8 proto;

    if (len) {
	*len  = sizeof(struct ipv6hdr);
    }

    hdr = (__u8*)(ipv6 + 1);
    proto = ipv6->nexthdr;

    for (;;) {
	size_t hlen;

	switch (proto) {
	case NEXTHDR_HOP:
	case NEXTHDR_ROUTING:
	case NEXTHDR_DEST:
	    hlen = (hdr[1] + 1) << 4;
	    break;
	case NEXTHDR_TCP:
	case NEXTHDR_UDP:
	case NEXTHDR_ICMP:
	case NEXTHDR_FRAGMENT:
	    return proto;
	default:
	    return NEXTHDR_NONE;
	}
	proto = hdr[0];
	hdr += hlen;
	if (len) {
	    *len += hlen;
	}
    }
    return proto;
}

extern __u8 *skb_util_get_transport_header(const struct sk_buff *skb)
{
    __u8 *nw;

    nw = skb_util_get_network_header(skb);
    if (likely(nw)) {
	return skb_util_get_transport_header_nw(nw);
    }

    return NULL;
}

extern __u8 *skb_util_get_transport_header_nw(const __u8 *nw)
{
    if (((struct iphdr*)nw)->version == 4) {
	struct iphdr *ip4;
	ip4 = (struct iphdr*)nw;
	if (((ip4->frag_off & htons(0x1FF)) == 0) &&
	    ((ip4->protocol == IPPROTO_TCP) || 
	     (ip4->protocol == IPPROTO_UDP))) {
	    return (__u8*)&nw[ip4->ihl << 2];
	}
    } else if (((struct ipv6hdr*)nw)->version == 6) {
	__u8 proto;
	size_t len;
	proto = skb_util_get_upper_proto_v6((struct ipv6hdr*)nw, &len);
	if ((proto == NEXTHDR_TCP) || (proto == NEXTHDR_UDP)) {
	    return (__u8*)&nw[len];
	}
    }
    return NULL;
}
