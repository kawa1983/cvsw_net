/*
 * geneve.c : Geneve processing
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
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/ip.h>
#include "../cvsw_flow_entry.h"
#include "../skb_util.h"
#include "tunnel.h"
#include "geneve.h"


/***************************************************************************
 * Encapsulation
 ***************************************************************************/

extern void cvsw_apply_set_geneve(struct sk_buff *skb, const struct inst_geneve *geneve)
{
    off_t offset;

    if (unlikely(! skb_util_make_tunnel_space(skb, GENEVE_HEADROOM_LEN))) {
	return ;
    }

    memcpy(skb->data, geneve, sizeof(struct inst_geneve));

    offset = sizeof(struct ethhdr);
    cvsw_setup_tun_ip_header((struct iphdr*)&skb->data[offset], skb->len - offset);
    offset += sizeof(struct iphdr);
    cvsw_setup_tun_udp_header((struct udphdr*)&skb->data[offset], skb->len - offset);

    if (skb_is_gso(skb)) {
	if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV4) {
	    skb_shinfo(skb)->gso_size = 1410;
	}
	skb_shinfo(skb)->gso_type |= SKB_GSO_UDP_TUNNEL;
    } else if (skb->ip_summed == CHECKSUM_PARTIAL) {
	cvsw_calc_inner_csum(skb, GENEVE_HEADROOM_LEN);
    }
}


/***************************************************************************
 * Decapsulation
 ***************************************************************************/

static inline bool cvsw_handle_geneve_packet(struct sk_buff *skb)
{
    struct udphdr    *udp;
    struct genevehdr *geneve;

    udp = (struct udphdr*)&skb->data[ETHERIP_HDR_LEN];

    if (ntohs(udp->dest) != GENEVE_PORT) {
	return true;
    } else if (udp->check != 0) {
	/* TBD: Validate checksums */
	skb->ip_summed = CHECKSUM_UNNECESSARY;
    }

    geneve = (struct genevehdr*)(udp + 1);

    if (geneve->version != GENEVE_VERSION) {
	return false;
    }

    cvsw_strip_tunnel(skb, GENEVE_HEADROOM_LEN);

    return true;
}


static inline void cvsw_register_geneve_fragment(const struct sk_buff *skb, const struct iphdr *ip, const __u32 key)
{
    if (likely(skb->len > GENEVE_HEADROOM_LEN + sizeof(struct ethhdr))) {
	const size_t packet_len = ntohs(((struct udphdr*)(ip + 1))->len);
	if (likely(skb->len - ETHERIP_HDR_LEN < packet_len)) {
	    cvsw_register_tun_fragment(skb, ip->id, 
				       skb->len - ETHERIP_HDR_LEN, 
				       packet_len, key);
	}
    }
}


static inline bool cvsw_handle_geneve_fragment(struct sk_buff *skb, const struct iphdr *ip, struct tun_fragment *frag)
{
    skb_util_remove_tunnel_space(skb, ETHERIP_HDR_LEN);
    strip_ip_padding(skb, ip, frag);

    if (! cvsw_handle_fragment(skb, frag, (ntohs(ip->frag_off) & IP_OFFSET) << 3)) {
	return false;
    }

    return cvsw_handle_geneve_packet(skb);
}


extern bool cvsw_apply_strip_geneve(struct sk_buff *skb)
{
    struct iphdr *ip;
    off_t offset;
    __u32 key;

    offset = sizeof(struct ethhdr);

    if (unlikely(skb->len < ETHERIP_HDR_LEN)) {
	return true; /* Not an IP packet */
    }
    ip = (struct iphdr*)&skb->data[offset];
    offset += sizeof(struct iphdr);

    if (ip->protocol != IPPROTO_UDP) {
	return true;
    }
    /* TBD: Verify IP checksum */

    key = ip->id ^ ip->saddr;

    if (ntohs(ip->frag_off) & IP_OFFSET) {
	struct tun_fragment *frag;
	frag = cvsw_find_tunnel_frag_cb(key, ip->id);
	if (unlikely(! frag)) {
	    return false;
	}
	return cvsw_handle_geneve_fragment(skb, ip, frag);
    } else if (ntohs(ip->frag_off) & IP_MF) {
	cvsw_register_geneve_fragment(skb, ip, key);
	return false;
    }

    cvsw_handle_geneve_packet(skb);

    return true;
}
