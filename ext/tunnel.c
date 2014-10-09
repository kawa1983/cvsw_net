/*
 * tunnel.c : Common tunnel processing
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

#include <linux/if_ether.h>
#include <linux/etherdevice.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/random.h>
#include "../skb_util.h"
#include "tunnel.h"

extern __be16 cvsw_calc_tnl_src_port(const __u8 *inner)
{
    struct ethhdr *eth;
    __u32 port;

    port = 0;

    eth = (struct ethhdr*)inner;
    port ^= *(__u32*)&eth->h_dest[0];
    port ^= *(__u32*)&eth->h_dest[4];
    port ^= *(__u32*)&eth->h_source[2];

    if (eth->h_proto == htons(ETH_P_IP)) {
	struct iphdr *ip;
	ip = (struct iphdr*)(eth + 1);
	port ^= ip->daddr;
	port ^= ip->saddr;

	if ((ip->protocol == IPPROTO_TCP) ||
	    (ip->protocol == IPPROTO_UDP)) {
	    struct udphdr *udp;
	    udp = (struct udphdr*)(ip + 1);
	    port ^= *(__u32*)&udp->source;
	}
    }

    port = ((port >> 16) ^ port) & 0x7FFF;

    return htons((__u16)(49152 + port));
}


extern bool cvsw_calc_inner_csum(struct sk_buff *skb, size_t headroom_len)
{
    struct ethhdr *eth;
    __u8 *data;
    __u16  len;
    __wsum csum;
    __sum16 *check;

    if (skb_is_nonlinear(skb)) {
	if (unlikely(skb_linearize(skb) != 0)) {
	    pr_warn("Can't linearize skb\n");
	    return false;
	}
    }

    eth = (struct ethhdr*)&skb->data[headroom_len];

    if (ntohs(eth->h_proto) == ETH_P_IP) {
	struct iphdr *ip;
	ip = (struct iphdr*)(eth + 1);
	data = &(((__u8*)ip)[ip->ihl << 2]);
	len = ntohs(ip->tot_len) - (ip->ihl << 2);
	if (ip->protocol == IPPROTO_TCP) {
	    check = &((struct tcphdr*)data)->check;
	} else if (ip->protocol == IPPROTO_UDP) {
	    check = &((struct udphdr*)data)->check;
	} else {
	    return false;
	}
	*check = 0;
	csum = csum_partial(data, len, 0);
	*check = csum_tcpudp_magic(ip->saddr, ip->daddr, len, 
				   ip->protocol, csum);
    } else {
	return false; /* TBD: IPV6 support */
    }

    skb->ip_summed = CHECKSUM_UNNECESSARY;

    return true;
}


extern void cvsw_setup_tun_ip_header(struct iphdr *ip, const __u16 len)
{
    __u16 ip_id;

    csum_replace2(&ip->check, ip->tot_len, htons(len));
    ip->tot_len = htons(len);

    get_random_bytes(&ip_id, sizeof(ip_id));
    csum_replace2(&ip->check, ip->id, ip_id);
    ip->id = ip_id;
}


extern void cvsw_setup_tun_udp_header(struct udphdr *udp, const __u16 len)
{
    udp->source = cvsw_calc_tnl_src_port((__u8*)(udp + 2));
    udp->len    = htons(len);
    udp->check  = 0;
}


extern void cvsw_strip_tunnel(struct sk_buff *skb, const size_t len)
{
    if (likely(skb->len > len + sizeof(struct ethhdr))) {
	skb_util_remove_tunnel_space(skb, len);
	
	if (memcmp(eth_hdr(skb)->h_dest, 
		   skb->dev->dev_addr, ETH_ALEN) == 0) {
	    skb->pkt_type = PACKET_HOST;	    
	} else if (ether_addr_equal_64bits(eth_hdr(skb)->h_dest, 
					   skb->dev->broadcast)) {
	    skb->pkt_type = PACKET_BROADCAST;
	} else {
	    skb->pkt_type = PACKET_OTHERHOST;
	}
	skb->protocol = eth_hdr(skb)->h_proto;
    }
}


extern void strip_ip_padding(struct sk_buff *skb, const struct iphdr *ip, const struct tun_fragment *frag)
{
    if ((!(ntohs(ip->frag_off) & 0xE000)) && 
	(frag->next_idx + skb->len) > frag->frame_size) {
	skb_trim(skb, frag->frame_size - frag->next_idx);
    }
}


extern void cvsw_register_tun_fragment(const struct sk_buff *skb, const __u32 frame_id, const off_t frag_off, 
				       const __u32 frame_size, const __u32 key)
{
    struct tun_fragment *frag;

    frag = (struct tun_fragment*)kzalloc(sizeof(struct tun_fragment), GFP_ATOMIC);
    if (unlikely(! frag)) {
	return ;
    }

    frag->id         = frame_id;
    frag->next_idx   = frag_off;
    frag->frame_size = frame_size;
    frag->skb = skb_copy_expand(skb, 0, frag->frame_size - frag->next_idx, GFP_ATOMIC);
    if (unlikely(! frag->skb)) {
	kfree(frag);
	return ;
    }

    cvsw_add_tunnel_frag_cb(frag, key);
}


extern bool cvsw_handle_fragment(struct sk_buff *skb, struct tun_fragment *frag, const off_t frag_off)
{
    struct sk_buff tmp_skb;

    if (unlikely(frag->next_idx != frag_off)) {
	/* TBD: Reordering */
	return false;
    } else if (unlikely(frag->next_idx + skb->len > frag->frame_size)) {
	/* Too large packets */
	return false;
    }

    memcpy(skb_put(frag->skb, skb->len), skb->data, skb->len);
    frag->next_idx += skb->len;

    if (frag->next_idx != frag->frame_size) {
	/* Further fragment packets are needed */
	return false;
    }

    /* Defragment completed */

    memcpy(&tmp_skb, skb, sizeof(struct sk_buff));
    memcpy(skb, frag->skb, sizeof(struct sk_buff));
    memcpy(frag->skb, &tmp_skb, sizeof(struct sk_buff));
    cvsw_delete_tunnel_frag_cb(&frag->list);

    return true;
}

