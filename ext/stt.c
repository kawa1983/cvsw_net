/*
 * stt.c : STT processing
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
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include "../cvsw_flow_entry.h"
#include "../skb_util.h"
#include "tunnel.h"
#include "stt.h"


/***************************************************************************
 * Encapsulation
 ***************************************************************************/

static void cvsw_setup_tun_ptcp_header(struct ptcphdr *ptcp, const __u16 len)
{
    ptcp->source = cvsw_calc_tnl_src_port(&((__u8*)(ptcp + 1))[sizeof(struct stthdr)]);
    ptcp->len    = htons(len);
    ptcp->check  = 0;
    get_random_bytes(&ptcp->id, sizeof(ptcp->id));
}


static void cvsw_setup_tun_stt_header(struct sk_buff *skb, struct stthdr *stt, const size_t len)
{
    __u8 *nw;
    __u8 *tp;

    skb_pull(skb, STT_HEADROOM_LEN);
    nw = skb_util_get_network_header(skb);
    if (likely(nw)) {
	__u8 protocol;
	if (((struct iphdr*)nw)->version == 4) {
	    stt->ipv4 = 1;
	    protocol = ((struct iphdr*)nw)->protocol;
	} else if (((struct ipv6hdr*)nw)->version == 6) {
	    protocol = ((struct ipv6hdr*)nw)->nexthdr; /* TBD: Skip IPv6 Option headers */
	} else {
	    pr_warn("Unknown L3 protocol\n");
	    protocol = 0xFF;
	}
	tp = skb_util_get_transport_header_nw(nw);
	if (likely(tp)) {
	    stt->offset = tp - (__u8*)(stt + 1);
	    if (protocol == IPPROTO_TCP) {
		stt->tcp = 1;
	    }
	}
    }
    skb_push(skb, STT_HEADROOM_LEN);

    stt->mss = htons(skb->dev->mtu - (sizeof(struct iphdr) + sizeof(struct tcphdr)));

    switch (skb->ip_summed) {
    case CHECKSUM_NONE:
    case CHECKSUM_UNNECESSARY:
	stt->csum_verified = 1;
	break;
    case CHECKSUM_PARTIAL:
	stt->csum_partial = 1;
	break;
    default:
	pr_warn("Unsupported csum type : %d\n", skb->ip_summed);
    }
}


static void cvsw_set_ptcp_csum(struct sk_buff *skb, const struct iphdr *ip, struct ptcphdr *ptcp)
{
    if (skb->ip_summed == CHECKSUM_PARTIAL) {
	skb->csum_start  = skb_headroom(skb) + ETHERIP_HDR_LEN;
	skb->csum_offset = offsetof(struct tcphdr, check);
    } else {
	__wsum csum;
	csum = csum_partial((__u8*)ptcp, skb->len - ETHERIP_HDR_LEN, 0);
	ptcp->check = csum_tcpudp_magic(ip->saddr, ip->daddr,
					skb->len - ETHERIP_HDR_LEN, IPPROTO_TCP, csum);
    }
}


extern void cvsw_apply_set_stt(struct sk_buff *skb, const struct inst_stt *stt)
{
    off_t offset;

    if (unlikely(! skb_util_make_tunnel_space(skb, STT_HEADROOM_LEN))) {
	return ;
    }

    memcpy(skb->data, stt, sizeof(struct inst_stt));

    offset = sizeof(struct ethhdr);
    cvsw_setup_tun_ip_header((struct iphdr*)&skb->data[offset], skb->len - offset);
    offset += sizeof(struct iphdr);
    cvsw_setup_tun_ptcp_header((struct ptcphdr*)&skb->data[offset], skb->len - offset - sizeof(struct ptcphdr));

    offset += sizeof(struct ptcphdr);
    cvsw_setup_tun_stt_header(skb, (struct stthdr*)&skb->data[offset], skb->len - offset);

    /* Calculate TCP Checksum */
    cvsw_set_ptcp_csum(skb, &stt->ip, (struct ptcphdr*)&skb->data[offset - sizeof(struct ptcphdr)]);

    if (skb_is_gso(skb)) {
	if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV4) {
	    skb_shinfo(skb)->gso_size += STT_HEADROOM_LEN - sizeof(struct tcphdr);
	} else {
	    skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
	}
    }
}


/***************************************************************************
 * Decapsulation
 ***************************************************************************/

static bool cvsw_check_ptcp_csum(struct sk_buff *skb, const struct iphdr *ip, const struct ptcphdr *ptcp)
{
    __wsum csum;

    if ((skb->ip_summed == CHECKSUM_UNNECESSARY) ||
	(skb->ip_summed == CHECKSUM_PARTIAL)) {
	return true;
    }

    if (skb->ip_summed == CHECKSUM_COMPLETE) {
	skb_postpull_rcsum(skb, skb->data, ETHERIP_HDR_LEN);
	csum = skb->csum;
    } else {
	csum = csum_partial((__u8*)ptcp, skb->len - ETHERIP_HDR_LEN, 0);
    }

    csum = csum_tcpudp_magic(ip->saddr, ip->daddr, skb->len - ETHERIP_HDR_LEN, IPPROTO_TCP, csum);

    return likely(csum == 0);
}


static inline bool cvsw_handle_stt_frame(struct sk_buff *skb, const struct stthdr *stt)
{
    cvsw_strip_tunnel(skb, STT_HEADROOM_LEN);

    skb->ip_summed = CHECKSUM_UNNECESSARY; /* Already verified */

    return true;
}


static inline void cvsw_register_stt_fragment(const struct sk_buff *skb, const struct iphdr *ip, const struct ptcphdr *ptcp, 
					      const __u32 id, const __u32 key)
{
    if (likely(skb->len > STT_HEADROOM_LEN + sizeof(struct ethhdr))) {
	const size_t this_len  = skb->len - (likely(ptcp) ? (STT_HEADROOM_LEN - STT_HDR_LEN) : ETHERIP_HDR_LEN);
	const size_t total_len = ntohs(((struct ptcphdr*)(ip + 1))->len);
	if (likely(this_len < total_len)) {
	    cvsw_register_tun_fragment(skb, id, this_len, total_len, key);
	}
    }
}


static inline bool cvsw_handle_stt_ip_fragment(struct sk_buff *skb, const struct iphdr *ip, struct tun_fragment *frag)
{
    skb_util_remove_tunnel_space(skb, ETHERIP_HDR_LEN);
    strip_ip_padding(skb, ip, frag);

    if (! cvsw_handle_fragment(skb, frag, (ntohs(ip->frag_off) & IP_OFFSET) << 3)) {
	return false;
    }

    return cvsw_handle_stt_frame(skb, (struct stthdr*)&skb->data[STT_HEADROOM_LEN - STT_HDR_LEN]);
}


static bool cvsw_handle_stt_ptcp_fragment(struct sk_buff *skb, const struct ptcphdr *ptcp, struct tun_fragment *frag)
{
    skb_util_remove_tunnel_space(skb, STT_HEADROOM_LEN - STT_HDR_LEN); /* Strip Ether/IP/TCP headers */

    if (! cvsw_handle_fragment(skb, frag, ntohs(ptcp->offset))) {
	return false;
    }

    return cvsw_handle_stt_frame(skb, (struct stthdr*)&skb->data[STT_HEADROOM_LEN - STT_HDR_LEN]);
}


extern bool cvsw_apply_strip_stt(struct sk_buff *skb)
{
    struct iphdr   *ip;
    struct ptcphdr *ptcp;
    struct stthdr  *stt;
    off_t offset;
    __u32 key;

    offset = sizeof(struct ethhdr);

    if (unlikely(skb->len < offset + sizeof(struct iphdr))) {
	return true; /* Not an IP packet */
    }
    ip = (struct iphdr*)&skb->data[offset];
    offset += sizeof(struct iphdr);

    if (ip->protocol != IPPROTO_TCP) {
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
	return cvsw_handle_stt_ip_fragment(skb, ip, frag);
    } else if (ntohs(ip->frag_off) & IP_MF) {
	cvsw_register_stt_fragment(skb, ip, NULL, ip->id, key);
	return false;
    }

    if (unlikely(skb->len < offset + sizeof(struct ptcphdr))) {
	return false; /* Not a TCP packet */
    }
    ptcp = (struct ptcphdr*)&skb->data[offset];
    offset += sizeof(struct ptcphdr);

    if (ntohs(ptcp->dest) != STT_PORT) {
	return true;
    }

    /* Validate PTCP's checksum */
    if (unlikely(! cvsw_check_ptcp_csum(skb, ip, ptcp))) {
	return false;
    }

    key = ptcp->id ^ ip->saddr ^ ptcp->len;

    if (skb->len - offset < ntohs(ptcp->len)) {
	if (ptcp->offset == 0) {
	    cvsw_register_stt_fragment(skb, ip, ptcp, ptcp->id, key);
	    return false;
	} else {
	    struct tun_fragment *frag;
	    frag = cvsw_find_tunnel_frag_cb(key, ptcp->id);
	    if (unlikely(! frag)) {
		return false;
	    }
	    return cvsw_handle_stt_ptcp_fragment(skb, ptcp, frag);
        }
    }

    if (unlikely(skb->len < STT_HEADROOM_LEN + sizeof(struct ethhdr))) {
	return false;
    }
    stt = (struct stthdr*)&skb->data[offset];
    if (unlikely(stt->version != STT_VERSION)) {
	return false;
    }

    cvsw_handle_stt_frame(skb, stt);

    return true;
}
