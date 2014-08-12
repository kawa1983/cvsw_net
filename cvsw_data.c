/*
 * cvsw_data.c : Data plane processing
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

#include <linux/list.h>
#include <linux/random.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "cvsw_net.h"
#include "cvsw_table.h"
#include "cvsw_flow_entry.h"
#include "cvsw_data.h"
#include "skb_util.h"
#include "openflow.h"
#include "ext/openflow_ext.h"
#include "ext/vxlan.h"
#include "ext/stt.h"

#define ETHERIP_HDR_LEN (sizeof(struct ethhdr) + sizeof(struct iphdr))

static inline void update_tp_pseudo_csum_4(struct sk_buff *skb, struct iphdr *ip, const __u32 old_addr, const __u32 new_addr)
{
    const __u8 *l4h = &((__u8*)ip)[ip->ihl << 2];

    if (ip->protocol == IPPROTO_TCP) {
	struct tcphdr *tcp = (struct tcphdr*)l4h;
	inet_proto_csum_replace4(&tcp->check, skb, old_addr, new_addr, 1);
    } else if (ip->protocol == IPPROTO_UDP) {
	struct udphdr *udp = (struct udphdr*)l4h;
	if (udp->check || (skb->ip_summed == CHECKSUM_PARTIAL)) {
	    inet_proto_csum_replace4(&udp->check, skb, old_addr, new_addr, 1);
	    if (! udp->check) {
		udp->check = CSUM_MANGLED_0;
	    }
	}
    }
}

static inline void update_tp_pseudo_csum_6(struct sk_buff *skb, struct ipv6hdr *ip, const __u32 *old_addr, const __u32 *new_addr)
{
    if (ip->nexthdr == IPPROTO_TCP) {
	struct tcphdr *tcp = (struct tcphdr*)(ip + 1);
	inet_proto_csum_replace16(&tcp->check, skb, old_addr, new_addr, 1);
    } else if (ip->nexthdr == IPPROTO_UDP) {
	struct udphdr *udp = (struct udphdr*)(ip + 1);
	if (udp->check || (skb->ip_summed == CHECKSUM_PARTIAL)) {
	    inet_proto_csum_replace16(&udp->check, skb, old_addr, new_addr, 1);
	    if (! udp->check) {
		udp->check = CSUM_MANGLED_0;
	    }
	}
    }
}

static bool cvsw_match_dl_vlan_vid(const __be16 vid, const struct ethhdr *hdr)
{
    if (hdr->h_proto == htons(ETH_P_8021Q)) {
	struct vlan_ethhdr *vlan;
	vlan = (struct vlan_ethhdr*)hdr;
	return ((vlan->h_vlan_TCI & htons(VLAN_VID_MASK)) == vid);
    }
    return false;
}

static bool cvsw_match_dl_vlan_pcp(const __u8 pcp, const struct ethhdr *hdr)
{
    if (hdr->h_proto == htons(ETH_P_8021Q)) {
	struct vlan_ethhdr *vlan;
	vlan = (struct vlan_ethhdr*)hdr;
	return (((vlan->h_vlan_TCI & htons(VLAN_PRIO_MASK)) >> VLAN_PRIO_SHIFT) == pcp);
    }
    return false;
}

static bool cvsw_do_match(const struct sk_buff *skb, const __u16 in_port, const struct cvsw_match *match)
{
    struct ethhdr *dl;
    struct iphdr  *nw;
    struct udphdr *tp;
    __u8 *hdr;
    __u32 wildcards;

    wildcards = match->wildcards;

    if (unlikely(wildcards == 0)) {
	return false;
    } else if (wildcards == OFPFW_ALL) {
	return true;
    }

    /* Check input port */
    if (~wildcards & OFPFW_IN_PORT) {
	if (match->in_port != in_port) {
	    return false;
	}
	wildcards |= OFPFW_IN_PORT;
    }

    /* Check datalink layer */
    dl = eth_hdr(skb);

    /* Check VLAN */
    if (dl->h_proto == htons(ETH_P_8021Q)) {
	if (~wildcards & OFPFW_DL_VLAN) {
	    if (! cvsw_match_dl_vlan_vid(match->dl_vlan_vid, dl)) {
		return false;
	    }
	    wildcards |= OFPFW_DL_VLAN;
	}
	if (~wildcards & OFPFW_DL_VLAN_PCP) {
	    if (! cvsw_match_dl_vlan_pcp(match->dl_vlan_pcp, dl)) {
		return false;
	    }
	    wildcards |= OFPFW_DL_VLAN_PCP;
	}
    }
    if (~wildcards & OFPFW_DL_DST) {
	if (memcmp(match->dl_dst, dl->h_dest, ETH_ALEN) != 0) {
	    return false;
	}
	wildcards |= OFPFW_DL_DST;
    }
    if (~wildcards & OFPFW_DL_SRC) {
	if (memcmp(match->dl_src, dl->h_source, ETH_ALEN) != 0) {
	    return false;
	}
	wildcards |= OFPFW_DL_SRC;
    }
    if (~wildcards & OFPFW_DL_TYPE) {
	if (match->dl_type != dl->h_proto) {
	    return false;
	}
	wildcards |= OFPFW_DL_TYPE;
    }
    if (wildcards == OFPFW_ALL) {
	return true;
    }

    /* Check network layer */
    hdr = skb_util_get_network_header(skb);
    if (unlikely(! hdr)) {
	return false;
    }

    nw = (struct iphdr*)hdr; /* TBD: IPv6 support */

    if (~wildcards & OFPFW_NW_PROTO) {
	if (match->nw_proto != nw->protocol) {
	    return false;
	}
	wildcards |= OFPFW_NW_PROTO;
    }
    if (~wildcards & OFPFW_NW_DST_ALL) {
	if (memcmp(match->nw_dst, &nw->daddr, 4) != 0) {
	    return false;
	}
	wildcards |= OFPFW_NW_DST_ALL;
    }
    if (~wildcards & OFPFW_NW_SRC_ALL) {
	if (memcmp(match->nw_src, &nw->saddr, 4) != 0) {
	    return false;
	}
	wildcards |= OFPFW_NW_SRC_ALL;
    }
    if (wildcards == OFPFW_ALL) {
	return true;
    }

    /* Check transport layer */
    hdr = skb_util_get_transport_header_nw(hdr);
    if (unlikely(! hdr)) {
	return false;
    }

    tp = (struct udphdr*)hdr; /* UDP and TCP have port fields at the same position */

    if (~wildcards & OFPFW_TP_DST) {
	if (match->tp_dst != tp->dest) {
	    return false;
	}
	wildcards |= OFPFW_TP_DST;
    }
    if (~wildcards & OFPFW_TP_SRC) {
	if (match->tp_src != tp->source) {
	    return false;
	}
	wildcards |= OFPFW_TP_SRC;
    }
    if (wildcards == OFPFW_ALL) {
	return true;
    }

    /* Check tunnel layer */
    hdr = skb_util_get_tunnel_header_tp(hdr, nw->protocol);
    if (unlikely(! hdr)) {
	return false;
    }

    if (nw->protocol == IPPROTO_UDP) {
	struct vxlanhdr *vxlan;
	vxlan = (struct vxlanhdr*)hdr;
	if (~wildcards & OFPFW_EXT_TUN_VXLAN_VNI) {
	    if (match->tun_id != vxlan->vni) {
		return false;
	    }
	    wildcards |= OFPFW_EXT_TUN_VXLAN_VNI;
	}
    } else if (nw->protocol == IPPROTO_TCP) {
	struct stthdr *stt;
	stt = (struct stthdr*)hdr;
	if (~wildcards & OFPFW_EXT_TUN_STT_CID) {
	    if (match->tun_id != stt->context_id) {
		return false;
	    }
	    wildcards |= OFPFW_EXT_TUN_STT_CID;
	}
    }

    return (wildcards == OFPFW_ALL);
}

static void cvsw_apply_output(struct sk_buff *skb, const __u16 port)
{
    /* Not supported */
}

static void cvsw_apply_set_vlan_vid(struct sk_buff *skb, const __be16 vid)
{
    struct vlan_ethhdr *vlan;

    if (likely(eth_hdr(skb)->h_proto != htons(ETH_P_8021Q))) {
	if (unlikely(! skb_util_make_vlan_space(skb))) {
	    pr_warn("Can't insert VLAN tag space\n");
	    return ;
	}
	skb->protocol = eth_hdr(skb)->h_proto = htons(ETH_P_8021Q);
    }

    vlan = (struct vlan_ethhdr*)eth_hdr(skb);
    vlan->h_vlan_TCI &= htons(VLAN_PRIO_MASK);
    vlan->h_vlan_TCI |= vid & htons(VLAN_VID_MASK);
    skb->vlan_tci = ntohs(vlan->h_vlan_TCI);
}

static void cvsw_apply_set_vlan_pcp(struct sk_buff *skb, const __u8 pcp)
{
    struct vlan_ethhdr *vlan;

    if (likely(eth_hdr(skb)->h_proto != htons(ETH_P_8021Q))) {
	if (unlikely(! skb_util_make_vlan_space(skb))) {
	    pr_warn("Can't insert VLAN tag space\n");
	    return ;
	}
	skb->protocol = eth_hdr(skb)->h_proto = htons(ETH_P_8021Q);
    }

    vlan = (struct vlan_ethhdr*)eth_hdr(skb);
    vlan->h_vlan_TCI &= htons(VLAN_VID_MASK);
    vlan->h_vlan_TCI |= (pcp << VLAN_PRIO_SHIFT) & htons(VLAN_PRIO_MASK);
    skb->vlan_tci = ntohs(vlan->h_vlan_TCI);
}

static void cvsw_apply_strip_vlan(struct sk_buff *skb)
{
    if (likely(eth_hdr(skb)->h_proto == htons(ETH_P_8021Q))) {
	skb_util_remove_vlan_space(skb);
	skb->protocol = eth_hdr(skb)->h_proto;
	skb->vlan_tci = 0;
    }
}

static void cvsw_apply_set_nw_dst(struct sk_buff *skb, const __u8 *addr)
{
    __u8 *nw;

    nw = skb_util_get_network_header(skb);
    if (unlikely(! nw)) {
	return ;
    }
    if (((struct iphdr*)nw)->version == 4) {
	struct iphdr *ip4;
	ip4 = (struct iphdr*)nw;
	/* Update L3 checksum */
	csum_replace4(&ip4->check, ip4->daddr, *((__u32*)addr));
	/* Update L4 checksum */
	update_tp_pseudo_csum_4(skb, ip4, ip4->daddr, *((__u32*)addr));
	/* Set dest address */
	memcpy(&ip4->daddr, addr, 4);
    } else if (((struct ipv6hdr*)nw)->version == 6) {
	struct ipv6hdr *ip6;
	ip6 = (struct ipv6hdr*)nw;
	/* Update L4 checksum */
	update_tp_pseudo_csum_6(skb, ip6, ip6->daddr.s6_addr32, (__u32*)addr);
	/* Set dest address */
	memcpy(&ip6->daddr, addr, 16);
    } else {
	pr_warn("Unsupported NW protocol\n");
    }
}

static void cvsw_apply_set_nw_src(struct sk_buff *skb, const __u8 *addr)
{
    __u8 *nw;

    nw = skb_util_get_network_header(skb);
    if (unlikely(! nw)) {
	return ;
    }
    if (((struct iphdr*)nw)->version == 4) {
	struct iphdr *ip4;
	ip4 = (struct iphdr*)nw;
	/* Update L3 checksum */
	csum_replace4(&ip4->check, ip4->saddr, *((__u32*)addr));
	/* Update L4 checksum */
	update_tp_pseudo_csum_4(skb, ip4, ip4->saddr, *((__u32*)addr));
	/* Set source address */
	memcpy(&ip4->saddr, addr, 4);
    } else if (((struct ipv6hdr*)nw)->version == 6) {
	struct ipv6hdr *ip6;
	ip6 = (struct ipv6hdr*)nw;
	/* Update L4 checksum */
	update_tp_pseudo_csum_6(skb, ip6, ip6->saddr.s6_addr32, (__u32*)addr);
	/* Set source address */
	memcpy(&ip6->saddr, addr, 16);
    } else {
	pr_warn("Unsupported NW protocol\n");
    }
}

static void cvsw_apply_set_nw_tos(struct sk_buff *skb, const __u8 tos)
{
    __u8 *nw;

    nw = skb_util_get_network_header(skb);
    if (unlikely(! nw)) {
	return ;
    }

    if (((struct iphdr*)nw)->version == 4) {
	off_t off;
	struct iphdr *ip4;
	ip4 = (struct iphdr*)nw;
	off = offsetof(struct iphdr, tos);
	/* Update L3 checksum */
	csum_replace2(&ip4->check, htons(*((__u16*)&ip4->tos)), tos << 8 | nw[off + 1]);
	/* Set ToS */
	ip4->tos = tos;
    } else if (((struct ipv6hdr*)nw)->version == 6) {
	struct ipv6hdr *ip6;
	ip6 = (struct ipv6hdr*)nw;
	ip6->priority = (tos >> 2) & 0x0F;
	/* Set Flow label */
	ip6->flow_lbl[0] = (tos << 6) | (ip6->flow_lbl[0] & 0xC0);
    } else {
	pr_warn("Unsupported NW protocol\n");
    }
}

static __u8 *get_tp(const struct sk_buff *skb, __u8 *protocol)
{
    __u8 *nw;
    __u8 *tp;

    nw = skb_util_get_network_header(skb);
    if (unlikely(! nw)) {
	return NULL;
    }
    tp = skb_util_get_transport_header_nw(nw);
    if (unlikely(! tp)) { 
	return NULL;
    }

    if (((struct iphdr*)nw)->version == 4) {
	*protocol = ((struct iphdr*)nw)->protocol;
    } else { /* IPv6 */
	/* TBD: Support IPv6 Option headers */
	*protocol = ((struct ipv6hdr*)nw)->nexthdr;
    }

    return tp;
}

static void update_tp_csum(struct sk_buff *skb, const __u8 protocol, __be16 *csum, const __be16 old, const __be16 new)
{
    if (skb->ip_summed == CHECKSUM_PARTIAL) {
	return ;
    }
    if ((*csum == 0) && (protocol == IPPROTO_UDP)) {
	return ;
    }

    inet_proto_csum_replace2(csum, skb, old, new, 0);
    if ((*csum == 0) && (protocol == IPPROTO_UDP)) {
	*csum = CSUM_MANGLED_0;
    }
}

static void cvsw_apply_set_tp_dst(struct sk_buff *skb, const __be16 port)
{
    __u8 *tp;
    __u8 protocol;
    __be16 *old_port;
    __be16 *pcsum;

    tp = get_tp(skb, &protocol);
    if (unlikely(! tp)) {
	return ;
    }

    if (protocol == IPPROTO_TCP) {
	struct tcphdr *tcp;
	tcp = (struct tcphdr*)tp;
	old_port = &tcp->dest;
	pcsum = &tcp->check;
    } else if (protocol == IPPROTO_UDP) {
	struct udphdr *udp;
	udp = (struct udphdr*)tp;
	old_port = &udp->dest;
	pcsum = &udp->check;
    } else {
	return ;
    }

    /* Update L4 checksum */
    update_tp_csum(skb, protocol, pcsum, *old_port, port);

    /* Set dest port */
    *old_port = port;
}

static void cvsw_apply_set_tp_src(struct sk_buff *skb, const __be16 port)
{
    __u8 *tp;
    __u8 protocol;
    __u16 *old_port;
    __be16 *pcsum;

    tp = get_tp(skb, &protocol);
    if (unlikely(! tp)) {
	return ;
    }

    if (protocol == IPPROTO_TCP) {
	struct tcphdr *tcp;
	tcp = (struct tcphdr*)tp;
	old_port = &tcp->source;
	pcsum = &tcp->check;
    } else if (protocol == IPPROTO_UDP) {
	struct udphdr *udp;
	udp = (struct udphdr*)tp;
	old_port = &udp->source;
	pcsum = &udp->check;
    } else {
	return ;
    }

    /* Update L4 checksum */
    update_tp_csum(skb, protocol, pcsum, *old_port, port);

    /* Set source port */
    *old_port = port;
}

static void cvsw_setup_tun_ip_header(struct iphdr *ip, const __u16 len)
{
    __u16 ip_id;

    csum_replace2(&ip->check, ip->tot_len, htons(len));
    ip->tot_len = htons(len);

    get_random_bytes(&ip_id, sizeof(ip_id));
    csum_replace2(&ip->check, ip->id, ip_id);
    ip->id = ip_id;
}

static __be16 cvsw_calc_tnl_src_port(const __u8 *inner)
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
	    port ^= *(__u32*)&udp->dest;
	}
    }

    port = ((port >> 16) ^ port) & 0x7FFF;

    return htons((__u16)(49152 + port));
}

static void cvsw_setup_tun_udp_header(struct udphdr *udp, const __u16 len)
{
    udp->source = cvsw_calc_tnl_src_port((__u8*)(udp + 2));
    udp->len    = htons(len);
    udp->check  = 0;
}

static void cvsw_setup_tun_ptcp_header(struct ptcphdr *ptcp, const __u16 len)
{
    ptcp->source = cvsw_calc_tnl_src_port(&((__u8*)(ptcp + 1))[sizeof(struct stthdr)]);
    ptcp->len    = htons(len);
    ptcp->check  = 0;
    get_random_bytes(&ptcp->id, sizeof(ptcp->id));
}

static void cvsw_apply_set_vxlan(struct sk_buff *skb, const struct inst_vxlan *vxlan)
{
    off_t offset;

    if (unlikely(! skb_util_make_tunnel_space(skb, VXLAN_HEADROOM_LEN))) {
	return ;
    }

    memcpy(skb->data, vxlan, sizeof(struct inst_vxlan));

    offset = sizeof(struct ethhdr);
    cvsw_setup_tun_ip_header((struct iphdr*)&skb->data[offset], skb->len - offset);
    offset += sizeof(struct iphdr);
    cvsw_setup_tun_udp_header((struct udphdr*)&skb->data[offset], skb->len - offset);
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
	ptcp->check = ~csum_tcpudp_magic(ip->saddr, ip->daddr,
					 skb->len - ETHERIP_HDR_LEN, IPPROTO_TCP, 0);
	skb->csum_start  = skb_headroom(skb) + ETHERIP_HDR_LEN;
	skb->csum_offset = offsetof(struct tcphdr, check);
    } else {
	__wsum csum;
	csum = csum_partial((__u8*)ptcp, skb->len - ETHERIP_HDR_LEN, 0);
	ptcp->check = csum_tcpudp_magic(ip->saddr, ip->daddr,
					skb->len - ETHERIP_HDR_LEN, IPPROTO_TCP, csum);
    }
}

static void cvsw_apply_set_stt(struct sk_buff *skb, const struct inst_stt *stt)
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
}

static void cvsw_strip_tunnel(struct sk_buff *skb, const size_t len)
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

static void cvsw_register_tun_fragment(const struct sk_buff *skb, const __u32 frame_id, const off_t frag_off, const __u32 frame_size, const __u32 key)
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

static bool cvsw_handle_fragment(struct sk_buff *skb, struct tun_fragment *frag, const off_t frag_off)
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

static inline void strip_ip_padding(struct sk_buff *skb, const struct iphdr *ip, const struct tun_fragment *frag)
{
    if ((!(ntohs(ip->frag_off) & 0xE000)) && 
	(frag->next_idx + skb->len) > frag->frame_size) {
	skb_trim(skb, frag->frame_size - frag->next_idx);
    }
}

static inline bool cvsw_handle_vxlan_packet(struct sk_buff *skb)
{
    /* TBD: Validate checksums */
    skb->ip_summed = CHECKSUM_UNNECESSARY;

    cvsw_strip_tunnel(skb, VXLAN_HEADROOM_LEN);

    return true;
}

static inline void cvsw_register_vxlan_fragment(const struct sk_buff *skb, const struct iphdr *ip, const __u32 key)
{
    if (likely(skb->len > VXLAN_HEADROOM_LEN + sizeof(struct ethhdr))) {
	const size_t packet_len = ntohs(((struct udphdr*)(ip + 1))->len);
	if (likely(skb->len - ETHERIP_HDR_LEN < packet_len)) {
	    cvsw_register_tun_fragment(skb, ip->id, 
				       skb->len - ETHERIP_HDR_LEN, 
				       packet_len, key);
	}
    }
}

static inline bool cvsw_handle_vxlan_fragment(struct sk_buff *skb, const struct iphdr *ip, struct tun_fragment *frag)
{
    skb_util_remove_tunnel_space(skb, ETHERIP_HDR_LEN);
    strip_ip_padding(skb, ip, frag);

    if (! cvsw_handle_fragment(skb, frag, (ntohs(ip->frag_off) & 0x1FFF) << 3)) {
	return false;
    }

    return cvsw_handle_vxlan_packet(skb);
}

static bool cvsw_apply_strip_vxlan(struct sk_buff *skb)
{
    struct iphdr *ip;
    off_t offset;
    __u32 key;

    offset = sizeof(struct ethhdr);

    if (unlikely(skb->len < offset + sizeof(struct iphdr))) {
	return false; /* Not an IP packet */
    }
    ip = (struct iphdr*)&skb->data[offset];
    offset += sizeof(struct iphdr);

    /* TBD: Verify IP checksum */

    key = ip->id ^ ip->saddr;

    if (ntohs(ip->frag_off) & 0x1FFF) {
	struct tun_fragment *frag;
	frag = cvsw_find_tunnel_frag_cb(key, ip->id);
	if (unlikely(! frag)) {
	    return false;
	}
	return cvsw_handle_vxlan_fragment(skb, ip, frag);
    } else if (ntohs(ip->frag_off) & 0x2000) {
	cvsw_register_vxlan_fragment(skb, ip, key);
	return false;
    }

    cvsw_handle_vxlan_packet(skb);

    return true;
}

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

    if (! cvsw_handle_fragment(skb, frag, (ntohs(ip->frag_off) & 0x1FFF) << 3)) {
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

static bool cvsw_apply_strip_stt(struct sk_buff *skb)
{
    struct iphdr   *ip;
    struct ptcphdr *ptcp;
    struct stthdr  *stt;
    off_t offset;
    __u32 key;

    offset = sizeof(struct ethhdr);

    if (unlikely(skb->len < offset + sizeof(struct iphdr))) {
	return false; /* Not an IP packet */
    }
    ip = (struct iphdr*)&skb->data[offset];
    offset += sizeof(struct iphdr);

    /* TBD: Verify IP checksum */

    key = ip->id ^ ip->saddr;

    if (ntohs(ip->frag_off) & 0x1FFF) {
	struct tun_fragment *frag;
	frag = cvsw_find_tunnel_frag_cb(key, ip->id);
	if (unlikely(! frag)) {
	    return false;
	}
	return cvsw_handle_stt_ip_fragment(skb, ip, frag);
    } else if (ntohs(ip->frag_off) & 0x2000) {
	cvsw_register_stt_fragment(skb, ip, NULL, ip->id, key);
	return false;
    }

    if (unlikely(skb->len < offset + sizeof(struct ptcphdr))) {
	return false; /* Not a TCP packet */
    }
    ptcp = (struct ptcphdr*)&skb->data[offset];
    offset += sizeof(struct ptcphdr);

    /* Validate PTCP's checksum */
    if (unlikely(! cvsw_check_ptcp_csum(skb, ip, ptcp))) {
	return false;
    }
    skb->ip_summed = CHECKSUM_UNNECESSARY;

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

static bool cvsw_apply_instruction(struct sk_buff *skb, const struct cvsw_instruction *inst)
{
    switch (inst->type) {
    case CVSW_INST_TYPE_DROP:
	return false;
    case CVSW_INST_TYPE_OUTPUT:
	cvsw_apply_output(skb, inst->out_port);
	break;
    case CVSW_INST_TYPE_SET_VLAN_VID:
	cvsw_apply_set_vlan_vid(skb, inst->vlan_vid);
	break;
    case CVSW_INST_TYPE_SET_VLAN_PCP:
	cvsw_apply_set_vlan_pcp(skb, inst->vlan_pcp);
	break;
    case CVSW_INST_TYPE_STRIP_VLAN:
	cvsw_apply_strip_vlan(skb);
	break;
    case CVSW_INST_TYPE_SET_DL_DST:
	memcpy(eth_hdr(skb)->h_dest, inst->dl_addr, ETH_ALEN);
	break;
    case CVSW_INST_TYPE_SET_DL_SRC:
	memcpy(eth_hdr(skb)->h_source, inst->dl_addr, ETH_ALEN);
	break;
    case CVSW_INST_TYPE_SET_NW_DST:
	cvsw_apply_set_nw_dst(skb, inst->nw_addr);
	break;
    case CVSW_INST_TYPE_SET_NW_SRC:
	cvsw_apply_set_nw_src(skb, inst->nw_addr);
	break;
    case CVSW_INST_TYPE_SET_NW_TOS:
	cvsw_apply_set_nw_tos(skb, inst->nw_tos);
	break;
    case CVSW_INST_TYPE_SET_TP_DST:
	cvsw_apply_set_tp_dst(skb, inst->tp_port);
	break;
    case CVSW_INST_TYPE_SET_TP_SRC:
	cvsw_apply_set_tp_src(skb, inst->tp_port);
	break;
    case CVSW_INST_TYPE_SET_VXLAN:
	cvsw_apply_set_vxlan(skb, &inst->tun_vxlan);
	break;
    case CVSW_INST_TYPE_STRIP_VXLAN:
	return cvsw_apply_strip_vxlan(skb);
    case CVSW_INST_TYPE_SET_STT:
	cvsw_apply_set_stt(skb, &inst->tun_stt);
	break;
    case CVSW_INST_TYPE_STRIP_STT:
	return cvsw_apply_strip_stt(skb);
    default:
	pr_warn("Unknown instruction : %d\n", inst->type);
	break;
    }

    return true;
}

static inline bool cvsw_do_instructions(struct sk_buff *skb, const struct cvsw_instruction *insts, const int nr_insts)
{
    int i;

    for (i = 0; i < nr_insts; i++) {
	if (unlikely(! cvsw_apply_instruction(skb, &insts[i]))) {
	    return false;
	}
    }

    return true;
}

extern bool cvsw_handle_data(struct sk_buff *skb, const __u16 in_port)
{
    struct list_head *flow_table;
    struct list_head *p;
    struct cvsw_flow_entry *entry;

    if (! skb_mac_header_was_set(skb)) {
	skb_reset_mac_header(skb);
    }

    flow_table = cvsw_get_flow_table();

    entry = NULL;
    list_for_each(p, flow_table) {
	entry = list_entry(p, struct cvsw_flow_entry, list);
	if (cvsw_do_match(skb, in_port, &entry->match)) {
	    break; /* Matched ! */
	}
	entry = NULL;
    }

    if (! entry) {
	return true; /* Not matched */
    }

    return cvsw_do_instructions(skb, entry->instructions, entry->nr_insts);
}
