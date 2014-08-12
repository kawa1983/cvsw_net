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
    if ((csum == 0) && (protocol == IPPROTO_UDP)) {
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
