/*
 * vxlan_sclp.c : VXLAN_SCLP processing
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
#include <linux/sclp.h>
#include <net/ip.h>
#include "../cvsw_flow_entry.h"
#include "../skb_util.h"
#include "tunnel.h"
#include "vxlan_sclp.h"


/***************************************************************************
 * Encapsulation
 ***************************************************************************/

static void cvsw_setup_tun_sclp_header(struct sclphdr *sclp)
{
    get_random_bytes(&sclp->id, sizeof(sclp->id));
    sclp->id &= ntohl(SCLP_ID_MASK);

    sclp_set_first_segment(sclp);

    sclp->source = cvsw_calc_tnl_src_port(&((__u8*)(sclp + 1))[sizeof(struct vxlanhdr)]);
    sclp->rem    = 0;
    sclp->check  = 0;
}


static void cvsw_set_sclp_csum(struct sk_buff *skb, struct sclphdr *sclp)
{
    if (skb->ip_summed == CHECKSUM_PARTIAL) {
	skb->csum_start  = skb_headroom(skb) + ETHERIP_HDR_LEN;
	skb->csum_offset = offsetof(struct sclphdr, check);
	sclp->check = csum_fold(skb_checksum(skb, ETHERIP_HDR_LEN, skb->len - ETHERIP_HDR_LEN, 0));
    } else {
	sclp->check = csum_fold(skb_checksum(skb, ETHERIP_HDR_LEN, skb->len - ETHERIP_HDR_LEN, 0));
	skb->ip_summed = CHECKSUM_UNNECESSARY;
    }
}


extern void cvsw_apply_set_vxlan_sclp(struct sk_buff *skb, const struct inst_vxlan_sclp *vxlan_sclp)
{
    off_t offset;

    if (unlikely(! skb_util_make_tunnel_space(skb, VXLAN_SCLP_HEADROOM_LEN))) {
	return ;
    }

    memcpy(skb->data, vxlan_sclp, sizeof(struct inst_vxlan_sclp));

    offset = sizeof(struct ethhdr);
    cvsw_setup_tun_ip_header((struct iphdr*)&skb->data[offset], skb->len - offset);
    offset += sizeof(struct iphdr);
    cvsw_setup_tun_sclp_header((struct sclphdr*)&skb->data[offset]);

    cvsw_set_sclp_csum(skb, (struct sclphdr*)&skb->data[offset]);

    if (skb_is_gso(skb)) {
	skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
	skb_shinfo(skb)->gso_size = 1468;
    }
}


/***************************************************************************
 * Decapsulation
 ***************************************************************************/


static bool cvsw_check_sclp_csum(struct sk_buff *skb, const struct sclphdr *sclp)
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
	csum = skb_checksum(skb, ETHERIP_HDR_LEN, skb->len - ETHERIP_HDR_LEN, 0);
    }

    return likely(csum_fold(csum) == 0);
}


static inline bool cvsw_handle_vxlan_sclp_frame(struct sk_buff *skb, const struct vxlanhdr *vxlan)
{
    cvsw_strip_tunnel(skb, VXLAN_SCLP_HEADROOM_LEN);

    skb->ip_summed = CHECKSUM_UNNECESSARY; /* Already validated */

    return true;
}


static inline void cvsw_register_vxlan_sclp_fragment(const struct sk_buff *skb, const struct iphdr *ip, const struct sclphdr *sclp, 
					       const __u32 id, const __u32 key)
{
    if (likely(skb->len > VXLAN_SCLP_HEADROOM_LEN + sizeof(struct ethhdr))) {
	const size_t this_len  = skb->len - (likely(sclp) ? (VXLAN_SCLP_HEADROOM_LEN - VXLAN_HDR_LEN) : ETHERIP_HDR_LEN);
	const size_t total_len = this_len + ntohs(((struct sclphdr*)(ip + 1))->rem);
	if (likely(this_len < total_len)) {
	    cvsw_register_tun_fragment(skb, id, this_len, total_len, key);
	}
    }
}


static inline bool cvsw_handle_vxlan_sclp_ip_fragment(struct sk_buff *skb, const struct iphdr *ip, struct tun_fragment *frag)
{
    skb_util_remove_tunnel_space(skb, ETHERIP_HDR_LEN);
    strip_ip_padding(skb, ip, frag);

    if (! cvsw_handle_fragment(skb, frag, (ntohs(ip->frag_off) & IP_OFFSET) << 3)) {
	return false;
    }

    return cvsw_handle_vxlan_sclp_frame(skb, (struct vxlanhdr*)&skb->data[VXLAN_SCLP_HEADROOM_LEN - VXLAN_HDR_LEN]);
}


static bool cvsw_handle_vxlan_sclp_sclp_fragment(struct sk_buff *skb, const struct sclphdr *sclp, struct tun_fragment *frag)
{
    size_t rem;

    skb_util_remove_tunnel_space(skb, VXLAN_SCLP_HEADROOM_LEN - VXLAN_HDR_LEN); /* Strip Ether/IP/SCLP headers */

    rem = skb->len + ntohs(sclp->rem);
    if (! cvsw_handle_fragment(skb, frag, frag->frame_size - rem)) {
	return false;
    }

    return cvsw_handle_vxlan_sclp_frame(skb, (struct vxlanhdr*)&skb->data[VXLAN_SCLP_HEADROOM_LEN - VXLAN_HDR_LEN]);
}


extern bool cvsw_apply_strip_vxlan_sclp(struct sk_buff *skb)
{
    struct iphdr    *ip;
    struct sclphdr  *sclp;
    struct vxlanhdr *vxlan;
    off_t offset;
    __u32 key;

    offset = sizeof(struct ethhdr);

    if (unlikely(skb->len < ETHERIP_HDR_LEN)) {
	return true; /* Not an IP packet */
    }
    ip = (struct iphdr*)&skb->data[offset];
    offset += sizeof(struct iphdr);

    if (ip->protocol != IPPROTO_SCLP) {
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
	return cvsw_handle_vxlan_sclp_ip_fragment(skb, ip, frag);
    } else if (ntohs(ip->frag_off) & IP_MF) {
	cvsw_register_vxlan_sclp_fragment(skb, ip, NULL, ip->id, key);
	return false;
    }

    if (unlikely(skb->len < offset + sizeof(struct sclphdr))) {
	return false; /* Not a SCLP packet */
    }
    sclp = (struct sclphdr*)&skb->data[offset];
    offset += sizeof(struct sclphdr);

    if (ntohs(sclp->dest) != VXLAN_PORT) {
	return false;
    }

    /* Validate SCLP's checksum */
    if (unlikely(! cvsw_check_sclp_csum(skb, sclp))) {
	return false;
    }

    key = (sclp->id & htonl(SCLP_ID_MASK)) ^ sclp->source ^ ip->saddr;

    if (! sclp_is_first_segment(sclp)) {
	struct tun_fragment *frag;
	frag = cvsw_find_tunnel_frag_cb(key, (sclp->id & htonl(SCLP_ID_MASK)));
	if (unlikely(! frag)) {
	    return false;
	}
	return cvsw_handle_vxlan_sclp_sclp_fragment(skb, sclp, frag);
    }

    if (unlikely(skb->len < VXLAN_SCLP_HEADROOM_LEN + sizeof(struct ethhdr))) {
	return false;
    }

    vxlan = (struct vxlanhdr*)&skb->data[offset];
    offset += sizeof(struct vxlanhdr);
    if (ntohs(sclp->rem) > 0) {
	cvsw_register_vxlan_sclp_fragment(skb, ip, sclp, sclp->id & htonl(SCLP_ID_MASK), key);
	return false;
    }

    cvsw_handle_vxlan_sclp_frame(skb, vxlan);

    return true;
}
