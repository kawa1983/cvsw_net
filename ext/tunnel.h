/*
 * tunnel.h : Common tunnel processing
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

#ifndef __CVSW_TUNNEL_H_INCLUDED__
#define __CVSW_TUNNEL_H_INCLUDED__

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include "../cvsw_flow_entry.h"
#include "../cvsw_table.h"

#define ETHERIP_HDR_LEN (sizeof(struct ethhdr) + sizeof(struct iphdr))

extern __be16 cvsw_calc_tnl_src_port(const __u8 *inner);

extern bool   cvsw_calc_inner_csum(struct sk_buff *skb, size_t headroom_len);

extern void   cvsw_setup_tun_ip_header(struct iphdr *ip, const __u16 len);

extern void   cvsw_setup_tun_udp_header(struct udphdr *udp, const __u16 len);

extern void   cvsw_strip_tunnel(struct sk_buff *skb, const size_t len);

extern void   strip_ip_padding(struct sk_buff *skb, const struct iphdr *ip, const struct tun_fragment *frag);

extern void   cvsw_register_tun_fragment(const struct sk_buff *skb, const __u32 frame_id, const off_t frag_off, 
					 const __u32 frame_size, const __u32 key);

extern bool   cvsw_handle_fragment(struct sk_buff *skb, struct tun_fragment *frag, const off_t frag_off);

#endif /* __CVSW_TUNNEL_H_INCLUDED__ */
