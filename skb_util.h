/*
 * skb_util.h : Utility functions for SKB
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

#ifndef __SKB_UTIL_H_INCLUDED__
#define __SKB_UTIL_H_INCLUDED__

struct sk_buff;

extern bool skb_util_make_vlan_space(struct sk_buff *skb);
extern void skb_util_remove_vlan_space(struct sk_buff *skb);

extern __u8 *skb_util_get_network_header(const struct sk_buff *skb);
extern __u8 *skb_util_get_transport_header(const struct sk_buff *skb);
extern __u8 *skb_util_get_transport_header_nw(const __u8 *nw);

#endif /* __SKB_UTIL_H_INCLUDED__ */
