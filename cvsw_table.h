/*
 * cvsw_table.h : Flow table management
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

#ifndef __CVSW_TABLE_H_INCLUDED__
#define __CVSW_TABLE_H_INCLUDED__

struct sk_buff;
struct hlist_node;

struct tun_fragment
{
    __be32            id;
    off_t             next_idx;
    size_t            frame_size;
    struct sk_buff   *skb;
    struct hlist_node list;
};

struct list_head;
extern struct list_head *cvsw_get_flow_table(void);

extern bool cvsw_add_table_entry(const __u8 *data, const int len);
extern bool cvsw_delete_table_entry(const __u8 *data, const int len);
extern void cvsw_add_tunnel_frag_cb(struct tun_fragment *frag, const __u32 key);
extern void cvsw_delete_tunnel_frag_cb(struct hlist_node *node);
extern struct tun_fragment *cvsw_find_tunnel_frag_cb(const __u32 key, const __u32 id);
extern void cvsw_cleanup_table(void);

#endif /* __CVSW_TABLE_H_INCLUDED__ */
