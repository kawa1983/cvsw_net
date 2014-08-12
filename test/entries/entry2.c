/*
 * entry1.c : CVSW basic test entries (receiver)
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

#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include "../cvsw_net.h"
#include "../cvsw_ctl.h"
#include "../openflow.h"
#include "cvsw_test.h"
#include "entries/cvsw_test_flow_entry.h"

static void init_cvsw_hdr(struct cvsw_hdr *hdr, int len)
{
    memset(hdr->dst_mac, 0xFF, ETH_ALEN);
    hdr->cvsw.version = CVSW_VERSION;
    hdr->cvsw.type    = CVSW_TYPE_SET_ENTRY;
    hdr->cvsw.len     = htons((__u16)len);
    hdr->cvsw.data    = 0;
    hdr->ether_type   = htons(CVSW_ETH_TYPE);
}

/*
 * Match  : IN_PORT (NET)
 * Match  : DL_DST (FF:FF:FF:FF:FF:FF)
 * Action : DL_DST (52:54:00:22:22:22)
 */
extern bool cvsw_test_add_entry1(struct net_device *dev)
{
    struct sk_buff *skb;
    struct cvsw_hdr hdr;
    struct ofp_flow_mod flow;
    struct ofp_action_dl_addr addr;

    init_cvsw_hdr(&hdr, sizeof(flow) + sizeof(addr));

    memset(&flow, 0, sizeof(flow));
    flow.header.type = OFPT_FLOW_MOD;
    flow.priority = htons(10000);

    flow.match.wildcards = htonl(OFPFW_ALL ^ OFPFW_IN_PORT ^ OFPFW_DL_DST);
    flow.match.in_port   = htons(CVSW_PORT_NET);
    flow.match.dl_dst[0] = 0xFF;
    flow.match.dl_dst[1] = 0xFF;
    flow.match.dl_dst[2] = 0xFF;
    flow.match.dl_dst[3] = 0xFF;
    flow.match.dl_dst[4] = 0xFF;
    flow.match.dl_dst[5] = 0xFF;

    memset(&addr, 0, sizeof(addr));
    addr.type = htons(OFPAT_SET_DL_DST);
    addr.len  = htons(sizeof(addr));
    addr.dl_addr[0] = 0x52;
    addr.dl_addr[1] = 0x54;
    addr.dl_addr[2] = 0x00;
    addr.dl_addr[3] = 0x22;
    addr.dl_addr[4] = 0x22;
    addr.dl_addr[5] = 0x22;

    skb = cvsw_alloc_skb(sizeof(hdr) + sizeof(flow) + sizeof(addr), dev);
    if (! skb) {
	return false;
    }

    memcpy(skb_put(skb, sizeof(hdr)), &hdr, sizeof(hdr));
    memcpy(skb_put(skb, sizeof(flow)), &flow, sizeof(flow));
    memcpy(skb_put(skb, sizeof(addr)), &addr, sizeof(addr));

    cvsw_handle_ctl(skb);

    dev_kfree_skb(skb);
    
    return true;
}

/*
 * Match  : IN_PORT (NET)
 * Match  : NW_SRC (172.16.0.1)
 * Action : NW_SRC (192.168.0.1)
 */
extern bool cvsw_test_add_entry2(struct net_device *dev)
{
    struct sk_buff *skb;
    struct cvsw_hdr hdr;
    struct ofp_flow_mod flow;
    struct ofp_action_nw_addr addr;

    init_cvsw_hdr(&hdr, sizeof(flow) + sizeof(addr));
    flow.header.type = OFPT_FLOW_MOD;
    flow.priority = htons(10001);

    flow.match.wildcards = htonl(OFPFW_ALL ^ OFPFW_IN_PORT ^ OFPFW_NW_SRC_ALL);
    flow.match.in_port   = htons(CVSW_PORT_NET);
    flow.match.nw_src    = htonl(
	(172 << 24) + (16 << 16) + 1
	);

    memset(&addr, 0, sizeof(addr));
    addr.type = htons(OFPAT_SET_NW_SRC);
    addr.len  = htons(sizeof(addr));
    addr.nw_addr = htonl(
	(192 << 24) + (168 << 16) + 1
	);

    skb = cvsw_alloc_skb(sizeof(hdr) + sizeof(flow) + sizeof(addr), dev);
    if (! skb) {
	return false;
    }

    memcpy(skb_put(skb, sizeof(hdr)), &hdr, sizeof(hdr));
    memcpy(skb_put(skb, sizeof(flow)), &flow, sizeof(flow));
    memcpy(skb_put(skb, sizeof(addr)), &addr, sizeof(addr));

    cvsw_handle_ctl(skb);

    dev_kfree_skb(skb);

    return true;
}

/*
 * Match  : IN_PORT (NET)
 * Match  : TP_SRC (65535)
 * Action : TP_SRC (44444)
 */
extern bool cvsw_test_add_entry3(struct net_device *dev)
{
    struct sk_buff *skb;
    struct cvsw_hdr hdr;
    struct ofp_flow_mod flow;
    struct ofp_action_tp_port port;

    init_cvsw_hdr(&hdr, sizeof(flow) + sizeof(port));
    flow.header.type = OFPT_FLOW_MOD;
    flow.priority = htons(10002);

    flow.match.wildcards = htonl(OFPFW_ALL ^ OFPFW_IN_PORT ^ OFPFW_TP_SRC);
    flow.match.in_port   = htons(CVSW_PORT_NET);
    flow.match.tp_src    = htons(65535);

    memset(&port, 0, sizeof(port));
    port.type    = htons(OFPAT_SET_TP_SRC);
    port.len     = htons(sizeof(port));
    port.tp_port = htons(44444);

    skb = cvsw_alloc_skb(sizeof(hdr) + sizeof(flow) + sizeof(port), dev);
    if (! skb) {
	return false;
    }

    memcpy(skb_put(skb, sizeof(hdr)), &hdr, sizeof(hdr));
    memcpy(skb_put(skb, sizeof(flow)), &flow, sizeof(flow));
    memcpy(skb_put(skb, sizeof(port)), &port, sizeof(port));

    cvsw_handle_ctl(skb);

    dev_kfree_skb(skb);

    return true;
}

/*
 * Match  : IN_PORT (NET)
 * Match  : VLAN_VID (10)
 * Action : STRIP_VLAN
 */
extern bool cvsw_test_add_entry4(struct net_device *dev)
{
    struct sk_buff *skb;
    struct cvsw_hdr hdr;
    struct ofp_flow_mod flow;
    struct ofp_action_header vlan;

    init_cvsw_hdr(&hdr, sizeof(flow) + sizeof(vlan));
    flow.header.type = OFPT_FLOW_MOD;
    flow.priority = htons(10003);

    flow.match.wildcards = htonl(OFPFW_ALL ^ OFPFW_IN_PORT ^ OFPFW_DL_VLAN);
    flow.match.in_port   = htons(CVSW_PORT_NET);
    flow.match.dl_vlan   = htons(10);

    memset(&vlan, 0, sizeof(vlan));
    vlan.type     = htons(OFPAT_STRIP_VLAN);
    vlan.len      = htons(sizeof(vlan));

    skb = cvsw_alloc_skb(sizeof(hdr) + sizeof(flow) + sizeof(vlan), dev);
    if (! skb) {
	return false;
    }

    memcpy(skb_put(skb, sizeof(hdr)), &hdr, sizeof(hdr));
    memcpy(skb_put(skb, sizeof(flow)), &flow, sizeof(flow));
    memcpy(skb_put(skb, sizeof(vlan)), &vlan, sizeof(vlan));

    cvsw_handle_ctl(skb);

    dev_kfree_skb(skb);

    return true;
}

/*
 * Match  : IN_PORT (NET)
 * Match  : VLAN_VID (20)
 * Match  : TP_SRC (50000)
 * Action : DL_SRC (52:54:00:11:11:11)
 * Action : NW_DST (192.168.0.2)
 * Action : NW_TOS (0x80)
 * Action : TP_SRC (65535)
 * Action : STRIP_VLAN
 */
extern bool cvsw_test_add_entry5(struct net_device *dev)
{
    struct sk_buff *skb;
    struct cvsw_hdr hdr;
    struct ofp_flow_mod flow;
    struct ofp_action_dl_addr dl_addr;
    struct ofp_action_nw_addr nw_addr;
    struct ofp_action_nw_tos  nw_tos;
    struct ofp_action_tp_port port;
    struct ofp_action_header  vlan;
    size_t len;

    len = sizeof(hdr) + sizeof(flow) + sizeof(dl_addr) + sizeof(nw_addr) + 
	sizeof(nw_tos) + sizeof(port) + sizeof(vlan);

    init_cvsw_hdr(&hdr, len - sizeof(hdr));
    flow.header.type = OFPT_FLOW_MOD;
    flow.priority = htons(10004);

    flow.match.wildcards = htonl(OFPFW_ALL ^ OFPFW_IN_PORT ^ OFPFW_DL_VLAN ^ OFPFW_TP_SRC);
    flow.match.in_port   = htons(CVSW_PORT_NET);
    flow.match.dl_vlan   = htons(20);
    flow.match.tp_src    = htons(50000);

    /* DL_SRC */
    memset(&dl_addr, 0, sizeof(dl_addr));
    dl_addr.type = htons(OFPAT_SET_DL_SRC);
    dl_addr.len  = htons(sizeof(dl_addr));
    dl_addr.dl_addr[0] = 0x52;
    dl_addr.dl_addr[1] = 0x54;
    dl_addr.dl_addr[2] = 0x00;
    dl_addr.dl_addr[3] = 0x11;
    dl_addr.dl_addr[4] = 0x11;
    dl_addr.dl_addr[5] = 0x11;

    /* NW_DST */
    memset(&nw_addr, 0, sizeof(nw_addr));
    nw_addr.type = htons(OFPAT_SET_NW_DST);
    nw_addr.len  = htons(sizeof(nw_addr));
    nw_addr.nw_addr = htonl(
	(192 << 24) + (168 << 16) + 2
	);

    /* NW_TOS */
    memset(&nw_tos, 0, sizeof(nw_tos));
    nw_tos.type   = htons(OFPAT_SET_NW_TOS);
    nw_tos.len    = htons(sizeof(nw_tos));
    nw_tos.nw_tos = 0x80;

    /* TP_SRC */
    memset(&port, 0, sizeof(port));
    port.type    = htons(OFPAT_SET_TP_SRC);
    port.len     = htons(sizeof(port));
    port.tp_port = htons(65535);

    /* VLAN_VID */
    memset(&vlan, 0, sizeof(vlan));
    vlan.type     = htons(OFPAT_STRIP_VLAN);
    vlan.len      = htons(sizeof(vlan));

    skb = cvsw_alloc_skb(len, dev);
    if (! skb) {
	return false;
    }

    memcpy(skb_put(skb, sizeof(hdr)), &hdr, sizeof(hdr));
    memcpy(skb_put(skb, sizeof(flow)), &flow, sizeof(flow));
    memcpy(skb_put(skb, sizeof(dl_addr)), &dl_addr, sizeof(dl_addr));
    memcpy(skb_put(skb, sizeof(nw_addr)), &nw_addr, sizeof(nw_addr));
    memcpy(skb_put(skb, sizeof(nw_tos)), &nw_tos, sizeof(nw_tos));
    memcpy(skb_put(skb, sizeof(port)), &port, sizeof(port));
    memcpy(skb_put(skb, sizeof(vlan)), &vlan, sizeof(vlan));

    cvsw_handle_ctl(skb);

    dev_kfree_skb(skb);

    return true;
}
