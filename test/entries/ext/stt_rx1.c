/*
 * stt_rx1.c : CVSW stt test entries (receiver)
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
#include "../ext/openflow_ext.h"
#include "../ext/stt.h"
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
 * Set MTU size (1420)
 */
extern bool cvsw_test_add_entry1(struct net_device *dev)
{
    struct sk_buff *skb;
    struct cvsw_hdr hdr;

    init_cvsw_hdr(&hdr, 0);
    hdr.cvsw.type = CVSW_TYPE_CHANGE_MTU;
    hdr.cvsw.data = htons(1420);

    skb = cvsw_alloc_skb(sizeof(hdr), dev);
    if (! skb) {
	return false;
    }

    memcpy(skb_put(skb, sizeof(hdr)), &hdr, sizeof(hdr));

    cvsw_handle_ctl(skb);

    dev_kfree_skb(skb);

    return true;
}

/*
 * Set Offloading (CSUM, TSO, UFO, GSO, GRO)
 */
extern bool cvsw_test_add_entry2(struct net_device *dev)
{
    struct sk_buff *skb;
    struct cvsw_hdr hdr;

    init_cvsw_hdr(&hdr, 0);
    hdr.cvsw.type = CVSW_TYPE_CHANGE_OFFLOAD;
    hdr.cvsw.data = htons(CVSW_OFFLOAD_CSUM|
			  CVSW_OFFLOAD_TSO|CVSW_OFFLOAD_UFO|
			  CVSW_OFFLOAD_GSO|CVSW_OFFLOAD_GRO);

    skb = cvsw_alloc_skb(sizeof(hdr), dev);
    if (! skb) {
	return false;
    }

    memcpy(skb_put(skb, sizeof(hdr)), &hdr, sizeof(hdr));

    cvsw_handle_ctl(skb);

    dev_kfree_skb(skb);

    return true;
}

/*
 * Match  : IN_PORT (NET)
 * Action : STRIP_STT
 */
extern bool cvsw_test_add_entry3(struct net_device *dev)
{
    struct sk_buff *skb;
    struct cvsw_hdr hdr;
    struct ofp_flow_mod flow;
    struct ofp_action_header stt;

    init_cvsw_hdr(&hdr, sizeof(flow) + sizeof(stt));

    memset(&flow, 0, sizeof(flow));
    flow.header.type = OFPT_FLOW_MOD;
    flow.priority = htons(10000);

    flow.match.wildcards = htonl(OFPFW_ALL ^ OFPFW_IN_PORT);
    flow.match.in_port   = htons(CVSW_PORT_NET);

    memset(&stt, 0, sizeof(stt));
    stt.type = htons(OFPAT_EXT_STRIP_STT);
    stt.len  = htons(sizeof(stt));

    skb = cvsw_alloc_skb(sizeof(hdr) + sizeof(flow) + sizeof(stt), dev);
    if (! skb) {
	return false;
    }

    memcpy(skb_put(skb, sizeof(hdr)), &hdr, sizeof(hdr));
    memcpy(skb_put(skb, sizeof(flow)), &flow, sizeof(flow));
    memcpy(skb_put(skb, sizeof(stt)), &stt, sizeof(stt));

    cvsw_handle_ctl(skb);

    dev_kfree_skb(skb);
    
    return true;
}

/*
 * Match  : 
 * Action : 
 */
extern bool cvsw_test_add_entry4(struct net_device *dev)
{
    return true;
}

/*
 * Match  : 
 * Action : 
 */
extern bool cvsw_test_add_entry5(struct net_device *dev)
{
    return true;
}
