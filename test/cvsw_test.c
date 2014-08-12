/*
 * cvsw_test.c : CVSW test framework
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

#include "../cvsw_net.h"
#include "../cvsw_ctl.h"
#include "../openflow.h"
#include "cvsw_test.h"
#include "entries/cvsw_test_flow_entry.h"

extern struct sk_buff *cvsw_alloc_skb(size_t size, struct net_device *dev)
{
    struct sk_buff *skb;

    skb = dev_alloc_skb(size);
    if (! skb) {
	pr_err("Can't allocate skb\n");
	return NULL;
    }
    skb->protocol = htons(CVSW_ETH_TYPE);
    skb->dev = dev;
    skb->ip_summed = CHECKSUM_NONE;
    skb_reset_mac_header(skb);
    skb_reset_network_header(skb);
    skb_reset_transport_header(skb);

    return skb;
}

static bool cvsw_test_hello(struct net_device *dev)
{
    struct sk_buff *skb;
    struct cvsw_hdr hdr;

    memset(&hdr, 0, sizeof(struct cvsw_hdr));

    memset(hdr.dst_mac, 0xFF, ETH_ALEN);
    hdr.cvsw.version = CVSW_VERSION;
    hdr.cvsw.type    = CVSW_TYPE_HELLO;
    hdr.cvsw.len     = 0;
    hdr.cvsw.data    = 0;
    hdr.ether_type   = htons(CVSW_ETH_TYPE);

    skb = cvsw_alloc_skb(sizeof(struct cvsw_hdr), dev);
    if (! skb) {
	return NULL;
    }
    memcpy(skb_put(skb, sizeof(struct cvsw_hdr)), &hdr, sizeof(struct cvsw_hdr));

    cvsw_handle_ctl(skb);

    dev_kfree_skb(skb);

    return true;
}

static bool cvsw_test_setup_table(struct net_device *dev)
{
    if (! cvsw_test_add_entry1(dev)) {
	return false;
    }

    if (! cvsw_test_add_entry2(dev)) {
	return false;
    }

    if (! cvsw_test_add_entry3(dev)) {
	return false;
    }

    if (! cvsw_test_add_entry4(dev)) {
	return false;
    }

    if (! cvsw_test_add_entry5(dev)) {
	return false;
    }

    return true;
}

extern bool cvsw_test_start(struct net_device *dev)
{
    if (! cvsw_test_hello(dev)) {
	pr_err("Can't receive CVSW_HELLO\n");
	return false;
    }

    if (! cvsw_test_setup_table(dev)) {
	pr_err("Can't setup CVSW table\n");
	return false;
    }

    return true;
}
