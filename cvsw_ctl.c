/*
 * cvsw_ctl.c : CVSW message processing
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
#include <linux/netdevice.h>
#include "cvsw_net.h"
#include "cvsw_ctl.h"
#include "cvsw_table.h"

static bool cvsw_handle_hello_msg(const struct sk_buff *skb)
{
    struct sk_buff *reg_skb;
    struct cvsw_hdr cvsw_hdr;

    pr_info("Received a CVSW Hello message\n");

    if (unlikely(cvsw_state != CVSW_STATE_DISCONNECTED)) {
	pr_err("Duplicated CVSW hello messages\n");
	return false;
    }

    /* Set up CVSW header for registration */
    memset(&cvsw_hdr, 0, sizeof(cvsw_hdr));
    memcpy(cvsw_hdr.dst_mac, skb->dev->dev_addr, ETH_ALEN); /* To notify my address */
    cvsw_hdr.cvsw.version = CVSW_VERSION;
    cvsw_hdr.cvsw.type    = CVSW_TYPE_REGISTER;
    cvsw_hdr.ether_type   = htons(CVSW_ETH_TYPE);

    /* Create a skb for CVSW register message */
    reg_skb = dev_alloc_skb(sizeof(cvsw_hdr));
    if (unlikely(! reg_skb)) {
	pr_err("Can't allocate skb\n");
	return false;
    }

    memcpy(skb_put(reg_skb, sizeof(cvsw_hdr)), &cvsw_hdr, sizeof(cvsw_hdr));

    reg_skb->dev       = skb->dev;
    reg_skb->protocol  = cvsw_hdr.ether_type;
    reg_skb->ip_summed = CHECKSUM_NONE;

    if (likely(cvsw_xmit_skb(reg_skb))) {
	pr_info("Sent CVSW Register message\n");
	cvsw_state = CVSW_STATE_CONNECTING;
    } else {
	pr_err("Can't send REGISTER message\n");
    }

    return true;
}

static bool cvsw_handle_set_entry_msg(const struct sk_buff *skb)
{
    struct cvsw_hdr *cvsw_hdr;
    struct sk_buff *tmp_skb;
    __u8 *data;
    int len;

    pr_info("Received a CVSW Set Entry message\n");

    if (unlikely((cvsw_state != CVSW_STATE_CONNECTING) && 
		 (cvsw_state != CVSW_STATE_CONNECTED))) {
	pr_err("CVSW features have not been initialized yet\n");
	return false;
    } else if (cvsw_state == CVSW_STATE_CONNECTING) {
	cvsw_state = CVSW_STATE_CONNECTED;
    }

    cvsw_hdr = CVSW_HEADER(skb);
    len = ntohs(cvsw_hdr->cvsw.len); /* Flow mod len */

    /* Linearize the SKB */
    tmp_skb = skb_copy(skb, GFP_ATOMIC);
    if (unlikely(! tmp_skb)) {
	pr_err("Can't allocate memory\n");
	return false;
    }

    data = (__u8*)(CVSW_HEADER(tmp_skb) + 1);
    /* Add the CVSW table entry */
    if (unlikely(! cvsw_add_table_entry(data, len))) {
	pr_warn("Can't add a table entry\n");
	dev_kfree_skb_any(tmp_skb);
	return false;
    }

    dev_kfree_skb_any(tmp_skb);

    return true;
}

static bool cvsw_handle_delete_entry_msg(const struct sk_buff *skb)
{
    struct cvsw_hdr *cvsw_hdr;
    struct sk_buff *tmp_skb;
    __u8 *data;
    int len;

    pr_info("Received a CVSW Delete Entry message\n");

    if (unlikely(cvsw_state != CVSW_STATE_CONNECTED)) {
	pr_err("CVSW features have not been initialized yet\n");
	return false;
    }

    cvsw_hdr = CVSW_HEADER(skb);
    len = ntohl(cvsw_hdr->cvsw.len); /* Flow mod len */

    /* Linearize the SKB */
    tmp_skb = skb_copy(skb, GFP_ATOMIC);
    if (unlikely(! tmp_skb)) {
	pr_err("Can't allocate memory\n");
	return false;
    }

    data = (__u8*)(CVSW_HEADER(tmp_skb) + 1);    
    /* Delete the CVSW table entry */
    if (unlikely(! cvsw_delete_table_entry(data, len))) {
	pr_warn("Can't delete the table entry\n");
	dev_kfree_skb_any(tmp_skb);
	return false;
    }

    dev_kfree_skb_any(tmp_skb);

    return true;
}

static bool cvsw_handle_change_mtu_msg(const struct sk_buff *skb)
{
    struct cvsw_hdr *cvsw_hdr;

    pr_info("Received a CVSW MTU Change message\n");

    if (unlikely((cvsw_state != CVSW_STATE_CONNECTING) && 
		 (cvsw_state != CVSW_STATE_CONNECTED))) {
	pr_err("CVSW features have not been initialized yet\n");
	return false;
    } else if (cvsw_state == CVSW_STATE_CONNECTING) {
	cvsw_state = CVSW_STATE_CONNECTED;
    }

    cvsw_hdr = CVSW_HEADER(skb);

    return cvsw_change_mtu(skb->dev, ntohs(cvsw_hdr->cvsw.data));
}

static bool cvsw_handle_change_offload_msg(const struct sk_buff *skb)
{
    struct cvsw_hdr *cvsw_hdr;

    pr_info("Received a CVSW Offload Change message\n");

    if (unlikely((cvsw_state != CVSW_STATE_CONNECTING) && 
		 (cvsw_state != CVSW_STATE_CONNECTED))) {
	pr_err("CVSW features have not been initialized yet\n");
	return false;
    } else if (cvsw_state == CVSW_STATE_CONNECTING) {
	cvsw_state = CVSW_STATE_CONNECTED;
    }

    cvsw_hdr = CVSW_HEADER(skb);

    cvsw_change_offload(skb->dev, ntohs(cvsw_hdr->cvsw.data));

    return true;
}

extern void cvsw_handle_ctl(const struct sk_buff *skb)
{
    struct cvsw_hdr *cvsw_hdr;
    bool ret;

    pr_info("Received a CVSW message\n");

    cvsw_hdr = CVSW_HEADER(skb);

    ret = false;
    switch (cvsw_hdr->cvsw.type) {
    case CVSW_TYPE_HELLO:
	ret = cvsw_handle_hello_msg(skb);
	break;
    case CVSW_TYPE_SET_ENTRY:
	ret = cvsw_handle_set_entry_msg(skb);
	break;
    case CVSW_TYPE_DELETE_ENTRY:
	ret = cvsw_handle_delete_entry_msg(skb);
	break;
    case CVSW_TYPE_CHANGE_MTU:
	ret = cvsw_handle_change_mtu_msg(skb);
	break;
    case CVSW_TYPE_CHANGE_OFFLOAD:
	ret = cvsw_handle_change_offload_msg(skb);
	break;
    default:
	pr_warn("Unknown CVSW type : 0x0%X\n", cvsw_hdr->cvsw.type);
	break;
    }

    if (unlikely(! ret)) {
	/* TBD: Send an error message to the controller */
    }
}
