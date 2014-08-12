/*
 * cvsw_table.c : Flow table management
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
#include <linux/list_sort.h>
#include "openflow.h"
#include "cvsw_net.h"
#include "cvsw_table.h"
#include "cvsw_flow_entry.h"

static LIST_HEAD(flow_table);  /* OpenFlow-based flow table */


static int entry_sort_cmp(void *priv, struct list_head *a, struct list_head *b)
{
    struct cvsw_flow_entry *entry_a;
    struct cvsw_flow_entry *entry_b;

    entry_a = list_entry(a, struct cvsw_flow_entry, list);
    entry_b = list_entry(b, struct cvsw_flow_entry, list);

    if (entry_a->priority > entry_b->priority) {
	return -1;
    } else if (entry_a->priority < entry_b->priority) {
	return 1;
    }
    return 0;
}

static struct cvsw_flow_entry *cvsw_create_entry(void)
{
    struct cvsw_flow_entry *entry;

    entry = kzalloc(sizeof(struct cvsw_flow_entry), GFP_ATOMIC);
    if (unlikely(! entry)) {
	pr_err("Can't allocate memory\n");
    }

    return entry;
}

static void cvsw_delete_entry(struct cvsw_flow_entry *entry)
{
    if (entry) {
	if (entry->instructions) {
	    kfree(entry->instructions);
	    entry->instructions = NULL;
	}
	if (entry->list.next || entry->list.prev) {
	    list_del(&entry->list);
	    entry->list.next = entry->list.prev = NULL;
	}
	kfree(entry);
    }
}

static void cvsw_set_entry_match(struct cvsw_match *cvsw, const struct ofp_match *ofp)
{
    cvsw->wildcards = ntohl(ofp->wildcards);

    if (~cvsw->wildcards & OFPFW_IN_PORT) {
	cvsw->in_port = ntohs(ofp->in_port);
    }
    if (~cvsw->wildcards & OFPFW_DL_VLAN) {
	cvsw->dl_vlan_vid = ofp->dl_vlan;
    }
    if (~cvsw->wildcards & OFPFW_DL_VLAN_PCP) {
        cvsw->dl_vlan_pcp = ofp->dl_vlan_pcp;
    }
    if (~cvsw->wildcards & OFPFW_DL_SRC) {
        memcpy(cvsw->dl_src, ofp->dl_src, ETH_ALEN);
    }
    if (~cvsw->wildcards & OFPFW_DL_DST) {
        memcpy(cvsw->dl_dst, ofp->dl_dst, ETH_ALEN);
    }
    if (~cvsw->wildcards & OFPFW_DL_TYPE) {
        cvsw->dl_type = ofp->dl_type;
    }
    if (~cvsw->wildcards & OFPFW_NW_PROTO) {
        cvsw->nw_proto = ofp->nw_proto;
    }
    if (~cvsw->wildcards & OFPFW_NW_SRC_ALL) {
        memcpy(cvsw->nw_src, &ofp->nw_src, 4);
    }
    if (~cvsw->wildcards & OFPFW_NW_DST_ALL) {
	memcpy(cvsw->nw_dst, &ofp->nw_dst, 4);
    }
    if (~cvsw->wildcards & OFPFW_TP_SRC) {
        cvsw->tp_src = ofp->tp_src;
    }
    if (~cvsw->wildcards & OFPFW_TP_DST) {
	cvsw->tp_dst = ofp->tp_dst;
    }
}

static int cvsw_parse_instructions_len(const __u8 *data, const int data_len)
{
    int nr_insts;
    int rem_data_len;
    __u8 *instruction;

    instruction  = (__u8*)data;
    nr_insts     = 0;
    rem_data_len = data_len;
    while (rem_data_len >= sizeof(struct ofp_action_header)) {
	__u16 len;

	len  = ntohs(((struct ofp_action_header*)instruction)->len);
	if ((len < sizeof(struct ofp_action_header)) || 
	    (len > rem_data_len)) {
	    pr_warn("Invalid instruction size : %d\n", len);
	    return -1;
	}
	instruction  += len;
	rem_data_len -= len;
	nr_insts++;
    }

    if (rem_data_len > 0) {
	pr_warn("Remaining instruction : %d bytes\n", rem_data_len);
    }

    return nr_insts;
}

static bool cvsw_set_output_instruction(struct cvsw_instruction *inst, const __u8 *data, const int len)
{
    struct ofp_action_output *action;

    if (unlikely(sizeof(struct ofp_action_output) != len)) {
	return false;
    }

    action = (struct ofp_action_output*)data;

    if (action->port == htons(OFPP_NONE)) {
	inst->type = CVSW_INST_TYPE_DROP;
	pr_info("ADD Drop instruction\n");
    } else {
	inst->type = CVSW_INST_TYPE_OUTPUT;
	inst->out_port = ntohs(action->port);
	pr_info("ADD Output instruction : port %d\n", inst->out_port);
    }

    return true;
}

static bool cvsw_set_vlan_vid_instruction(struct cvsw_instruction *inst, const __u8 *data, const int len)
{
    struct ofp_action_vlan_vid *action;

    if (unlikely(sizeof(struct ofp_action_vlan_vid) != len)) {
	return false;
    }

    action = (struct ofp_action_vlan_vid*)data;

    inst->type     = CVSW_INST_TYPE_SET_VLAN_VID;
    inst->vlan_vid = action->vlan_vid;

    pr_info("ADD VLAN instruction : VID = %d\n", ntohs(inst->vlan_vid));

    return true;
}

static bool cvsw_set_vlan_pcp_instruction(struct cvsw_instruction *inst, const __u8 *data, const int len)
{
    struct ofp_action_vlan_pcp *action;

    if (unlikely(sizeof(struct ofp_action_vlan_pcp) != len)) {
	return false;
    }

    action = (struct ofp_action_vlan_pcp*)data;

    inst->type     = CVSW_INST_TYPE_SET_VLAN_PCP;
    inst->vlan_pcp = action->vlan_pcp;

    pr_info("Add VLAN instruction : PCP = %d\n", inst->vlan_pcp);

    return true;
}

static bool cvsw_set_strip_vlan_instruction(struct cvsw_instruction *inst)
{
    inst->type = CVSW_INST_TYPE_STRIP_VLAN;

    pr_info("Add strip VLAN instruction\n");

    return true;
}

static bool cvsw_set_dl_addr_instruction(struct cvsw_instruction *inst, const __u8 *data, const int len)
{
    struct ofp_action_dl_addr *action;

    if (unlikely(sizeof(struct ofp_action_dl_addr) != len)) {
	return false;
    }

    action = (struct ofp_action_dl_addr*)data;

    if (action->type == htons(OFPAT_SET_DL_DST)) {
	inst->type = CVSW_INST_TYPE_SET_DL_DST;
    } else if (action->type == htons(OFPAT_SET_DL_SRC)) {
	inst->type = CVSW_INST_TYPE_SET_DL_SRC;
    } else {
	return false;
    }

    memcpy(inst->dl_addr, action->dl_addr, ETH_ALEN);

    pr_info("Add DL address instruction : %2X:%2X:%2X:%2X:%2X:%2X\n",
	    inst->dl_addr[0], inst->dl_addr[1], inst->dl_addr[2],
	    inst->dl_addr[3], inst->dl_addr[4], inst->dl_addr[5]);

    return true;
}

static bool cvsw_set_nw_addr_instruction(struct cvsw_instruction *inst, const __u8 *data, const int len)
{
    struct ofp_action_nw_addr *action;

    if (unlikely(sizeof(struct ofp_action_nw_addr) != len)) {
	return false;
    }

    action = (struct ofp_action_nw_addr*)data;

    if (action->type == htons(OFPAT_SET_NW_DST)) {
	inst->type = CVSW_INST_TYPE_SET_NW_DST;
    } else if (action->type == htons(OFPAT_SET_NW_SRC)) {
	inst->type = CVSW_INST_TYPE_SET_NW_SRC;
    } else {
	return false;
    }

    memcpy(inst->nw_addr, &action->nw_addr, 4);

    pr_info("Add NW address : %d.%d.%d.%d\n", 
	    inst->nw_addr[0], inst->nw_addr[1],
	    inst->nw_addr[2], inst->nw_addr[3]);

    return true;
}

static bool cvsw_set_nw_tos_instruction(struct cvsw_instruction *inst, const __u8 *data, const int len)
{
    struct ofp_action_nw_tos *action;

    if (unlikely(sizeof(struct ofp_action_nw_tos) != len)) {
	return false;
    }

    action = (struct ofp_action_nw_tos*)data;

    inst->type   = CVSW_INST_TYPE_SET_NW_TOS;
    inst->nw_tos = action->nw_tos;

    pr_info("Add NW ToS : %d\n", inst->nw_tos);

    return true;
}

static bool cvsw_set_tp_port_instruction(struct cvsw_instruction *inst, const __u8 *data, const int len)
{
    struct ofp_action_tp_port *action;

    if (unlikely(sizeof(struct ofp_action_tp_port) != len)) {
	return false;
    }

    action = (struct ofp_action_tp_port*)data;

    if (action->type == htons(OFPAT_SET_TP_DST)) {
	inst->type = CVSW_INST_TYPE_SET_TP_DST;
    } else if (action->type == htons(OFPAT_SET_TP_SRC)) {
	inst->type = CVSW_INST_TYPE_SET_TP_SRC;
    } else {
	return false;
    }

    inst->tp_port = action->tp_port;

    pr_info("Add TP port : %d\n", ntohs(inst->tp_port));

    return true;
}

static bool cvsw_set_entry_instructions_impl(struct cvsw_instruction *insts, const int nr_insts, const __u8 *data)
{
    int i;

    for (i = 0; i < nr_insts; i++) {
	__u16 type;
	__u16 len;
	bool  ret;

	type = ntohs(((struct ofp_action_header*)data)->type);
	len  = ntohs(((struct ofp_action_header*)data)->len);
	ret  = false;

	switch (type) {
	case OFPAT_OUTPUT:
	    ret = cvsw_set_output_instruction(&insts[i], data, len);
	    break;
	case OFPAT_SET_VLAN_VID:
	    ret = cvsw_set_vlan_vid_instruction(&insts[i], data, len);
	    break;
	case OFPAT_SET_VLAN_PCP:
	    ret = cvsw_set_vlan_pcp_instruction(&insts[i], data, len);
	    break;
	case OFPAT_STRIP_VLAN:
	    ret = cvsw_set_strip_vlan_instruction(&insts[i]);
	    break;
	case OFPAT_SET_DL_SRC:
	case OFPAT_SET_DL_DST:
	    ret = cvsw_set_dl_addr_instruction(&insts[i], data, len);
	    break;
	case OFPAT_SET_NW_SRC:
	case OFPAT_SET_NW_DST:
	    ret = cvsw_set_nw_addr_instruction(&insts[i], data, len);
	    break;
	case OFPAT_SET_NW_TOS:
	    ret = cvsw_set_nw_tos_instruction(&insts[i], data, len);
	    break;
	case OFPAT_SET_TP_SRC:
	case OFPAT_SET_TP_DST:
	    ret = cvsw_set_tp_port_instruction(&insts[i], data, len);
	    break;
	default:
	    pr_warn("Unsupported instruction type : %d\n", type);
	    break;
	}

	if (unlikely(! ret)) {
	    return false;
	}

	data += len;
    }

    return true;
}

static bool cvsw_set_entry_instructions(struct cvsw_flow_entry *entry, const __u8 *data, const int len)
{
    int nr_insts;

    nr_insts = cvsw_parse_instructions_len(data, len);
    if (nr_insts < 0) {
	return false;
    } else if (nr_insts == 0) {
	return true;
    }

    entry->nr_insts = (__u16)nr_insts;

    entry->instructions = kzalloc(sizeof(struct cvsw_instruction) * nr_insts, GFP_ATOMIC);
    if (unlikely(! entry->instructions)) {
	pr_err("Can't allocate memory\n");
	return false;
    }

    return cvsw_set_entry_instructions_impl(entry->instructions, nr_insts, data);
}

extern struct list_head *cvsw_get_flow_table(void)
{
    return &flow_table;
}

extern bool cvsw_add_table_entry(const __u8 *data, const int len)
{
    struct ofp_flow_mod *flow_mod;
    struct cvsw_flow_entry *entry;
    __u8 *inst_data;
    int inst_len;

    if (len < sizeof(struct ofp_flow_mod)) {
	pr_err("Too short entry : %d\n", len);
	return false;
    }

    flow_mod = (struct ofp_flow_mod*)data;
    inst_data = (__u8*)(flow_mod + 1);
    inst_len  = len - sizeof(struct ofp_flow_mod);

    entry = cvsw_create_entry();
    if (unlikely(! entry)) {
	pr_err("Can't create flow entry\n");
	return false;
    }

    entry->priority = ntohs(flow_mod->priority);

    cvsw_set_entry_match(&entry->match, &flow_mod->match);

    if (unlikely(! cvsw_set_entry_instructions(entry, inst_data, inst_len))) {
	pr_err("Can't setup entry instructions\n");
	cvsw_delete_entry(entry);
	return false;
    }

    list_add(&entry->list, &flow_table);

    list_sort(NULL, &flow_table, entry_sort_cmp);

    return true;
}

static bool is_same_entry(const struct ofp_flow_mod *flow_mod, const struct cvsw_flow_entry *entry, const bool strict)
{
    if (strict) {
	if (ntohs(flow_mod->priority) != entry->priority) {
	    return false;
	}
	if (ntohl(flow_mod->match.wildcards) != entry->match.wildcards) {
	    return false;
	}
    }
    if (~flow_mod->match.wildcards & OFPFW_IN_PORT) {
	if (ntohs(flow_mod->match.in_port) != entry->match.in_port) {
	    return false;
	}
    }
    if (~flow_mod->match.wildcards & OFPFW_DL_SRC) {
	if (memcmp(flow_mod->match.dl_src, entry->match.dl_src, ETH_ALEN) != 0) {
	    return false;
	}
    }
    if (~flow_mod->match.wildcards & OFPFW_DL_DST) {
	if (memcmp(flow_mod->match.dl_dst, entry->match.dl_dst, ETH_ALEN) != 0) {
	    return false;
	}
    }
    if (~flow_mod->match.wildcards & OFPFW_DL_TYPE) {
	if (flow_mod->match.dl_type != entry->match.dl_type) {
	    return false;
	}
    }
    if (~flow_mod->match.wildcards & OFPFW_DL_VLAN) {
	if (flow_mod->match.dl_vlan != entry->match.dl_vlan_vid) {
	    return false;
	}
    }
    if (~flow_mod->match.wildcards & OFPFW_DL_VLAN_PCP) {
	if (flow_mod->match.dl_vlan_pcp != entry->match.dl_vlan_pcp) {
	    return false;
	}
    }
    if (~flow_mod->match.wildcards & OFPFW_NW_TOS) {
	if (flow_mod->match.nw_tos != entry->match.nw_tos) {
	    return false;
	}
    }
    if (~flow_mod->match.wildcards & OFPFW_NW_PROTO) {
	if (flow_mod->match.nw_proto != entry->match.nw_proto) {
	    return false;
	}
    }
    if (~flow_mod->match.wildcards & OFPFW_NW_SRC_ALL) {
	if (memcmp(&flow_mod->match.nw_src, entry->match.nw_src, 4) != 0) {
	    return false;
	}
    }
    if (~flow_mod->match.wildcards & OFPFW_NW_DST_ALL) {
	if (memcmp(&flow_mod->match.nw_dst, entry->match.nw_dst, 4) != 0) {
	    return false;
	}
    }
    if (~flow_mod->match.wildcards & OFPFW_TP_SRC) {
	if (flow_mod->match.tp_src != entry->match.tp_src) {
	    return false;
	}
    }
    if (~flow_mod->match.wildcards & OFPFW_TP_DST) {
	if (flow_mod->match.tp_dst != entry->match.tp_dst) {
	    return false;
	}
    }
    return true;
}

extern bool cvsw_delete_table_entry(const __u8 *data, const int len)
{
    struct ofp_flow_mod *flow_mod;
    struct cvsw_flow_entry *entry;
    struct list_head *flow_table;
    struct list_head *p;

    if (len < sizeof(struct ofp_flow_mod)) {
	pr_err("Too short entry : %d\n", len);
	return false;
    }

    flow_mod = (struct ofp_flow_mod*)data;

    if ((ntohs(flow_mod->command) != OFPFC_DELETE) && 
	(ntohs(flow_mod->command) != OFPFC_DELETE_STRICT)) {
	pr_err("Invalid flow_mod command : %d\n", ntohs(flow_mod->command));
	return false;
    }

    flow_table = cvsw_get_flow_table();

    list_for_each(p, flow_table) {
	entry = list_entry(p, struct cvsw_flow_entry, list);
	if (is_same_entry(flow_mod, entry, ntohs(flow_mod->command) == OFPFC_DELETE_STRICT)) {
	    cvsw_delete_entry(entry);
	}
    }

    return true;
}

extern void cvsw_cleanup_table(void)
{
    struct cvsw_flow_entry *entry;

    while (! list_empty(&flow_table)) {
	entry = list_entry(flow_table.next, struct cvsw_flow_entry, list);
	cvsw_delete_entry(entry);
    }
}
