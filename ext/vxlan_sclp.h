/*
 * vxlan_sclp.h : VXLAN_SCLP definition
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

#ifndef __CVSW_EXT_VXLAN_SCLP_H_INCLUDED__
#define __CVSW_EXT_VXLAN_SCLP_H_INCLUDED__

#include "vxlan.h"

#define VXLAN_SCLP_HEADROOM_LEN 54


struct sk_buff;
struct inst_vxlan_sclp;
extern void cvsw_apply_set_vxlan_sclp(struct sk_buff *skb, const struct inst_vxlan_sclp *vxlan_sclp);
extern bool cvsw_apply_strip_vxlan_sclp(struct sk_buff *skb);

#endif /* __CVSW_EXT_VXLAN_SCLP_H_INCLUDED__ */
