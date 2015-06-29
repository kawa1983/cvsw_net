/*
 * sclp.h : SCLP definition
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

#ifndef __SCLP_H_INCLUDED__
#define __SCLP_H_INCLUDED__

#include <linux/skbuff.h>

#ifndef IPPROTO_SCLP
#define IPPROTO_SCLP        234
#endif

#ifndef NEXTHDR_SCLP
#define NEXTHDR_SCLP        234
#endif

#define SCLP_ID_MASK        0xFFFFFFFE


struct sclphdr
{
    __be16 source;
    __be16 dest;
    __be32 id;
    __be16 rem;
    __be16 check;
} __attribute__ ((packed));


static inline struct sclphdr *sclp_hdr(const struct sk_buff *skb)
{
    return (struct sclphdr*)skb_transport_header(skb);
}

static inline void sclp_set_first_segment(struct sclphdr *sclp)
{
    sclp->id |= htonl(~SCLP_ID_MASK);
}

static inline bool sclp_is_first_segment(const struct sclphdr *sclp)
{
    return (sclp->id & htonl(~SCLP_ID_MASK));
}

#endif /* __SCLP_H_INCLUDED__ */
