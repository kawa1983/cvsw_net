/*
 * cvsw_test.h : CVSW test framework
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

#ifndef __CVSW_TEST_H_INCLUDED__
#define __CVSW_TEST_H_INCLUDED__

struct sk_buff;
struct net_device;

extern bool cvsw_test_start(struct net_device *dev);
extern struct sk_buff *cvsw_alloc_skb(size_t size, struct net_device *dev);

#endif /* __CVSW_TEST_H_INCLUDED__ */
