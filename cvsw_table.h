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

struct list_head;
extern struct list_head *cvsw_get_flow_table(void);

extern bool cvsw_add_table_entry(const __u8 *data, const int len);
extern bool cvsw_delete_table_entry(const __u8 *data, const int len);
extern void cvsw_cleanup_table(void);

#endif /* __CVSW_TABLE_H_INCLUDED__ */
