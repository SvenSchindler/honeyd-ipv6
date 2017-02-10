/*
 * Copyright (c) 2002, 2003, 2004, 2005 Niels Provos <provos@citi.umich.edu>
 * Copyright (c) 2013 Sebastian Menski <menski@cs.uni-potsdam.de>
 * All rights reserved.
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _PERSONALITY6_H_
#define _PERSONALITY6_H_

#include "honeyd.h"

struct ip_personate6 {
    uint16_t plen;
    uint8_t tc;
};

struct tcp_personate6 {
    struct ip_personate6 ip;
    uint16_t window;
    uint16_t flags;  /* 0,0,0,0,RES8,RES9,RES10,RES11,C,E,U,A,P,R,S,F */
    uint8_t options[16][2];
    uint16_t mss;
    uint8_t sackok;
    uint8_t wscale;
};

struct personality6 {
    SPLAY_ENTRY(personality6) node;
    char *name;
    double tcp_isr;
    struct ip_personate6 ie[2];         /* IE1, IE2 */
    struct ip_personate6 ni;            /* NI */
    struct ip_personate6 ns;            /* NS */
    struct ip_personate6 u1;            /* U1 */
    struct tcp_personate6 s[6];        /* S1-S6*/
    struct tcp_personate6 tecn;        /* TECN */
    struct tcp_personate6 t[6];        /* T2-T7 */
};

static int
personality6_ip6_response(const struct ip_personate6 *pers) {
    return (pers == NULL) || pers->plen != (uint16_t) -1 || pers->tc != (uint8_t) -1;
}

void personality6_config_new(struct personality6 *);
void personality6_init(void);
struct personality6 *personality6_find(const char *);
struct personality6 *personality6_clone(const struct personality6 *);
void personality6_declone(struct personality6 *pers);
struct personality6 *personality6_random(void);
void personality6_free(struct personality6 *);
struct tcp_personate6 *tcp_personality6(struct tcp_con *, uint8_t *, uint8_t *, int *);
void tcp_personality6_options(struct tcp_con *, struct tcp_hdr *, struct tcp_personate6 *);

SPLAY_HEAD(perstree6, personality6) personalities6;

static int
perscompare6(struct personality6 *a, struct personality6 *b)
{
    return (strcmp(a->name, b->name));
}

SPLAY_PROTOTYPE(perstree6, personality6, node, perscompare6);

#endif
