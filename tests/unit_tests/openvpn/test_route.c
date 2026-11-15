/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "test_common.h"

#include "route.h"
#include "tun.h"
#include "networking.h"

#include "test_route.h"

/* Stubs for functions route.c references but that no test here reaches.
 * They assert rather than return quietly, so a test straying onto one
 * fails loudly instead of silently doing nothing.
 */
bool
get_ipv6_addr(const char *prefix_str, struct in6_addr *network, unsigned int *netbits,
              msglvl_t msglevel)
{
    assert_true(0);
    return false;
}

bool
parse_line(const char *line, char *p[], const int n, const char *file, const int line_num,
           int msglevel, struct gc_arena *gc)
{
    assert_true(0);
    return false;
}

in_addr_t
getaddr(unsigned int flags, const char *hostname, int resolve_retry, bool *succeeded,
        struct signal_info *sig_info)
{
    assert_true(0);
    return 0;
}

int
openvpn_getaddrinfo(unsigned int flags, const char *hostname, const char *servname,
                    int resolve_retry_seconds, struct signal_info *sig_info, int ai_family,
                    struct addrinfo **res)
{
    assert_true(0);
    return 0;
}

struct signal_info siginfo_static; /* GLOBAL */

int
signal_reset(struct signal_info *si, int signum)
{
    assert_true(0);
    return 0;
}

static void
test_is_special_addr(void **state)
{
    assert_true(is_special_addr("net_gateway"));
    assert_true(is_special_addr("vpn_gateway"));
    assert_true(is_special_addr("remote_host"));

    assert_false(is_special_addr("10.0.0.1"));
    assert_false(is_special_addr("default"));
    assert_false(is_special_addr(NULL));
}

static void
test_netmask_to_netbits(void **state)
{
    int netbits;

    assert_true(netmask_to_netbits(0x0a000000, 0xff000000, &netbits)); /* 10/8 */
    assert_int_equal(netbits, 8);

    assert_true(netmask_to_netbits(0xc0a80100, 0xffffff00, &netbits)); /* 192.168.1/24 */
    assert_int_equal(netbits, 24);

    assert_true(netmask_to_netbits(0x00000000, 0x00000000, &netbits)); /* default route */
    assert_int_equal(netbits, 0);

    /* a full-length mask reports -1 rather than 32 */
    assert_true(netmask_to_netbits(0x0a010203, 0xffffffff, &netbits));
    assert_int_equal(netbits, -1);

    /* host bits set in the network part */
    assert_false(netmask_to_netbits(0x0a000001, 0xff000000, &netbits));

    /* not a contiguous netmask */
    assert_false(netmask_to_netbits(0x0a000000, 0xff00ff00, &netbits));
}

static void
test_netmask_to_netbits2(void **state)
{
    assert_int_equal(netmask_to_netbits2(0xff000000), 8);
    assert_int_equal(netmask_to_netbits2(0xffffff00), 24);
    assert_int_equal(netmask_to_netbits2(0x00000000), 0);

    /* unlike netmask_to_netbits(), this one reports a full-length mask as 32 */
    assert_int_equal(netmask_to_netbits2(0xffffffff), 32);

    assert_int_equal(netmask_to_netbits2(0xff00ff00), -1);
}

static void
assert_clear_host_bits(const char *addr, unsigned int netbits, const char *expected)
{
    struct route_ipv6 r6;
    struct in6_addr want;

    CLEAR(r6);
    assert_int_equal(inet_pton(AF_INET6, addr, &r6.network), 1);
    assert_int_equal(inet_pton(AF_INET6, expected, &want), 1);
    r6.netbits = netbits;

    route_ipv6_clear_host_bits(&r6);
    assert_memory_equal(&r6.network, &want, sizeof(struct in6_addr));
}

static void
test_route_ipv6_clear_host_bits(void **state)
{
    /* whole bytes cleared */
    assert_clear_host_bits("2001:db8::1", 64, "2001:db8::");
    assert_clear_host_bits("2001:db8:dead:beef::1", 32, "2001:db8::");

    /* a prefix that does not fall on a byte boundary */
    assert_clear_host_bits("2001:db8:0:00ff::1", 60, "2001:db8:0:00f0::");
    assert_clear_host_bits("2001:db8::ffff", 121, "2001:db8::ff80");

    /* nothing to clear, and everything to clear */
    assert_clear_host_bits("2001:db8::1", 128, "2001:db8::1");
    assert_clear_host_bits("2001:db8::1", 0, "::");
}

/*
 * Tests for reconcile_route_list()/reconcile_route_ipv6_list().
 *
 * The net_route_*() functions talking to the kernel are wrapped
 * (--wrap) so that the tests can record which kernel route operations
 * a reconcile performs, and in which order.  Outside of the reconcile
 * tests the wrappers pass through to the real implementations, so the
 * netlink tests in test_networking.c are unaffected.
 */

enum route_call
{
    CALL_ADD4,
    CALL_DEL4,
    CALL_ADD6,
    CALL_DEL6
};

struct route_event
{
    enum route_call call;
    union
    {
        struct
        {
            in_addr_t network;
            int prefixlen;
            in_addr_t gateway;
        } v4;
        struct
        {
            struct in6_addr network;
            struct in6_addr gateway;
            unsigned int netbits;
        } v6;
    } u;
};

#define MAX_ROUTE_EVENTS 32

static struct route_event route_events[MAX_ROUTE_EVENTS];
static int num_route_events;
static bool wrap_net_route_active;
static bool wrap_add_route_fails;

static void
reset_route_events(void)
{
    num_route_events = 0;
    wrap_net_route_active = true;
    wrap_add_route_fails = false;
    CLEAR(route_events);
}

static void
record_route_event(const struct route_event *ev)
{
    assert_true(num_route_events < MAX_ROUTE_EVENTS);
    route_events[num_route_events++] = *ev;
}

int
__real_net_route_v4_add(const openvpn_net_ctx_t *ctx, const in_addr_t *dst, int prefixlen,
                        const in_addr_t *gw, const openvpn_net_iface_t *iface, uint32_t table,
                        int metric);
int
__real_net_route_v4_del(const openvpn_net_ctx_t *ctx, const in_addr_t *dst, int prefixlen,
                        const in_addr_t *gw, const openvpn_net_iface_t *iface, uint32_t table,
                        int metric);
int
__real_net_route_v6_add(const openvpn_net_ctx_t *ctx, const struct in6_addr *dst, int prefixlen,
                        const struct in6_addr *gw, const openvpn_net_iface_t *iface, uint32_t table,
                        int metric);
int
__real_net_route_v6_del(const openvpn_net_ctx_t *ctx, const struct in6_addr *dst, int prefixlen,
                        const struct in6_addr *gw, const openvpn_net_iface_t *iface, uint32_t table,
                        int metric);

int
__wrap_net_route_v4_add(const openvpn_net_ctx_t *ctx, const in_addr_t *dst, int prefixlen,
                        const in_addr_t *gw, const openvpn_net_iface_t *iface, uint32_t table,
                        int metric)
{
    if (!wrap_net_route_active)
    {
        return __real_net_route_v4_add(ctx, dst, prefixlen, gw, iface, table, metric);
    }
    const struct route_event ev = { .call = CALL_ADD4,
                                    .u.v4 = { *dst, prefixlen, gw ? *gw : 0 } };
    record_route_event(&ev);
    return wrap_add_route_fails ? -1 : 0;
}

int
__wrap_net_route_v4_del(const openvpn_net_ctx_t *ctx, const in_addr_t *dst, int prefixlen,
                        const in_addr_t *gw, const openvpn_net_iface_t *iface, uint32_t table,
                        int metric)
{
    if (!wrap_net_route_active)
    {
        return __real_net_route_v4_del(ctx, dst, prefixlen, gw, iface, table, metric);
    }
    const struct route_event ev = { .call = CALL_DEL4,
                                    .u.v4 = { *dst, prefixlen, gw ? *gw : 0 } };
    record_route_event(&ev);
    return 0;
}

int
__wrap_net_route_v6_add(const openvpn_net_ctx_t *ctx, const struct in6_addr *dst, int prefixlen,
                        const struct in6_addr *gw, const openvpn_net_iface_t *iface, uint32_t table,
                        int metric)
{
    if (!wrap_net_route_active)
    {
        return __real_net_route_v6_add(ctx, dst, prefixlen, gw, iface, table, metric);
    }
    struct route_event ev = { .call = CALL_ADD6, .u.v6 = { .netbits = (unsigned int)prefixlen } };
    ev.u.v6.network = *dst;
    if (gw)
    {
        ev.u.v6.gateway = *gw;
    }
    record_route_event(&ev);
    return wrap_add_route_fails ? -1 : 0;
}

int
__wrap_net_route_v6_del(const openvpn_net_ctx_t *ctx, const struct in6_addr *dst, int prefixlen,
                        const struct in6_addr *gw, const openvpn_net_iface_t *iface, uint32_t table,
                        int metric)
{
    if (!wrap_net_route_active)
    {
        return __real_net_route_v6_del(ctx, dst, prefixlen, gw, iface, table, metric);
    }
    struct route_event ev = { .call = CALL_DEL6, .u.v6 = { .netbits = (unsigned int)prefixlen } };
    ev.u.v6.network = *dst;
    if (gw)
    {
        ev.u.v6.gateway = *gw;
    }
    record_route_event(&ev);
    return 0;
}

static struct route_ipv4 *
append_route_ipv4(struct route_list *rl, in_addr_t network, in_addr_t netmask, in_addr_t gateway)
{
    struct route_ipv4 *r = calloc(1, sizeof(struct route_ipv4));
    assert_non_null(r);
    r->flags = RT_DEFINED;
    r->network = network;
    r->netmask = netmask;
    r->gateway = gateway;

    struct route_ipv4 **tail = &rl->routes;
    while (*tail)
    {
        tail = &(*tail)->next;
    }
    *tail = r;
    return r;
}

/* mark all routes as installed, as add_route() would have done */
static void
mark_routes_added(struct route_list *rl)
{
    for (struct route_ipv4 *r = rl->routes; r; r = r->next)
    {
        r->flags |= RT_ADDED;
    }
    rl->iflags |= RL_ROUTES_ADDED;
}

static struct route_ipv6 *
append_route_ipv6(struct route_ipv6_list *rl6, const char *network, unsigned int netbits,
                  const char *gateway)
{
    struct route_ipv6 *r6 = calloc(1, sizeof(struct route_ipv6));
    assert_non_null(r6);
    r6->flags = RT_DEFINED;
    assert_int_equal(inet_pton(AF_INET6, network, &r6->network), 1);
    assert_int_equal(inet_pton(AF_INET6, gateway, &r6->gateway), 1);
    r6->netbits = netbits;

    struct route_ipv6 **tail = &rl6->routes_ipv6;
    while (*tail)
    {
        tail = &(*tail)->next;
    }
    *tail = r6;
    return r6;
}

static void
mark_routes_ipv6_added(struct route_ipv6_list *rl6)
{
    for (struct route_ipv6 *r6 = rl6->routes_ipv6; r6; r6 = r6->next)
    {
        r6->flags |= RT_ADDED;
    }
    rl6->iflags |= RL_ROUTES_ADDED;
}

static void
free_route_list_routes(struct route_list *rl)
{
    while (rl->routes)
    {
        struct route_ipv4 *next = rl->routes->next;
        free(rl->routes);
        rl->routes = next;
    }
}

static void
free_route_ipv6_list_routes(struct route_ipv6_list *rl6)
{
    while (rl6->routes_ipv6)
    {
        struct route_ipv6 *next = rl6->routes_ipv6->next;
        free(rl6->routes_ipv6);
        rl6->routes_ipv6 = next;
    }
}

static size_t
count_routes_ipv4(const struct route_list *rl)
{
    size_t count = 0;
    for (const struct route_ipv4 *r = rl->routes; r; r = r->next)
    {
        count++;
    }
    return count;
}

static void
assert_route_event(int idx, enum route_call call, in_addr_t network, in_addr_t gateway)
{
    assert_true(idx < num_route_events);
    assert_int_equal(route_events[idx].call, call);
    assert_int_equal(route_events[idx].u.v4.network, network);
    assert_int_equal(route_events[idx].u.v4.gateway, gateway);
}

static struct tuntap test_tt;

static void
init_test_tuntap(void)
{
    CLEAR(test_tt);
    test_tt.actual_name = (char *)"tun-test0";
}

/*
 * Reconcile keeps identical routes untouched, adds new routes before
 * deleting removed ones and re-adds routes whose gateway changed.
 */
static void
test_reconcile_route_list(void **state)
{
    const in_addr_t gw_old = 0xC0000201; /* 192.0.2.1 */
    const in_addr_t gw_new = 0xC00002FE; /* 192.0.2.254 */
    const in_addr_t mask24 = 0xFFFFFF00;

    struct route_list old_rl, new_rl;
    CLEAR(old_rl);
    CLEAR(new_rl);
    init_test_tuntap();

    append_route_ipv4(&old_rl, 0x0A010000, mask24, gw_old); /* A: removed */
    append_route_ipv4(&old_rl, 0x0A020000, mask24, gw_old); /* B: kept */
    append_route_ipv4(&old_rl, 0x0A030000, mask24, gw_old); /* C: gateway changes */
    mark_routes_added(&old_rl);

    append_route_ipv4(&new_rl, 0x0A020000, mask24, gw_old); /* B: kept */
    append_route_ipv4(&new_rl, 0x0A030000, mask24, gw_new); /* C': new gateway */
    append_route_ipv4(&new_rl, 0x0A040000, mask24, gw_old); /* D: added */

    reset_route_events();
    assert_true(reconcile_route_list(&old_rl, &new_rl, &test_tt, 0, NULL, NULL));

    /* changed route removed first, then new routes added, then the
     * stale route removed; the identical route B is never touched */
    assert_int_equal(num_route_events, 4);
    assert_route_event(0, CALL_DEL4, 0x0A030000, gw_old);
    assert_route_event(1, CALL_ADD4, 0x0A030000, gw_new);
    assert_route_event(2, CALL_ADD4, 0x0A040000, gw_old);
    assert_route_event(3, CALL_DEL4, 0x0A010000, gw_old);

    /* the persistent list now holds the reconciled new routes */
    assert_true(old_rl.iflags & RL_ROUTES_ADDED);
    assert_int_equal(count_routes_ipv4(&old_rl), 3);
    assert_int_equal(old_rl.routes->network, 0x0A020000);
    assert_null(new_rl.routes);

    free_route_list_routes(&old_rl);
}

/*
 * A failing route installation is reported to the caller.
 */
static void
test_reconcile_route_list_failure(void **state)
{
    struct route_list old_rl, new_rl;
    CLEAR(old_rl);
    CLEAR(new_rl);
    init_test_tuntap();

    mark_routes_added(&old_rl);
    append_route_ipv4(&new_rl, 0x0A080000, 0xFFFFFF00, 0xC0000201);

    reset_route_events();
    wrap_add_route_fails = true;
    assert_false(reconcile_route_list(&old_rl, &new_rl, &test_tt, 0, NULL, NULL));
    assert_int_equal(num_route_events, 1);

    free_route_list_routes(&old_rl);
}

/*
 * An identical redirect-gateway is kept in place: no kernel route
 * operations happen and the bookkeeping is transferred to the new
 * list so the redirect can be undone later.
 */
static void
test_reconcile_route_list_redirect_kept(void **state)
{
    struct route_list old_rl, new_rl;
    CLEAR(old_rl);
    CLEAR(new_rl);

    old_rl.flags = RG_ENABLE | RG_DEF1 | RG_REROUTE_GW;
    old_rl.spec.flags = RTSA_REMOTE_ENDPOINT;
    old_rl.spec.remote_endpoint = 0xC0000201;
    old_rl.iflags = RL_DID_REDIRECT_DEFAULT_GATEWAY | RL_DID_LOCAL | RL_ROUTES_ADDED;
    old_rl.rgi.flags = RGI_ADDR_DEFINED;
    old_rl.rgi.gateway.addr = 0x0A0B0C0D;

    new_rl.flags = old_rl.flags;
    new_rl.spec.flags = old_rl.spec.flags;
    new_rl.spec.remote_endpoint = old_rl.spec.remote_endpoint;

    init_test_tuntap();
    reset_route_events();
    assert_true(reconcile_route_list(&old_rl, &new_rl, &test_tt, 0, NULL, NULL));

    /* nothing was added or deleted, the redirect state moved over */
    assert_int_equal(num_route_events, 0);
    assert_true(old_rl.iflags & RL_DID_REDIRECT_DEFAULT_GATEWAY);
    assert_true(old_rl.iflags & RL_DID_LOCAL);
    assert_int_equal(old_rl.rgi.gateway.addr, 0x0A0B0C0D);

    free_route_list_routes(&old_rl);
}

/*
 * A redirect-gateway that is no longer pushed is undone.
 */
static void
test_reconcile_route_list_redirect_removed(void **state)
{
    struct route_list old_rl, new_rl;
    CLEAR(old_rl);
    CLEAR(new_rl);

    old_rl.flags = RG_ENABLE | RG_DEF1 | RG_REROUTE_GW;
    old_rl.spec.flags = RTSA_REMOTE_ENDPOINT;
    old_rl.spec.remote_endpoint = 0xC0000201;
    old_rl.iflags = RL_DID_REDIRECT_DEFAULT_GATEWAY | RL_ROUTES_ADDED;

    init_test_tuntap();
    reset_route_events();
    assert_true(reconcile_route_list(&old_rl, &new_rl, &test_tt, 0, NULL, NULL));

    /* the two def1 routes covering the default route are deleted */
    assert_int_equal(num_route_events, 2);
    assert_route_event(0, CALL_DEL4, 0x00000000, 0xC0000201);
    assert_route_event(1, CALL_DEL4, 0x80000000, 0xC0000201);
    assert_false(old_rl.iflags & RL_DID_REDIRECT_DEFAULT_GATEWAY);

    free_route_list_routes(&old_rl);
}

/*
 * IPv6 variant of the reconcile test.
 */
static void
test_reconcile_route_ipv6_list(void **state)
{
    struct route_ipv6_list old_rl6, new_rl6;
    CLEAR(old_rl6);
    CLEAR(new_rl6);
    init_test_tuntap();

    append_route_ipv6(&old_rl6, "2001:db8:1::", 64, "fe80::1"); /* removed */
    append_route_ipv6(&old_rl6, "2001:db8:2::", 64, "fe80::1"); /* kept */
    mark_routes_ipv6_added(&old_rl6);

    append_route_ipv6(&new_rl6, "2001:db8:2::", 64, "fe80::1"); /* kept */
    append_route_ipv6(&new_rl6, "2001:db8:3::", 64, "fe80::1"); /* added */

    reset_route_events();
    assert_true(reconcile_route_ipv6_list(&old_rl6, &new_rl6, &test_tt, 0, NULL, NULL));

    /* the new route is added before the stale one is deleted, the
     * identical route is never touched */
    assert_int_equal(num_route_events, 2);
    assert_int_equal(route_events[0].call, CALL_ADD6);
    assert_int_equal(route_events[0].u.v6.netbits, 64);
    {
        struct in6_addr want;
        assert_int_equal(inet_pton(AF_INET6, "2001:db8:3::", &want), 1);
        assert_memory_equal(&route_events[0].u.v6.network, &want, sizeof(want));
    }
    assert_int_equal(route_events[1].call, CALL_DEL6);
    {
        struct in6_addr want;
        assert_int_equal(inet_pton(AF_INET6, "2001:db8:1::", &want), 1);
        assert_memory_equal(&route_events[1].u.v6.network, &want, sizeof(want));
    }

    assert_true(old_rl6.iflags & RL_ROUTES_ADDED);
    assert_null(new_rl6.routes_ipv6);

    free_route_ipv6_list_routes(&old_rl6);
}

static const struct CMUnitTest route_test_list[] = {
    cmocka_unit_test(test_is_special_addr),
    cmocka_unit_test(test_netmask_to_netbits),
    cmocka_unit_test(test_netmask_to_netbits2),
    cmocka_unit_test(test_route_ipv6_clear_host_bits),
    cmocka_unit_test(test_reconcile_route_list),
    cmocka_unit_test(test_reconcile_route_list_failure),
    cmocka_unit_test(test_reconcile_route_list_redirect_kept),
    cmocka_unit_test(test_reconcile_route_list_redirect_removed),
    cmocka_unit_test(test_reconcile_route_ipv6_list),
};

int
route_tests(void)
{
    openvpn_unit_test_setup();
    return cmocka_run_group_tests(route_test_list, NULL, NULL);
}
