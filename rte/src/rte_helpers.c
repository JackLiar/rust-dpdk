#include <stdio.h>
#include <stdlib.h>

#include <rte_config.h>
#include <rte_version.h>
#include <rte_lcore.h>
#include <rte_errno.h>
#include <rte_spinlock.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>

unsigned
_rte_lcore_id()
{
    return rte_lcore_id();
}

int _rte_errno()
{
    return rte_errno;
}

const char *
_rte_version()
{
    return rte_version();
}

size_t
_rte_cache_line_size()
{
    return RTE_CACHE_LINE_SIZE;
}

uint64_t
_rte_rdtsc()
{
    return rte_rdtsc();
}

uint64_t
_rte_rdtsc_precise()
{
    return rte_rdtsc_precise();
}

void _rte_spinlock_lock(rte_spinlock_t *sl)
{
    rte_spinlock_lock(sl);
}

void _rte_spinlock_unlock(rte_spinlock_t *sl)
{
    rte_spinlock_unlock(sl);
}

int _rte_spinlock_trylock(rte_spinlock_t *sl)
{
    return rte_spinlock_trylock(sl);
}

int _rte_tm_supported(void)
{
    return rte_tm_supported();
}

void _rte_spinlock_lock_tm(rte_spinlock_t *sl)
{
    rte_spinlock_lock_tm(sl);
}

void _rte_spinlock_unlock_tm(rte_spinlock_t *sl)
{
    rte_spinlock_unlock_tm(sl);
}

int _rte_spinlock_trylock_tm(rte_spinlock_t *sl)
{
    return rte_spinlock_trylock_tm(sl);
}

void _rte_spinlock_recursive_lock(rte_spinlock_recursive_t *slr)
{
    rte_spinlock_recursive_lock(slr);
}

void _rte_spinlock_recursive_unlock(rte_spinlock_recursive_t *slr)
{
    rte_spinlock_recursive_unlock(slr);
}

int _rte_spinlock_recursive_trylock(rte_spinlock_recursive_t *slr)
{
    return rte_spinlock_recursive_trylock(slr);
}

void _rte_spinlock_recursive_lock_tm(rte_spinlock_recursive_t *slr)
{
    rte_spinlock_recursive_lock_tm(slr);
}

void _rte_spinlock_recursive_unlock_tm(rte_spinlock_recursive_t *slr)
{
    rte_spinlock_recursive_unlock_tm(slr);
}

int _rte_spinlock_recursive_trylock_tm(rte_spinlock_recursive_t *slr)
{
    return rte_spinlock_recursive_trylock_tm(slr);
}

uint16_t
_rte_eth_rx_burst(uint16_t port_id, uint16_t queue_id,
                  struct rte_mbuf **rx_pkts, const uint16_t nb_pkts)
{
    return rte_eth_rx_burst(port_id, queue_id, rx_pkts, nb_pkts);
}

uint16_t
_rte_eth_tx_burst(uint16_t port_id, uint16_t queue_id,
                  struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
    return rte_eth_tx_burst(port_id, queue_id, tx_pkts, nb_pkts);
}

size_t
_rte_eth_tx_buffer_size(size_t size)
{
    return RTE_ETH_TX_BUFFER_SIZE(size);
}

struct rte_mbuf *
_rte_pktmbuf_alloc(struct rte_mempool *mp)
{
    return rte_pktmbuf_alloc(mp);
}

void _rte_pktmbuf_free(struct rte_mbuf *m)
{
    rte_pktmbuf_free(m);
}

int _rte_pktmbuf_alloc_bulk(struct rte_mempool *pool, struct rte_mbuf **mbufs, unsigned count)
{
    return rte_pktmbuf_alloc_bulk(pool, mbufs, count);
}

struct rte_mbuf *
_rte_pktmbuf_clone(struct rte_mbuf *md, struct rte_mempool *mp)
{
    return rte_pktmbuf_clone(md, mp);
}

char *
_rte_pktmbuf_prepend(struct rte_mbuf *m, uint16_t len)
{
    return rte_pktmbuf_prepend(m, len);
}

char *
_rte_pktmbuf_append(struct rte_mbuf *m, uint16_t len)
{
    return rte_pktmbuf_append(m, len);
}

char *
_rte_pktmbuf_adj(struct rte_mbuf *m, uint16_t len)
{
    return rte_pktmbuf_adj(m, len);
}

int _rte_pktmbuf_trim(struct rte_mbuf *m, uint16_t len)
{
    return rte_pktmbuf_trim(m, len);
}

int _rte_vlan_strip(struct rte_mbuf *m)
{
    return rte_vlan_strip(m);
}

int _rte_vlan_insert(struct rte_mbuf **m)
{
    return rte_vlan_insert(m);
}
