//! Lock-free atomic metrics, latency histograms, RCODE breakdowns, and Prometheus / OpenMetrics
//! text exposition for `daviante-doh`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::dns::wire::{
    RCODE_FORMERR, RCODE_NOERROR, RCODE_NOTIMP, RCODE_NXDOMAIN, RCODE_REFUSED, RCODE_SERVFAIL,
};

/// Histogram bucket upper bounds in seconds (`le`).
pub const HISTOGRAM_BUCKETS_SECS: [f64; 12] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Lock-free latency histogram for a single DoH flavor (`wire`, `json`, `odoh`).
#[derive(Debug, Default)]
pub struct LatencyHistogram {
    buckets: [AtomicU64; 12],
    count: AtomicU64,
    sum_micros: AtomicU64,
}

impl LatencyHistogram {
    pub fn observe(&self, elapsed: Duration) {
        let secs = elapsed.as_secs_f64();
        let micros = elapsed.as_micros().min(u64::MAX as u128) as u64;
        for (i, &bound) in HISTOGRAM_BUCKETS_SECS.iter().enumerate() {
            if secs <= bound {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_micros.fetch_add(micros, Ordering::Relaxed);
    }

    fn write_prometheus(&self, out: &mut String, flavor: &str) {
        for (i, &bound) in HISTOGRAM_BUCKETS_SECS.iter().enumerate() {
            let val = self.buckets[i].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "daviante_doh_request_duration_seconds_bucket{{flavor=\"{flavor}\",le=\"{bound}\"}} {val}"
            );
        }
        let count = self.count.load(Ordering::Relaxed);
        let sum_secs = (self.sum_micros.load(Ordering::Relaxed) as f64) / 1_000_000.0;
        let _ = writeln!(
            out,
            "daviante_doh_request_duration_seconds_bucket{{flavor=\"{flavor}\",le=\"+Inf\"}} {count}"
        );
        let _ = writeln!(
            out,
            "daviante_doh_request_duration_seconds_sum{{flavor=\"{flavor}\"}} {sum_secs:.6}"
        );
        let _ = writeln!(
            out,
            "daviante_doh_request_duration_seconds_count{{flavor=\"{flavor}\"}} {count}"
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct UpstreamMetricKey {
    upstream: String,
    transport: &'static str,
    result: &'static str,
}

/// Lock-free runtime counters and histograms for first-party Prometheus / OpenMetrics scraping (`/metrics`).
#[derive(Debug, Default)]
pub struct DohMetricsInner {
    pub requests_wire_total: AtomicU64,
    pub requests_json_total: AtomicU64,
    pub requests_odoh_total: AtomicU64,
    pub responses_2xx_total: AtomicU64,
    pub responses_4xx_total: AtomicU64,
    pub responses_5xx_total: AtomicU64,
    pub rcode_noerror_total: AtomicU64,
    pub rcode_formerr_total: AtomicU64,
    pub rcode_servfail_total: AtomicU64,
    pub rcode_nxdomain_total: AtomicU64,
    pub rcode_notimp_total: AtomicU64,
    pub rcode_refused_total: AtomicU64,
    pub rcode_other_total: AtomicU64,
    pub cache_hits_total: AtomicU64,
    pub cache_misses_total: AtomicU64,
    pub cache_stale_hits_total: AtomicU64,
    pub cache_prefetch_total: AtomicU64,
    pub coalesced_queries_total: AtomicU64,
    pub policy_blocked_total: AtomicU64,
    pub rebinding_blocked_total: AtomicU64,
    pub hosts_hits_total: AtomicU64,
    pub rate_limited_total: AtomicU64,
    pub upstream_udp_total: AtomicU64,
    pub upstream_tcp_total: AtomicU64,
    pub upstream_dot_total: AtomicU64,
    pub upstream_failures_total: AtomicU64,
    pub connections_active: AtomicU64,
    pub hist_wire: LatencyHistogram,
    pub hist_json: LatencyHistogram,
    pub hist_odoh: LatencyHistogram,
    upstream_by_target: Mutex<BTreeMap<UpstreamMetricKey, u64>>,
}

#[derive(Clone, Debug, Default)]
pub struct DohMetrics {
    inner: Arc<DohMetricsInner>,
}

impl DohMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn inc_wire_req(&self) {
        self.inner
            .requests_wire_total
            .fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_json_req(&self) {
        self.inner
            .requests_json_total
            .fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_odoh_req(&self) {
        self.inner
            .requests_odoh_total
            .fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn observe_wire_duration(&self, elapsed: Duration) {
        self.inner.hist_wire.observe(elapsed);
    }

    #[inline]
    pub fn observe_json_duration(&self, elapsed: Duration) {
        self.inner.hist_json.observe(elapsed);
    }

    #[inline]
    pub fn observe_odoh_duration(&self, elapsed: Duration) {
        self.inner.hist_odoh.observe(elapsed);
    }

    #[inline]
    pub fn record_status(&self, status_code: u16) {
        match status_code {
            200..=299 => {
                self.inner
                    .responses_2xx_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            400..=499 => {
                self.inner
                    .responses_4xx_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            500..=599 => {
                self.inner
                    .responses_5xx_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    #[inline]
    pub fn record_rcode(&self, rcode_val: u8) {
        match rcode_val {
            RCODE_NOERROR => {
                self.inner
                    .rcode_noerror_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            RCODE_FORMERR => {
                self.inner
                    .rcode_formerr_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            RCODE_SERVFAIL => {
                self.inner
                    .rcode_servfail_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            RCODE_NXDOMAIN => {
                self.inner
                    .rcode_nxdomain_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            RCODE_NOTIMP => {
                self.inner
                    .rcode_notimp_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            RCODE_REFUSED => {
                self.inner
                    .rcode_refused_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.inner.rcode_other_total.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    #[inline]
    pub fn inc_cache_hit(&self) {
        self.inner.cache_hits_total.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_cache_miss(&self) {
        self.inner
            .cache_misses_total
            .fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_cache_stale_hit(&self) {
        self.inner
            .cache_stale_hits_total
            .fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_cache_prefetch(&self) {
        self.inner
            .cache_prefetch_total
            .fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_coalesced_query(&self) {
        self.inner
            .coalesced_queries_total
            .fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_policy_blocked(&self) {
        self.inner
            .policy_blocked_total
            .fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_rebinding_blocked(&self) {
        self.inner
            .rebinding_blocked_total
            .fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_hosts_hit(&self) {
        self.inner.hosts_hits_total.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_rate_limited(&self) {
        self.inner
            .rate_limited_total
            .fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_upstream_udp(&self) {
        self.inner
            .upstream_udp_total
            .fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_upstream_tcp(&self) {
        self.inner
            .upstream_tcp_total
            .fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_upstream_dot(&self) {
        self.inner
            .upstream_dot_total
            .fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_upstream_failure(&self) {
        self.inner
            .upstream_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records a per-upstream query outcome (`transport = "udp" | "tcp"`, `result = "ok" | "error" | "timeout"`).
    pub fn record_upstream_target(
        &self,
        upstream: SocketAddr,
        transport: &'static str,
        result: &'static str,
    ) {
        if let Ok(mut map) = self.inner.upstream_by_target.lock() {
            let key = UpstreamMetricKey {
                upstream: upstream.to_string(),
                transport,
                result,
            };
            *map.entry(key).or_insert(0) += 1;
        }
    }

    #[inline]
    pub fn inc_active_connections(&self) {
        self.inner
            .connections_active
            .fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn dec_active_connections(&self) {
        self.inner
            .connections_active
            .fetch_sub(1, Ordering::Relaxed);
    }

    /// Formats all counters, gauges, and histograms in standard Prometheus / OpenMetrics (`text/plain; version=0.0.4`) format.
    pub fn render_prometheus(&self) -> String {
        let i = &self.inner;
        let mut out = String::with_capacity(2048);

        let _ = write!(
            out,
            concat!(
                "# HELP daviante_doh_requests_total Total DoH requests received by protocol flavor.\n",
                "# TYPE daviante_doh_requests_total counter\n",
                "daviante_doh_requests_total{{flavor=\"wire\"}} {}\n",
                "daviante_doh_requests_total{{flavor=\"json\"}} {}\n",
                "daviante_doh_requests_total{{flavor=\"odoh\"}} {}\n",
                "# HELP daviante_doh_responses_total Total HTTP responses sent by status class.\n",
                "# TYPE daviante_doh_responses_total counter\n",
                "daviante_doh_responses_total{{status=\"2xx\"}} {}\n",
                "daviante_doh_responses_total{{status=\"4xx\"}} {}\n",
                "daviante_doh_responses_total{{status=\"5xx\"}} {}\n",
                "# HELP daviante_doh_responses_by_rcode_total Total DNS responses sent by DNS RCODE.\n",
                "# TYPE daviante_doh_responses_by_rcode_total counter\n",
                "daviante_doh_responses_by_rcode_total{{rcode=\"NOERROR\"}} {}\n",
                "daviante_doh_responses_by_rcode_total{{rcode=\"FORMERR\"}} {}\n",
                "daviante_doh_responses_by_rcode_total{{rcode=\"SERVFAIL\"}} {}\n",
                "daviante_doh_responses_by_rcode_total{{rcode=\"NXDOMAIN\"}} {}\n",
                "daviante_doh_responses_by_rcode_total{{rcode=\"NOTIMP\"}} {}\n",
                "daviante_doh_responses_by_rcode_total{{rcode=\"REFUSED\"}} {}\n",
                "daviante_doh_responses_by_rcode_total{{rcode=\"OTHER\"}} {}\n",
                "# HELP daviante_doh_cache_hits_total Total in-memory DNS cache hits.\n",
                "# TYPE daviante_doh_cache_hits_total counter\n",
                "daviante_doh_cache_hits_total {}\n",
                "# HELP daviante_doh_cache_misses_total Total in-memory DNS cache misses.\n",
                "# TYPE daviante_doh_cache_misses_total counter\n",
                "daviante_doh_cache_misses_total {}\n",
                "# HELP daviante_doh_cache_stale_hits_total Total expired cached responses served under RFC 8767 Serve-Stale.\n",
                "# TYPE daviante_doh_cache_stale_hits_total counter\n",
                "daviante_doh_cache_stale_hits_total {}\n",
                "# HELP daviante_doh_cache_prefetch_total Total background cache prefetch refreshes triggered.\n",
                "# TYPE daviante_doh_cache_prefetch_total counter\n",
                "daviante_doh_cache_prefetch_total {}\n",
                "# HELP daviante_doh_coalesced_queries_total Total concurrent cache-miss queries deduplicated via Singleflight.\n",
                "# TYPE daviante_doh_coalesced_queries_total counter\n",
                "daviante_doh_coalesced_queries_total {}\n",
                "# HELP daviante_doh_policy_blocked_total Total DNS queries blocked by Protective DNS policy.\n",
                "# TYPE daviante_doh_policy_blocked_total counter\n",
                "daviante_doh_policy_blocked_total {}\n",
                "# HELP daviante_doh_rebinding_blocked_total Total DNS responses blocked by DNS Rebinding Protection.\n",
                "# TYPE daviante_doh_rebinding_blocked_total counter\n",
                "daviante_doh_rebinding_blocked_total {}\n",
                "# HELP daviante_doh_hosts_hits_total Total DNS queries answered from local split-horizon hosts overrides.\n",
                "# TYPE daviante_doh_hosts_hits_total counter\n",
                "daviante_doh_hosts_hits_total {}\n",
                "# HELP daviante_doh_rate_limited_total Total requests rejected due to per-IP rate limiting.\n",
                "# TYPE daviante_doh_rate_limited_total counter\n",
                "daviante_doh_rate_limited_total {}\n",
                "# HELP daviante_doh_connections_active Currently active client TCP/TLS connections.\n",
                "# TYPE daviante_doh_connections_active gauge\n",
                "daviante_doh_connections_active {}\n",
                "# HELP daviante_doh_upstream_queries_total Total queries sent to upstream DNS resolvers by transport.\n",
                "# TYPE daviante_doh_upstream_queries_total counter\n",
                "daviante_doh_upstream_queries_total{{transport=\"udp\"}} {}\n",
                "daviante_doh_upstream_queries_total{{transport=\"tcp\"}} {}\n",
                "daviante_doh_upstream_queries_total{{transport=\"dot\"}} {}\n",
            ),
            i.requests_wire_total.load(Ordering::Relaxed),
            i.requests_json_total.load(Ordering::Relaxed),
            i.requests_odoh_total.load(Ordering::Relaxed),
            i.responses_2xx_total.load(Ordering::Relaxed),
            i.responses_4xx_total.load(Ordering::Relaxed),
            i.responses_5xx_total.load(Ordering::Relaxed),
            i.rcode_noerror_total.load(Ordering::Relaxed),
            i.rcode_formerr_total.load(Ordering::Relaxed),
            i.rcode_servfail_total.load(Ordering::Relaxed),
            i.rcode_nxdomain_total.load(Ordering::Relaxed),
            i.rcode_notimp_total.load(Ordering::Relaxed),
            i.rcode_refused_total.load(Ordering::Relaxed),
            i.rcode_other_total.load(Ordering::Relaxed),
            i.cache_hits_total.load(Ordering::Relaxed),
            i.cache_misses_total.load(Ordering::Relaxed),
            i.cache_stale_hits_total.load(Ordering::Relaxed),
            i.cache_prefetch_total.load(Ordering::Relaxed),
            i.coalesced_queries_total.load(Ordering::Relaxed),
            i.policy_blocked_total.load(Ordering::Relaxed),
            i.rebinding_blocked_total.load(Ordering::Relaxed),
            i.hosts_hits_total.load(Ordering::Relaxed),
            i.rate_limited_total.load(Ordering::Relaxed),
            i.connections_active.load(Ordering::Relaxed),
            i.upstream_udp_total.load(Ordering::Relaxed),
            i.upstream_tcp_total.load(Ordering::Relaxed),
            i.upstream_dot_total.load(Ordering::Relaxed),
        );

        if let Ok(map) = i.upstream_by_target.lock() {
            for (k, v) in map.iter() {
                let _ = writeln!(
                    out,
                    "daviante_doh_upstream_queries_total{{upstream=\"{}\",transport=\"{}\",result=\"{}\"}} {}",
                    k.upstream, k.transport, k.result, v
                );
            }
        }

        let _ = writeln!(
            out,
            "# HELP daviante_doh_upstream_failures_total Total upstream DNS timeouts or socket errors.\n# TYPE daviante_doh_upstream_failures_total counter\ndaviante_doh_upstream_failures_total {}",
            i.upstream_failures_total.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP daviante_doh_request_duration_seconds Request processing latency distribution in seconds.\n# TYPE daviante_doh_request_duration_seconds histogram"
        );
        i.hist_wire.write_prometheus(&mut out, "wire");
        i.hist_json.write_prometheus(&mut out, "json");
        i.hist_odoh.write_prometheus(&mut out, "odoh");

        out
    }
}
