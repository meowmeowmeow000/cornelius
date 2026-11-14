{
  "version": "1.2-cornelius",
  "worker_host": "bold-heart-a6e2.nedaymarg.workers.dev",
  "expected_ttl": 255,
  "operational_doctrine": {
    "telemetry_polling_ms": 3000,
    "max_acceptable_latency_ms": 800,
    "fallback_threshold_streak": 3
  },
  "modules": {
    "xdp_shield": {
      "mode": "adaptive",
      "expected_ttl": 255,
      "ttl_tolerance": 4,
      "rst_burst_threshold": 5
    },
    "stealth_factory": {
      "snispf_direction": "legacy",
      "default_spoof_sni": "www.speedtest.net",
      "primary_mode": "tls_frag",
      "fallback_mode": "tls_micro_frag",
      "fragmentation_delay_ms": 2,
      "jitter_ms": 2,
      "allow_insecure_certs": false,
      "default_ws_path": "/secret-knock-99"
    },
    "warm_pool": {
      "target_capacity": 8,
      "keepalive_interval_sec": 10
    }
  },
  "contingency_matrix": [
    {
      "condition": "http_403_forbidden",
      "action": "escalate_stealth_mode"
    },
    {
      "condition": "dpi_tls_reset",
      "action": "escalate_stealth_mode"
    },
    {
      "condition": "dial_timeout",
      "action": "flush_pool_and_rotate_ip"
    },
    {
      "condition": "dial_unreachable",
      "action": "flush_pool_and_rotate_ip"
    },
    {
      "condition": "tcp_rst_storm",
      "action": "engage_xdp_lockdown"
    }
  ],
  "primary_route": {
    "target_ip": "104.18.0.181",
    "target_port": 443,
    "snispf_direction": "legacy",
    "spoof_sni": "www.speedtest.net",
    "clean_sni": "bold-heart-a6e2.nedaymarg.workers.dev",
    "stealth_mode": "tls_frag",
    "fingerprint": "chrome_auto",
    "expected_ttl": 255,
    "decoy_ttl": 6,
    "tls_handshake_ms": 208,
    "ws_verified": false,
    "confidence_score": 80,
    "ws_path": "/secret-knock-99"
  },
  "failover_routes": [
    {
      "target_ip": "104.18.0.82",
      "target_port": 443,
      "snispf_direction": "legacy",
      "spoof_sni": "www.speedtest.net",
      "clean_sni": "bold-heart-a6e2.nedaymarg.workers.dev",
      "stealth_mode": "tls_frag",
      "fingerprint": "chrome_auto",
      "expected_ttl": 255,
      "decoy_ttl": 6,
      "tls_handshake_ms": 266,
      "ws_verified": false,
      "confidence_score": 74,
      "ws_path": "/secret-knock-99"
    },
    {
      "target_ip": "104.18.0.210",
      "target_port": 443,
      "snispf_direction": "legacy",
      "spoof_sni": "www.speedtest.net",
      "clean_sni": "bold-heart-a6e2.nedaymarg.workers.dev",
      "stealth_mode": "tls_frag",
      "fingerprint": "randomized",
      "expected_ttl": 255,
      "decoy_ttl": 6,
      "tls_handshake_ms": 270,
      "ws_verified": false,
      "confidence_score": 73,
      "ws_path": "/secret-knock-99"
    },
    {
      "target_ip": "104.18.0.50",
      "target_port": 443,
      "snispf_direction": "legacy",
      "spoof_sni": "www.speedtest.net",
      "clean_sni": "bold-heart-a6e2.nedaymarg.workers.dev",
      "stealth_mode": "tls_frag",
      "fingerprint": "chrome_auto",
      "expected_ttl": 255,
      "decoy_ttl": 6,
      "tls_handshake_ms": 272,
      "ws_verified": false,
      "confidence_score": 73,
      "ws_path": "/secret-knock-99"
    },
    {
      "target_ip": "104.18.0.121",
      "target_port": 443,
      "snispf_direction": "legacy",
      "spoof_sni": "www.speedtest.net",
      "clean_sni": "bold-heart-a6e2.nedaymarg.workers.dev",
      "stealth_mode": "tls_frag",
      "fingerprint": "chrome_auto",
      "expected_ttl": 255,
      "decoy_ttl": 6,
      "tls_handshake_ms": 273,
      "ws_verified": false,
      "confidence_score": 73,
      "ws_path": "/secret-knock-99"
    },
    {
      "target_ip": "104.18.0.118",
      "target_port": 443,
      "snispf_direction": "legacy",
      "spoof_sni": "www.speedtest.net",
      "clean_sni": "bold-heart-a6e2.nedaymarg.workers.dev",
      "stealth_mode": "tls_frag",
      "fingerprint": "firefox_auto",
      "expected_ttl": 255,
      "decoy_ttl": 6,
      "tls_handshake_ms": 273,
      "ws_verified": false,
      "confidence_score": 73,
      "ws_path": "/secret-knock-99"
    }
  ]
}