# Tests — Network Anomaly Detection (Domain-Aware IP Diff)

This file documents all test coverage for the domain-aware FCrDNS-backed
network anomaly detection feature and the DNS interceptor fallback.
Source: `src/scanning.rs`.

## 1. `forward_confirmed_hostname` — FCrDNS core logic (3 tests)

Pure function with injected DNS closures, deterministically testable.

| # | Test | Scenario | Expected |
|---|------|----------|----------|
| 1 | `fcrdns_accepts_hostname_that_forward_resolves_back_to_ip` | PTR → `cdn.example.com` → forward includes `1.2.3.4` | `Some("cdn.example.com")` |
| 2 | `fcrdns_rejects_spoofed_ptr_that_does_not_forward_confirm` | PTR → `cdn.example.com` → forward returns `9.9.9.9` only | `None` |
| 3 | `fcrdns_rejects_when_no_ptr_record` | reverse returns `None` | `None` |

Branch coverage: reverse → `None` / `Some`; forward → `None` / `Vec<addr>` where addr in / not in vec.

## 2. `reverse_dns_domain` — production resolver parse guard (1 test)

| # | Test | Scenario | Expected |
|---|------|----------|----------|
| 4 | `reverse_dns_domain_invalid_ip_returns_none` | `reverse_dns_domain("not_an_ip")` | `None` (parse fails early) |

## 3. `find_new_connections_domain_aware` — domain-aware IP diff (14 tests)

Complete truth table — every combination of resolver outcome, IP overlap, and domain overlap.

### Same IP in both current and baseline sets (5 cases)

| # | Curr R? | Base R? | Domain match | Expected | Test |
|---|---------|---------|-------------|----------|------|
| 5 | `Some X` | `Some X` | same | not flagged | `same_ip_same_domain_not_flagged` |
| 6 | `Some Y` | `Some X` | diff | flagged | `same_ip_changed_domain` |
| 7 | `None` | `Some X` | — | not flagged (IP in B) | `same_ip_baseline_resolves_current_not` |
| 8 | `Some Y` | `None` | — | flagged (base domains empty) | `same_ip_baseline_not_resolves_current_resolves` |
| 9 | `None` | `None` | — | not flagged (IP in B) | `current_unresolved_ip_in_baseline_not_flagged` |

### Different IPs (5 cases)

| # | Curr R? | Base R? | Domain match | Expected | Test |
|---|---------|---------|-------------|----------|------|
| 10 | `Some X` | `Some X` | same | not flagged | `discarded_ip_when_domain_seen_in_baseline` |
| 11 | `Some Y` | `Some X` | diff | flagged | `keeps_ip_when_domain_is_new` |
| 12 | `None` | `Some X` | — | flagged (IP not in B) | `falls_back_to_ip_when_neither_resolves` |
| 13 | `Some Y` | `None` | — | flagged (base domains empty) | `current_resolves_baseline_ip_unresolvable` |
| 14 | `None` | `None` | — | flagged (IP not in B) | `falls_back_to_ip_when_neither_resolves` |

### Set-size and multi-IP edges (4 cases)

| # | curr | baseline | Expected | Test |
|---|------|----------|----------|------|
| 15 | empty | non-empty | empty | `empty_current_returns_nothing` |
| 16 | non-empty | empty | all flagged | `empty_baseline_flags_all_current` |
| 17 | 2 IPs (1 same-domain, 1 new-domain) | 1 IP | new-domain flagged | `discarded_ip_when_domain_seen_in_baseline` |
| 18 | 3 IPs (all same domain as baseline) | 1 IP | all filtered | `multiple_ips_same_domain_all_discarded` |
| 19 | 2 IPs (1 resolves new, 1 unresolvable) | 1 IP | both flagged | `mixed_resolved_and_unresolved` |
| 20 | 2 IPs (1 in B, 1 not), both unresolvable | 1 IP | only new flagged | `not_new_when_ip_in_baseline_and_no_resolution` |

Branch coverage:
- `resolver(ip)` = `Some(domain)`: domain in baseline_domains → filtered (3 tests)
- `resolver(ip)` = `Some(domain)`: domain NOT in baseline_domains → flagged (4 tests)
- `resolver(ip)` = `None`: IP in baseline_ips → filtered (3 tests)
- `resolver(ip)` = `None`: IP NOT in baseline_ips → flagged (4 tests)

## 4. `filter_allowlisted_new_connections` — IP allowlist (3 tests)

| # | Test | Scenario | Expected |
|---|------|----------|----------|
| 21 | `ip_allowlist_filters_new_ips_before_blocking` | Mixed allowlisted + non-allowlisted IPs | Only allowlisted removed |
| 22 | `ip_allowlist_matches_equivalent_ipv6_representations` | Long-form IPv6 vs canonical | Match across representations |
| 23 | `ip_allowlist_matches_across_ipv4_mapped_and_bare_forms` | `::ffff:1.2.3.4` vs `1.2.3.4` | Match across IPv4-mapped |

## 5. `filter_domain_allowlisted_new_connections_with` — domain allowlist (3 tests)

| # | Test | Scenario | Expected |
|---|------|----------|----------|
| 24 | `domain_allowlist_filters_resolved_domains_before_blocking` | Resolved domain matches allowlist | Filtered |
| 25 | `domain_allowlist_does_not_filter_when_lookup_fails` | IP does not resolve | Remains (not filtered) |
| 26 | `domain_allowlist_normalization_matches_case_whitespace_and_trailing_dot` | Mixed-case, whitespace, trailing dot | Matches (pre-normalized) |

## 6. Legacy IP-level tests — routed through domain-aware fn (2 tests)

Pre-existing tests, now pass `|_| None` to `find_new_connections_domain_aware`
so unresolvable IPs fall through to plain membership (identical behaviour).

| # | Test | Scenario | Expected |
|---|------|----------|----------|
| 27 | `detects_anomalous_new_connection` | Unresolvable IP not in baseline | Flagged |
| 28 | `no_anomaly_when_connections_match_baseline` | Unresolvable IP in baseline | Not flagged |

## 7. Pipeline integration (1 test)

| # | Test | Scenario | Expected |
|---|------|----------|----------|
| 29 | `pipeline_chains_domain_aware_diff_with_allowlists` | Full 3-stage: domain-aware diff → IP allowlist → domain allowlist | Each stage correct, final remaining empty |

## 8. DNS interceptor fallback — CDN rotation without PTR records (3 tests)

When both baseline and current IPs belong to the same CDN (e.g. Fastly) but the
IPs have no PTR records, the domain-aware diff falls back to the strace-parsed
DNS response map. If the current IPs were resolved under a domain that baseline
traffic also resolved, and host-side forward confirmation verifies the binding,
the rotation is silently discarded.

| # | Test | Scenario | Expected | Status |
|---|------|----------|----------|--------|
| 30 | `domain_aware_diff_cdn_rotation_without_ptr_handled_by_dns_interceptor` | Fastly IPs, both sets lack PTR, dns_map + host-side verify confirm same domain | not flagged | **PASS** |
| 31 | `dns_interceptor_skips_when_domain_not_in_baseline` | Current IP has domain in dns_map, but domain not in baseline DNS traces | flagged (domain unknown) | **PASS** |
| 32 | `dns_interceptor_skips_when_forward_resolver_does_not_confirm` | Domain known from baseline but host-side lookup does not include this IP | flagged (host verification fails) | **PASS** |

## 9. DNS wire-format parser — strace `-xx` hex-escape decoding (15 tests)

Functions: `unescape_strace_string`, `decode_dns_name`, `parse_dns_response`, `extract_dns_map`.

### `unescape_strace_string` (6 tests)

| # | Test | Input | Expected |
|---|------|-------|----------|
| 33 | `unescape_bare_ascii_passthrough` | `"hello"` | `b"hello"` |
| 34 | `unescape_hex_escape_decode` | `"\x41\x42\x43"` | `b"ABC"` |
| 35 | `unescape_mixed_ascii_and_hex` | `"ab\x63\x64ef"` | `b"abcdef"` |
| 36 | `unescape_empty_string` | `""` | `b""` |
| 37 | `unescape_trailing_backslash` | `"ab\\"` | `b"ab"` |
| 38 | `unescape_backslash_escape_non_hex` | `"a\\nb"` | `b"anb"` (strace `\n` is literal) |

### `decode_dns_name` (8 tests)

| # | Test | Input | Expected |
|---|------|-------|----------|
| 39 | `decode_dns_name_simple_two_label` | `\x03foo\x03com\x00` | `"foo.com"`, offset=9 |
| 40 | `decode_dns_name_root_label_only` | `\x00` | `""`, offset=1 |
| 41 | `decode_dns_name_single_byte_pointer` | `\x03foo\x00\xc0\x00` (ptr to 0) | `"foo"`, offset=7 |
| 42 | `decode_dns_name_recursive_pointer_chain` | `\x03foo\x00\xc0\x00\xc0\x05` (2-hop) | `"foo"`, offset=9 |
| 43 | `decode_dns_name_out_of_bounds_returns_none` | Label length 16, only 2 bytes | `None` |
| 44 | `decode_dns_name_circular_pointer_returns_none` | `\xc0\x00` (self-ref ptr) | `None`, offset=0 |
| 45 | `decode_dns_name_long_but_not_circular_pointer_chain` | 3-hop chain → `\x03foo\x00` | `"foo"`, offset=2 |
| 46 | `decode_dns_name_excessive_pointer_hops_returns_none` | 6 pointers (limit 5) | `None` |

### `parse_dns_response` (4 tests)

| # | Test | Scenario | Expected |
|---|------|----------|----------|
| 47 | `parse_dns_response_a_record` | 1 A record for `foo.com` → 93.184.216.34 | `Some(("foo.com", [93.184.216.34]))` |
| 48 | `parse_dns_response_aaaa_record` | 1 AAAA record for `foo` → `2001:db8::1` | `Some(("foo", [2001:db8::1]))` |
| 49 | `parse_dns_response_non_response_returns_none` | QR flag not set | `None` |
| 50 | `parse_dns_response_too_short_returns_none` | 3 bytes only | `None` |

### `extract_dns_map` (3 tests)

| # | Test | Scenario | Expected |
|---|------|----------|----------|
| 51 | `extract_dns_map_empty_trace` | No DNS recvfrom in trace | Empty map |
| 52 | `extract_dns_map_malformed_payload_skipped` | recvfrom from port 53 with invalid payload | Empty map |
| 53 | `dns_interceptor_end_to_end_with_realistic_strace_trace` | Realistic strace -xx trace: connect calls + recvfrom with A+AAAA DNS response → parsed dns_map fed into find_new_connections_domain_aware | 1 domain extracted, CDN IPs not flagged |

## 10. Full pipeline integration: strace → dns_map → domain-aware diff (1 test)

Test 53 above covers the full wire: a realistic strace trace is fed through `extract_dns_map`, the parsed result is verified, and then the dns_map is wired into `find_new_connections_domain_aware` alongside baseline data and forward_resolver.

This validates:
- strace recvfrom+regex matching with spaces (`-xx` hex format)
- DNS response wire-format parsing (A + AAAA coexisting)
- dns_map threading into the domain-aware diff
- CDN rotation silent discard via DNS interceptor

**Total: 53 tests documented; 53 pass, 0 fail.**

## Coverage summary

- FCrDNS (forward_confirmed_hostname): 3 tests — all resolver branches
- reverse_dns_domain: 1 test — input guard
- Domain-aware IP diff (find_new_connections_domain_aware): 14 tests — full truth table
- IP allowlist: 3 tests — filtering, normalization, IPv4-mapped equivalence
- Domain allowlist: 3 tests — filtering, failure mode, normalization
- Legacy routing: 2 tests — backward compatibility
- Pipeline integration: 1 test — end-to-end 3-stage chain
- DNS interceptor fallback: 3 tests — CDN rotation, unknown domain, failed host verification
- DNS wire-format parser: 21 tests — unescape, decode, parse, extract
- **Total: 53 tests, all passing**
