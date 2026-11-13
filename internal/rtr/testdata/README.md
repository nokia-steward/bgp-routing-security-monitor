# RTR test fixtures

Real RTR deltas used as fixtures by `internal/rtr/fort_fixture_test.go`.

## Fort 1.7.0 deltas

| File | Serials | Announcements | Withdrawals | Wire order (`seq`) |
|---|---|---|---|---|
| `fort-delta-219-220.txt` | 219 → 220 | 764 | 760 | no |
| `fort-delta-220-221.txt` | 220 → 221 | 2276 | 2263 | yes |

Captured by Antonio Prado (University of Padova, ASPA Explorer) with his own
RTR client over RTR protocol version 1, from a Fort 1.7.0 validator, and
contributed to RAVEN under the repository's BSD-3-Clause license (see
`LICENSE`).

They show the Fort 1.7.0 bug reported as
[NICMx/FORT-validator#204](https://github.com/NICMx/FORT-validator/issues/204):
a delta announces records the client already holds and then withdraws them in
the same response, although the intended net change for those records is
zero. In 220 → 221, 2255 records are announced again while held and then
withdrawn; the real change is 21 announced and 8 withdrawn. A client that
ignores the duplicate announcements and applies the withdrawals loses the
2255 valid VRPs.

### Format

Each file is one JSON object, saved as `.txt`, from the capturing client's
log:

| Key | Meaning |
|---|---|
| `t` | When the delta was captured (RFC 3339, UTC) |
| `from`, `serial` | The serial before and after the delta |
| `ann` | The announcements (IPv4 and IPv6 Prefix PDUs with flag 1), in wire order |
| `wd` | The withdrawals (flag 0), in wire order |
| `seq` | 220 → 221 only: every Prefix PDU in wire order |

A record is written `prefix/length-maxlength ASN`, for example
`199.36.123.0/24-24 AS16509` or `2804:2540:0:0:0:0:0:0/32-128 AS264268`.

A `seq` entry is `+` (announcement) or `-` (withdrawal), then `H` if the
capturing client held the record before that PDU or `N` if it did not, a
space, and the record: `+H 199.36.120.0/24-24 AS16509`. In 220 → 221 there
are 2255 `+H`, 21 `+N` and 2263 `-H`. The records whose first entry is `H`
are what the client held before the delta: the baseline the test loads with
a full sync before replaying `seq`.

219 → 220 was captured before `seq` existed: it does not say how the
announcements and withdrawals were interleaved, or which records were held.
The test derives a baseline that makes it well defined (every withdrawn
record held) and checks the outcome under several interleavings; see the
comment on `TestFortDelta219To220`.

The files are kept as captured. Do not edit them; add a new file for a new
capture.
