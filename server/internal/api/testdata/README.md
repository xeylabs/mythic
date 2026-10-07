# testdata

## test-asn.mmdb

Synthetic ASN test fixture — **not** a MaxMind database and **not** derived
from one. Generated in-repo with `github.com/maxmind/mmdbwriter` (see the
generator used at fix time; mappings below are hardcoded test values, not
real-world claims):

| network         | ASN   | label        |
|-----------------|-------|--------------|
| 8.8.8.0/24      | 15169 | GOOGLE       |
| 1.1.1.0/24      | 13335 | CLOUDFLARENET|
| 2001:4860::/32  | 15169 | GOOGLE-V6    |

IPs not listed (e.g. 9.9.9.9, 192.0.2.1) are intentionally absent so tests
can assert the "unknown → 0" path against a real database file.

Regenerate (requires the mmdbwriter module):

```sh
go run ./gen <output.mmdb>   # from a scratch module with github.com/maxmind/mmdbwriter
```
