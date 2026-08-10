# Test fixtures

## GeoIP2-City-Test.mmdb

MaxMind's official GeoIP2 City **test** database, used by the geo MMDB tier
tests (`geo_mmdb_test.go`). It is a tiny synthetic fixture (~22 KB) containing a
handful of documented IP ranges — it is NOT a real geolocation database and must
never be used in production.

- Source: <https://github.com/maxmind/MaxMind-DB> (`test-data/GeoIP2-City-Test.mmdb`)
- License: MIT / Apache-2.0 (dual), per that repository

Useful records in this fixture:

| IP              | Country        | City       |
|-----------------|----------------|------------|
| `81.2.69.142`   | United Kingdom | London     |
| `2.125.160.216` | United Kingdom | Boxford    |
| `175.16.199.1`  | China          | Changchun  |
| `89.160.20.112` | Sweden         | Linköping  |
| `8.8.8.8`       | *(no record)*  | —          |

`8.8.8.8` is deliberately absent so tests can exercise the "MMDB miss falls
through to the HTTP tier" path.

For a real deployment, download `GeoLite2-City.mmdb` from MaxMind (free account
required) and point `geoip.mmdb` at it.
