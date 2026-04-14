# maxmind-geoip-rs

Async Rust library for GeoIP lookups using MaxMind's GeoLite2-City database. Downloads and caches the database automatically.

## Usage

```rust
use std::net::IpAddr;
use maxmind_geoip::MaxMindDb;

let ip: IpAddr = "89.160.20.128".parse().unwrap();
let location = MaxMindDb::lookup(ip).await.unwrap();

println!("City: {}, Country: {}", location.city, location.country);
```

## Configuration

The library is configured via environment variables:

| Variable | Required | Description |
|---|---|---|
| `MAXMIND_DB_URL` | No | Direct URL to a `.mmdb` file (e.g. a GCS bucket). If set, the database is downloaded from this URL instead of MaxMind. |
| `MAXMIND_DB_LICENSE_KEY` | No* | MaxMind license key for downloading directly from MaxMind. Used as fallback when `MAXMIND_DB_URL` is not set. |

\* One of `MAXMIND_DB_URL` or `MAXMIND_DB_LICENSE_KEY` must be set.

## How it works

- On the first `lookup()` call, the library downloads the GeoLite2-City database and caches it to disk (`/tmp/GeoLite2-City.mmdb`).
- The database `Reader` is kept in memory for the lifetime of the process — subsequent lookups are fast with no disk I/O.
- The cached file expires after **7 days**, triggering a fresh download on the next lookup.
- A download lock ensures only one task downloads at a time — concurrent lookups wait for the download to finish.
- Downloads write to a temp file first and atomically rename, preventing corrupt files from partial downloads.

## Download sources

1. **`MAXMIND_DB_URL`** (preferred) — Downloads the `.mmdb` file directly. Use this with a GCS/S3 bucket to avoid per-pod downloads from MaxMind.
2. **`MAXMIND_DB_LICENSE_KEY`** (fallback) — Downloads the `tar.gz` from MaxMind's API, extracts the `.mmdb` file.
