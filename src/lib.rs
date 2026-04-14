use flate2::read::GzDecoder;
use maxminddb::geoip2;
use std::env::VarError;
use std::io::{Error as IOError, Write, copy};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::{env, fs, net::IpAddr, path::Path};
use tar::Archive;
use tokio::sync::Mutex;

static DATABASE_EXPIRATION_DURATION: u64 = 3600 * 24 * 7;

static DATABASE_FILE_NAME: &str = "GeoLite2-City.mmdb";

fn database_file_path() -> &'static Path {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| env::temp_dir().join(DATABASE_FILE_NAME))
        .as_path()
}

static MAXMIND_DB_LICENSE_KEY_ENV_VAR_NAME: &str = "MAXMIND_DB_LICENSE_KEY";

static MAXMIND_DB_URL_ENV_VAR_NAME: &str = "MAXMIND_DB_URL";

static UNKNOWN: &str = "Unknown";

static DB_READER: OnceLock<maxminddb::Reader<Vec<u8>>> = OnceLock::new();

/// Guards database download so only one task downloads at a time.
static DOWNLOAD_LOCK: Mutex<()> = Mutex::const_new(());

#[derive(Clone, Debug)]
pub struct GeoLocation {
    pub country: String,
    pub city: String,
}

#[derive(Debug)]
pub enum GeoIpError {
    DBLookupError(maxminddb::MaxMindDbError),
    IO(IOError),
    Other(String),
}

#[derive(Clone)]
pub struct MaxMindDb;

impl GeoLocation {
    pub fn new(geoip: geoip2::City) -> Self {
        Self {
            city: geoip.city.names.english.unwrap_or(UNKNOWN).to_string(),
            country: geoip.country.names.english.unwrap_or(UNKNOWN).to_string(),
        }
    }
}

impl From<IOError> for GeoIpError {
    fn from(value: IOError) -> Self {
        GeoIpError::IO(value)
    }
}

impl From<maxminddb::MaxMindDbError> for GeoIpError {
    fn from(value: maxminddb::MaxMindDbError) -> Self {
        GeoIpError::DBLookupError(value)
    }
}

impl From<VarError> for GeoIpError {
    fn from(value: VarError) -> Self {
        GeoIpError::Other(format!("{}", value))
    }
}

impl MaxMindDb {
    pub async fn lookup(ip: IpAddr) -> Result<GeoLocation, GeoIpError> {
        let db = get_or_init_reader().await?;
        let result = db.lookup(ip)?;
        let geoip: geoip2::City = result
            .decode()?
            .ok_or_else(|| GeoIpError::Other("No city data found for IP".to_owned()))?;
        Ok(GeoLocation::new(geoip))
    }
}

async fn get_or_init_reader() -> Result<&'static maxminddb::Reader<Vec<u8>>, GeoIpError> {
    if let Some(reader) = DB_READER.get()
        && !is_database_expired()
    {
        return Ok(reader);
    }

    ready_database().await?;
    let reader = maxminddb::Reader::open_readfile(database_file_path())?;

    // If another task initialized it first, that's fine — we just use theirs.
    Ok(DB_READER.get_or_init(|| reader))
}

async fn ready_database() -> Result<(), GeoIpError> {
    if database_file_path().exists() && !is_database_expired() {
        return Ok(());
    }

    // Only one task downloads at a time. Others wait and then find the file ready.
    let _guard = DOWNLOAD_LOCK.lock().await;

    // Re-check after acquiring the lock — another task may have just finished downloading.
    if database_file_path().exists() && !is_database_expired() {
        return Ok(());
    }

    if let Ok(url) = env::var(MAXMIND_DB_URL_ENV_VAR_NAME) {
        eprintln!("[maxmind-geoip] Downloading database from custom URL");
        download_database_from_url(&url).await
    } else {
        eprintln!("[maxmind-geoip] Downloading database from MaxMind");
        download_and_extract_from_maxmind().await
    }
}

fn is_database_expired() -> bool {
    match fs::metadata(database_file_path()) {
        Ok(metadata) => match metadata.modified() {
            Ok(modified) => match modified.elapsed() {
                Ok(elapsed) => elapsed.as_secs() >= DATABASE_EXPIRATION_DURATION,
                Err(_) => true,
            },
            Err(_) => true,
        },
        Err(_) => true,
    }
}

/// Download the .mmdb file directly from a URL (e.g. a GCS bucket).
/// Writes to a temp file first, then atomically renames to avoid partial files.
async fn download_database_from_url(url: &str) -> Result<(), GeoIpError> {
    let tmp_path = database_file_path().with_extension("mmdb.tmp");
    let mut tmp_file = fs::File::create(&tmp_path)?;

    let res = reqwest::get(url)
        .await
        .map_err(|e| GeoIpError::Other(format!("Failed to download from {}: {}", url, e)))?;

    if !res.status().is_success() {
        let _ = fs::remove_file(&tmp_path);
        return Err(GeoIpError::Other(format!(
            "Download from {} failed with HTTP {}",
            url,
            res.status()
        )));
    }

    let bytes = res.bytes().await.map_err(|e| {
        GeoIpError::Other(format!("Failed to read response body from {}: {}", url, e))
    })?;

    tmp_file.write_all(&bytes).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        GeoIpError::Other(format!("Failed to write database file: {}", e))
    })?;

    fs::rename(&tmp_path, database_file_path()).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        GeoIpError::Other(format!("Failed to rename temp file: {}", e))
    })?;

    Ok(())
}

/// Download the tar.gz from MaxMind, extract the .mmdb, and write it atomically.
async fn download_and_extract_from_maxmind() -> Result<(), GeoIpError> {
    let license_key = env::var(MAXMIND_DB_LICENSE_KEY_ENV_VAR_NAME)?;
    let url = format!(
        "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key={}&suffix=tar.gz",
        license_key
    );

    let res = reqwest::get(&url)
        .await
        .map_err(|e| GeoIpError::Other(format!("Failed to download from MaxMind: {}", e)))?;

    if !res.status().is_success() {
        return Err(GeoIpError::Other(format!(
            "MaxMind download failed with HTTP {}",
            res.status()
        )));
    }

    let bytes = res
        .bytes()
        .await
        .map_err(|e| GeoIpError::Other(format!("Failed to read MaxMind response body: {}", e)))?;

    let decoder = GzDecoder::new(&bytes[..]);
    let mut archive = Archive::new(decoder);

    let tmp_path = database_file_path().with_extension("mmdb.tmp");
    let mut found = false;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;

        if path.file_name().unwrap_or_default() == "GeoLite2-City.mmdb" {
            let mut tmp_file = fs::File::create(&tmp_path)?;
            copy(&mut entry, &mut tmp_file)?;
            found = true;
            break;
        }
    }

    if !found {
        let _ = fs::remove_file(&tmp_path);
        return Err(GeoIpError::Other(
            "GeoLite2-City.mmdb not found in MaxMind archive".to_owned(),
        ));
    }

    fs::rename(&tmp_path, database_file_path()).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        GeoIpError::Other(format!("Failed to rename temp file: {}", e))
    })?;

    Ok(())
}
