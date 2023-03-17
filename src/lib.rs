use libflate::gzip::Decoder;
use maxminddb::geoip2;
use std::env::VarError;
use std::io::{copy, Error as IOError, Write};
use std::{env, fs, net::IpAddr, path::Path};
use tar::Archive;

static DATABASE_EXPIRATION_DURATION: u64 = 3600 * 24 * 7;

static DATABASE_FILE_PATH: &'static str = "./GeoLite2-City.mmdb";

static DOWNLOADED_FILE: &'static str = "GeoLite2-City.mmdb.tar.gz";

static TAR_FILE: &'static str = "GeoLite2-City.mmdb.tar";

static MAXMIND_DB_LICENSE_KEY_ENV_VAR_NAME: &'static str = "MAXMIND_DB_LICENSE_KEY";

static UNKNOWN: &'static str = "Unknown";

#[derive(Clone, Debug)]
pub struct GeoLocation {
    pub country: String,
    pub city: String,
}

#[derive(Debug)]
pub enum GeoIpError {
    DBLookupError(maxminddb::MaxMindDBError),
    IO(IOError),
    Other(String),
}

#[derive(Clone)]
pub struct MaxMindDb;

impl GeoLocation {
    pub fn new(geoip: geoip2::City) -> Self {
        Self {
            city: Self::city(geoip.city),
            country: Self::country(geoip.country),
        }
    }

    fn city(geoip_city: Option<geoip2::city::City>) -> String {
        match geoip_city {
            None => UNKNOWN.to_string(),
            Some(gc) => match gc.names {
                None => UNKNOWN.to_string(),
                Some(names) => match names.get("en") {
                    None => UNKNOWN.to_string(),
                    Some(name) => name.to_string(),
                },
            },
        }
    }

    fn country(geoip_city: Option<geoip2::country::Country>) -> String {
        match geoip_city {
            None => UNKNOWN.to_string(),
            Some(gc) => match gc.names {
                None => UNKNOWN.to_string(),
                Some(c) => match c.get("en") {
                    None => UNKNOWN.to_string(),
                    Some(name) => name.to_string(),
                },
            },
        }
    }
}

impl From<IOError> for GeoIpError {
    fn from(value: IOError) -> Self {
        GeoIpError::IO(value)
    }
}

impl From<maxminddb::MaxMindDBError> for GeoIpError {
    fn from(value: maxminddb::MaxMindDBError) -> Self {
        GeoIpError::DBLookupError(value)
    }
}

impl From<VarError> for GeoIpError {
    fn from(value: VarError) -> Self {
        GeoIpError::Other(format!("{}", value))
    }
}

impl MaxMindDb {
    pub async fn loopkup(ip: IpAddr) -> Result<GeoLocation, GeoIpError> {
        let db = database().await?;
        let geoip: geoip2::City = db.lookup(ip)?;
        Ok(GeoLocation::new(geoip))
    }
}

async fn database() -> Result<maxminddb::Reader<Vec<u8>>, GeoIpError> {
    ready_database().await?;
    let db = maxminddb::Reader::open_readfile(DATABASE_FILE_PATH)?;
    Ok(db)
}

async fn ready_database() -> Result<(), GeoIpError> {
    if Path::new(DATABASE_FILE_PATH).exists() && !is_database_expired() {
        return Ok(());
    }

    extract_database(&download_database().await?)
}

fn is_database_expired() -> bool {
    match fs::metadata(DATABASE_FILE_PATH) {
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

async fn download_database() -> Result<String, GeoIpError> {
    let license_key = env::var(MAXMIND_DB_LICENSE_KEY_ENV_VAR_NAME)?;
    let url = format!("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key={}&suffix=tar.gz", license_key);

    let temp_file_path = env::temp_dir().join(DOWNLOADED_FILE);
    let temp_file_path = temp_file_path
        .as_path()
        .to_str()
        .ok_or_else(|| GeoIpError::Other("Could not get path for the download file.".to_owned()))?;

    let mut temp_file = fs::File::create(temp_file_path)?;

    let mut res = reqwest::get(&url)
        .await
        .map_err(|e| GeoIpError::Other(format!("{}", e)))?;

    while let Some(chunk) = res
        .chunk()
        .await
        .map_err(|e| GeoIpError::Other(format!("{}", e)))?
    {
        temp_file
            .write_all(&chunk[..])
            .map_err(|e| GeoIpError::Other(format!("{}", e)))?;
    }

    Ok(temp_file_path.to_string())
}

fn extract_database(downloaded_file_path: &str) -> Result<(), GeoIpError> {
    let mut downloaded_file = fs::File::open(downloaded_file_path)?;
    let mut decoder = Decoder::new(&mut downloaded_file)?;

    let tar_file_path = env::temp_dir().join(TAR_FILE);
    let tar_file_path = tar_file_path
        .as_path()
        .to_str()
        .ok_or_else(|| GeoIpError::Other("Could not get path for the tar file.".to_owned()))?;

    let mut tar_file = fs::File::create(tar_file_path)?;
    copy(&mut decoder, &mut tar_file)?;

    let mut tar_file = Archive::new(fs::File::open(tar_file_path)?);
    let mut database_file = fs::File::create(DATABASE_FILE_PATH)?;

    for file in tar_file.entries()? {
        let mut f = file?;

        let file_path = f.path()?;

        if file_path.file_name().unwrap_or_default() == "GeoLite2-City.mmdb" {
            copy(&mut f, &mut database_file)?;
        }
    }

    Ok(())
}
