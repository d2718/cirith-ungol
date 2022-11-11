#![allow(dead_code)]

use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    str::FromStr,
};

use hyper::header::HeaderValue;
use once_cell::sync::Lazy;

static DEFAULT: &[(&str, &str)] = &[
    ("css", "text/css"),
    ("gz", "application/gzip"),
    ("gif", "image/gif"),
    ("htm", "text/html"),
    ("html", "text/html"),
    ("ico", "image/fnd.microsoft.icon"),
    ("jpeg", "image/jpeg"),
    ("jpg", "image/jpeg"),
    ("js", "text/javascript"),
    ("json", "application/json"),
    ("mp3", "audio/mpeg"),
    ("mp4", "audio/mp4"),
    ("mpeg", "video/mpeg"),
    ("png", "image/png"),
    ("pdf", "application/pdf"),
    ("svg", "image/svg+xml"),
    ("tar", "application/x-tar"),
    ("tif", "image/tiff"),
    ("tiff", "image/tiff"),
    ("txt", "text/plain"),
    ("wasm", "application/wasm"),
    ("wav", "audio/wav"),
    ("weba", "audio/webm"),
    ("webm", "video/webm"),
    ("webp", "image/webp"),
    ("woff", "font/woff"),
    ("woff2", "font/woff2"),
    ("xhtml", "application/xhtml+xml"),
    ("xml", "application/xml"),
    ("zip", "application/zip"),
    ("7z", "application/x-7z-compressed"),
];

pub static OCTET_STREAM: HeaderValue = HeaderValue::from_static("application/octet=stream");

pub static MIME_TYPES: Lazy<MimeMap> = Lazy::new(MimeMap::default);

pub struct MimeMap {
    map: BTreeMap<OsString, HeaderValue>,
}

impl MimeMap {
    pub fn empty() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    pub fn set<K, V>(&mut self, k: K, v: V) -> Result<(), String>
    where
        K: Into<OsString>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: std::fmt::Debug,
    {
        let k = k.into();
        let v = HeaderValue::try_from(v)
            .map_err(|e| format!("Error turning MIME type into header value: {:?}", &e))?;
        _ = self.map.insert(k, v);
        Ok(())
    }

    pub fn get<K: AsRef<OsStr>>(&self, k: K) -> Option<&HeaderValue> {
        let k = k.as_ref();
        self.map.get(k)
    }

    pub fn mime_type<K: AsRef<OsStr>>(&self, k: K) -> &HeaderValue {
        let k = k.as_ref().to_os_string().to_ascii_lowercase();
        self.map.get(&k).unwrap_or(&OCTET_STREAM)
    }

    pub fn maybe_mime_type<K>(&self, k: K) -> Option<&HeaderValue>
    where
        K: AsRef<OsStr>,
    {
        let k = k.as_ref().to_os_string().to_ascii_lowercase();
        self.map.get(&k)
    }
}

impl Default for MimeMap {
    fn default() -> Self {
        let map: BTreeMap<OsString, HeaderValue> = DEFAULT
            .iter()
            .map(|(k, v)| {
                (
                    OsString::from_str(k).unwrap(),
                    HeaderValue::try_from(*v).unwrap(),
                )
            })
            .collect();

        Self { map }
    }
}
