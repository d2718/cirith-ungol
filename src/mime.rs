use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    str::FromStr,
};

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

pub struct MimeMap {
    map: BTreeMap<OsString, String>
}

impl MimeMap {
    pub fn empty() -> Self {
        Self { map: BTreeMap::new() }
    }

    pub fn set<K, V>(&mut self, k: K, v: V)
    where
        K: Into<OsString>,
        V: Into<String>,
    {
        let k = k.into();
        let v = v.into();
        _ = self.map.insert(k, v);
    }

    pub fn get<K: AsRef<OsStr>>(&self, k: K) -> Option<&String> {
        let k = k.as_ref();
        self.map.get(k)
    }

    pub fn mime_type<'a, K: AsRef<OsStr>>(&'a self, k: K) -> &'a str {
        let k = k.as_ref().to_os_string().to_ascii_lowercase();
        match self.map.get(&k) {
            Some(t) => t.as_str(),
            None => { "application/octet-stream" },
        }
    }

    pub fn maybe_mime_type<'a, K>(&'a self, k: K) -> Option<&'a str>
    where K: AsRef<OsStr>
    {
        let k = k.as_ref().to_os_string().to_ascii_lowercase();
        self.map.get(&k).map(|s| s.as_str())
    }
}

impl Default for MimeMap {
    fn default() -> Self {
        let map: BTreeMap<OsString, String> = DEFAULT.iter()
            .map(|(k, v)| (OsString::from_str(k).unwrap(), String::from(*v)))
            .collect();
        
        Self { map }
    }
}