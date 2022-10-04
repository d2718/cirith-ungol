/*!
Mapping file extensions to MIME types.
*/
use std::{
    collections::HashMap,
    ffi::OsString,
    str::FromStr,
};

static MINIMAL: &[(&str, &str)] = &[
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

pub fn minimal_mime_map() -> HashMap<OsString, String> {
    let map: HashMap<OsString, String> = MINIMAL.iter()
        .map(|(k, v)| (OsString::from_str(k).unwrap(), String::from(*v)))
        .collect();
    map
}