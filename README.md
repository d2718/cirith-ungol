# cirith-ungol
Simple, single-threaded web server using
[`axum`](https://github.com/tokio-rs/axum).

This is an initial working version that has the following basic features:

  * serves static files
  * HTTP and HTTPS
  * runs CGI programs in response to both `GET` and `POST` requests
  * configurable blacklist
  * request logging
  * extremely permissive CORS implementation

The target use case of this software is serving small or personal websites
from virtual machines.

### Build

Build for `x86_64-unknown-linux-musl` for maximum compatibility and
strip it, because we don't need no stinking debug symbols.

```sh
cargo build --release --target x86_64-unknown-linux-musl
strip target/x86_64-unknown-linux-musl/release/cirith-ungol
```

### Install

Put the binary somewhere in your `$PATH` and make it executable.

```sh
sudo cp target/x86_64-unknown-linux-musl/release/cirith-ungol ~/usr/local/bin/
sudo chmod +x /usr/local/bin/cirith-ungol
```

Go ahead and make a configuration directory for it where you can put a
config file.

```sh
mkdir ~/.config/cirith-ungol
```

Create a a `config.toml` file there:

```toml
default_host = "default"
# User name as which to run after binding port 80 (and 443, if using TLS)
# and dropping root.
user = "www-data"
# You only need these next two if you want to support HTTPS.
ssl_cert = "/path/to/cert_file.pem"
ssl_key  = "/path/to/key_file.pem"
blacklist = [
    "157.240.229.35",
    "2a03:2880:f103:181:face:b00c:0:25de"
]

[[host]]
name = "default"
root = "/home/you/fake_webroot"

[[host]]
name = "yourdomain.com"
root = "/home/you/webroot"

[[cgi]]
path = "/home/you/webroot/cgi-bin"
# Set this to `false` if you _only_ want to run scripts through the
# interpreters specified below. Keep it `true` if you want to run any
# ol' file marked executable in the given directory.
execute = true
interpreters = [
    { ext = "py",  bin = "/usr/bin/python" },
    { ext = "lua", bin = "/usr/bin/lua" },
    { ext = "pl",  bin = "/usr/bin/perl" }
]
```

### Run

Right now it only reads configuration from `config.toml` in the current
directory.

```sh
cd ~/.config/cirith-ungol
```

Run it as root so you can bind to ports 80 and 443

```sh
sudo nohup cirith-ungol >run.log &
```

## To Do

  * make logging optional
  * command line arguments (and maybe look for config file in a few
    common places)
  * request rate limiting
  * maybe per-IP rate limiting
  * ~~CORS layer (pretty sure this is just a matter of adding an existing
    [`tower`](https://github.com/tower-rs/tower) Service)~~
  * configurable CORS layer (it is, in fact, a pretty simple `tower` layer)
  * more complete set of environment variables passed through CGI
  * custom MIME type configuration