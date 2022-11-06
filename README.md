# cirith-ungol
Simple, single-threaded web server using
[`axum`](https://github.com/tokio-rs/axum).

This is an initial working version that has the following basic features:

  * serves static files
  * HTTP and HTTPS
  * runs CGI programs in response to both `GET` and `POST` requests
  * configurable blacklist
  * request logging
  * very permissive CORS layer

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
# If a request has no Host header, or a value which doesn't match any of
# the configured hosts, it will be routed to this host. If this option is
# omitted, it will be insta-404'd.
default_host = "default"

# User name as which to run after binding port 80 (and 443, if using TLS)
# and dropping root.
user = "www-data"

# You only need these next two if you want to support HTTPS.
ssl_cert = "/path/to/cert_file.pem"
ssl_key  = "/path/to/key_file.pem"

# Example of blacklisting IPs. You don't necessarily need to blacklist these.
# Requests from these addresses will be insta-404'd.
blacklist = [
    "157.240.229.35",
    "2a03:2880:f103:181:face:b00c:0:25de"
]

# Each [[host]] stanza configures a host. A good idea is to set a "default"
# host that redirects to something dull or simple, and then a host with your
# actual domain name that points to your site.

[[host]]
name = "default"
root = "/home/you/fake_webroot"

[[host]]
# Domain name of your site.
name = "yourdomain.com"
# Local directory where the root URI of your domain should point.
root = "/home/you/webroot"
# List of local directories whose contents will be treated as CGI scripts.
cgi = ["/home/you/webrot/cgi-bin"]

```

This is, of course, just an example configuration. There are a few more options
(and there will probably eventually be more), but one of the project's goals is
to be easy to configure.

### Run

Go ahead and switch to that directory, because it's easiest to refer to a
config file in the current directory, and also so that it's easy to put the
log file there.

```sh
cd ~/.config/cirith-ungol
```

Run it as root so you can bind to ports 80 and 443. It logs to stdout, so
redirect that to a file.

```sh
sudo nohup cirith-ungol >run.log &
```

## To Do

  * Make logging optional.
  * more command line arguments (and maybe look for config file in a few
    common places)
  * request rate limiting
  * maybe per-IP rate limiting
  * directory autoindexing
  * ETags
  * ~~CORS layer (pretty sure this is just a matter of adding an existing
    [`tower`](https://github.com/tower-rs/tower) Service)~~
  * configurable CORS layer (it is, in fact, a pretty simple `tower` layer)
  * more complete set of environment variables passed through CGI
  * custom MIME type configuration
  * Squash a bunch of the `tower::Layer`s together into a single layer to
    reduce async runtime complexity.