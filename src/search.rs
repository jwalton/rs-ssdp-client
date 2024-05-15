use crate::{Error, SearchTarget};

use futures_core::stream::Stream;
use genawaiter::sync::{Co, Gen};
use std::{net::SocketAddr, time::Duration};
use tokio::net::UdpSocket;

const INSUFFICIENT_BUFFER_MSG: &str = "buffer size too small, udp packets lost";
const DEFAULT_SEARCH_TTL: u32 = 2;
const DEFAULT_SEARCH_TARGET: SearchTarget = SearchTarget::All;

/// Used to construct a SSDP search request with options.
#[derive(Debug)]
pub struct SearchBuilder<'a> {
    search_target: &'a SearchTarget,
    timeout: Duration,
    mx: usize,
    ttl: Option<u32>,
    bind_address: Option<SocketAddr>,
}

#[derive(Debug)]
/// Response given by ssdp control point
pub struct SearchResponse {
    location: String,
    st: SearchTarget,
    usn: String,
    server: String,
}

impl SearchResponse {
    /// URL of the control point
    pub fn location(&self) -> &str {
        &self.location
    }
    /// search target returned by the control point
    pub fn search_target(&self) -> &SearchTarget {
        &self.st
    }
    /// Unique Service Name
    pub fn usn(&self) -> &str {
        &self.usn
    }
    /// Server (user agent)
    pub fn server(&self) -> &str {
        &self.server
    }
}

#[cfg(not(windows))]
async fn get_bind_addr() -> Result<SocketAddr, std::io::Error> {
    Ok(([0, 0, 0, 0], 0).into())
}

#[cfg(windows)]
async fn get_bind_addr() -> Result<SocketAddr, std::io::Error> {
    // Windows 10 is multihomed so that the address that is used for the broadcast send is not guaranteed to be your local ip address, it can be any of the virtual interfaces instead.
    // Thanks to @dheijl for figuring this out <3 (https://github.com/jakobhellermann/ssdp-client/issues/3#issuecomment-687098826)
    let any: SocketAddr = ([0, 0, 0, 0], 0).into();
    let socket = UdpSocket::bind(any).await?;
    let googledns: SocketAddr = ([8, 8, 8, 8], 80).into();
    socket.connect(googledns).await?;
    let bind_addr = socket.local_addr()?;

    Ok(bind_addr)
}

impl<'a> SearchBuilder<'a> {
    /// Create a new search builder
    pub fn new() -> Self {
        Self {
            search_target: &DEFAULT_SEARCH_TARGET,
            timeout: Duration::from_secs(5),
            mx: 4,
            ttl: None,
            bind_address: None,
        }
    }

    /// Set the search target. If none is provided, defaults to SearchTarget::All.
    pub fn search_target(mut self, search_target: &'a SearchTarget) -> Self {
        self.search_target = search_target;
        self
    }

    /// Set the timeout for the search. Defaults to 5 seconds. This should be set
    /// higher than the mx value.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the maximum wait time for responses. Defaults to 4 seconds.
    pub fn mx(mut self, mx: usize) -> Self {
        self.mx = mx;
        self
    }

    /// Set the time-to-live value of outgoing multicast packets. Defaults to 2.
    pub fn ttl(mut self, ttl: u32) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set the bind address for the search. If none is provided, the search will
    /// try to bind to 0.0.0.0 on Unix-like systems or try to detect the interface
    /// to use on Windows systems.  Use `0` for the port to pick a free port.
    pub fn bind_address(mut self, bind_address: SocketAddr) -> Self {
        self.bind_address = Some(bind_address);
        self
    }

    /// Perform the search
    pub async fn search(self) -> Result<impl Stream<Item = Result<SearchResponse, Error>>, Error> {
        let bind_address = match self.bind_address {
            Some(addr) => addr,
            None => get_bind_addr().await?,
        };
        let broadcast_address: SocketAddr = ([239, 255, 255, 250], 1900).into();

        let socket = UdpSocket::bind(&bind_address).await?;
        socket
            .set_multicast_ttl_v4(self.ttl.unwrap_or(DEFAULT_SEARCH_TTL))
            .ok();

        let msg = format!(
            "M-SEARCH * HTTP/1.1\r
Host:239.255.255.250:1900\r
Man:\"ssdp:discover\"\r
ST: {}\r
MX: {}\r\n\r\n",
            self.search_target, self.mx
        );
        socket.send_to(msg.as_bytes(), &broadcast_address).await?;

        Ok(Gen::new(move |co| socket_stream(socket, self.timeout, co)))
    }
}

impl Default for SearchBuilder<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// Search for SSDP control points within a network.
/// Control Points will wait a random amount of time between 0 and mx seconds before responing to avoid flooding the requester with responses.
/// Therefore, the timeout should be at least mx seconds.
pub async fn search(
    search_target: &SearchTarget,
    timeout: Duration,
    mx: usize,
    ttl: Option<u32>,
) -> Result<impl Stream<Item = Result<SearchResponse, Error>>, Error> {
    SearchBuilder::new()
        .search_target(search_target)
        .timeout(timeout)
        .mx(mx)
        .ttl(ttl.unwrap_or(DEFAULT_SEARCH_TTL))
        .search().await
}

macro_rules! yield_try {
    ( $co:expr => $expr:expr ) => {
        match $expr {
            Ok(val) => val,
            Err(e) => {
                $co.yield_(Err(e.into())).await;
                continue;
            }
        }
    };
}

async fn socket_stream(
    socket: UdpSocket,
    timeout: Duration,
    co: Co<Result<SearchResponse, Error>>,
) {
    loop {
        let mut buf = [0u8; 2048];
        let text = match tokio::time::timeout(timeout, socket.recv(&mut buf)).await {
            Err(_) => break,
            Ok(res) => match res {
                Ok(2048) => {
                    log::warn!("{}", INSUFFICIENT_BUFFER_MSG);
                    continue;
                }
                Ok(read) => yield_try!(co => std::str::from_utf8(&buf[..read])),
                Err(e) => {
                    co.yield_(Err(e.into())).await;
                    continue;
                }
            },
        };

        let headers = yield_try!(co => parse_headers(text));

        let mut location = None;
        let mut st = None;
        let mut usn = None;
        let mut server = None;

        for (header, value) in headers {
            if header.eq_ignore_ascii_case("location") {
                location = Some(value);
            } else if header.eq_ignore_ascii_case("st") {
                st = Some(value);
            } else if header.eq_ignore_ascii_case("usn") {
                usn = Some(value);
            } else if header.eq_ignore_ascii_case("server") {
                server = Some(value);
            }
        }

        let location = yield_try!(co => location
            .ok_or(Error::MissingHeader("location")))
        .to_string();
        let st = yield_try!(co => yield_try!(co => st.ok_or(Error::MissingHeader("st"))).parse::<SearchTarget>());
        let usn = yield_try!(co => usn.ok_or(Error::MissingHeader("urn"))).to_string();
        let server = yield_try!(co => server.ok_or(Error::MissingHeader("server"))).to_string();

        co.yield_(Ok(SearchResponse {
            location,
            st,
            usn,
            server,
        }))
        .await;
    }
}

fn parse_headers(response: &str) -> Result<impl Iterator<Item = (&str, &str)>, Error> {
    let mut response = response.split("\r\n");
    let status_code = response
        .next()
        .ok_or(Error::InvalidHTTP("http response is empty"))?
        .trim_start_matches("HTTP/1.1 ")
        .chars()
        .take_while(|x| x.is_numeric())
        .collect::<String>()
        .parse::<u32>()
        .map_err(|_| Error::InvalidHTTP("status code is not a number"))?;

    if status_code != 200 {
        return Err(Error::HTTPError(status_code));
    }

    let iter = response.filter_map(|l| {
        let mut split = l.splitn(2, ':');
        match (split.next(), split.next()) {
            (Some(header), Some(value)) => Some((header, value.trim())),
            _ => None,
        }
    });

    Ok(iter)
}
