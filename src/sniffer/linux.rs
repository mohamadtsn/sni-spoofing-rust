use std::io;
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::RawFd;

use tracing::info;

use super::RawBackend;
use crate::error::SnifferError;

pub struct AfPacketBackend {
    fd: RawFd,
    ifindex: i32,
}

impl AfPacketBackend {
    pub fn open(upstreams: &[SocketAddr]) -> Result<Self, SnifferError> {
        let first = upstreams.first().expect("no upstreams");
        let (ifname, ifindex) = get_interface_for(first.ip())?;
        info!(interface = %ifname, ifindex, "binding AF_PACKET socket");

        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_ALL as u16).to_be() as i32,
            )
        };
        if fd < 0 {
            return Err(SnifferError::SocketOpen(io::Error::last_os_error()));
        }

        let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        sll.sll_ifindex = ifindex;

        let ret = unsafe {
            libc::bind(
                fd,
                &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(SnifferError::SocketBind(io::Error::last_os_error()));
        }

        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 100_000,
        };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                mem::size_of::<libc::timeval>() as u32,
            );
        }

        if let Err(error) = attach_bpf_filter(fd, upstreams) {
            unsafe { libc::close(fd) };
            return Err(error);
        }

        Ok(AfPacketBackend { fd, ifindex })
    }
}

impl RawBackend for AfPacketBackend {
    fn frame_kind(&self) -> crate::packet::FrameKind {
        crate::packet::FrameKind::Ethernet
    }

    fn recv_frame(&mut self, buf: &mut [u8]) -> Result<usize, SnifferError> {
        let n = unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if n < 0 {
            return Err(SnifferError::Recv(io::Error::last_os_error()));
        }
        Ok(n as usize)
    }

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), SnifferError> {
        let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_IP as u16).to_be();
        sll.sll_ifindex = self.ifindex;
        sll.sll_halen = 6;
        sll.sll_addr[..6].copy_from_slice(&frame[0..6]);

        let ret = unsafe {
            libc::sendto(
                self.fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
                &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if ret < 0 {
            return Err(SnifferError::Inject(io::Error::last_os_error()));
        }
        Ok(())
    }
}

impl Drop for AfPacketBackend {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

fn get_interface_for(ip: IpAddr) -> Result<(String, i32), SnifferError> {
    use std::net::UdpSocket;

    let target = match ip {
        IpAddr::V4(v4) => format!("{}:53", v4),
        IpAddr::V6(v6) => format!("[{}]:53", v6),
    };

    let sock = UdpSocket::bind(if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
        .map_err(|e| SnifferError::Other(format!("bind UDP: {}", e)))?;
    sock.connect(&target)
        .map_err(|e| SnifferError::Other(format!("connect UDP to {}: {}", target, e)))?;
    let local_ip = sock
        .local_addr()
        .map_err(|e| SnifferError::Other(format!("local addr: {}", e)))?
        .ip();

    let addrs = nix::ifaddrs::getifaddrs()
        .map_err(|e| SnifferError::Other(format!("getifaddrs: {}", e)))?;
    for ifaddr in addrs {
        if let Some(addr) = ifaddr.address {
            let matches = match (addr.as_sockaddr_in(), addr.as_sockaddr_in6()) {
                (Some(v4), _) => IpAddr::V4(v4.ip()) == local_ip,
                (_, Some(v6)) => IpAddr::V6(v6.ip()) == local_ip,
                _ => false,
            };
            if matches {
                let ifname = ifaddr.interface_name.clone();
                let ifindex = nix::net::if_::if_nametoindex(ifname.as_str())
                    .map_err(|e| SnifferError::Other(format!("if_nametoindex: {}", e)))?;
                return Ok((ifname, ifindex as i32));
            }
        }
    }

    Err(SnifferError::Other(format!(
        "no interface found for local IP {}",
        local_ip
    )))
}

fn build_bpf_filter(upstreams: &[SocketAddr]) -> Vec<libc::sock_filter> {
    let mut filter = vec![
        libc::sock_filter {
            code: 0x28,
            jt: 0,
            jf: 0,
            k: 0x0000000c,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 2,
            k: 0x00000800,
        },
        libc::sock_filter {
            code: 0x30,
            jt: 0,
            jf: 0,
            k: 0x00000017,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 6,
            jf: 7,
            k: 0x00000006,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 6,
            k: 0x000086dd,
        },
        libc::sock_filter {
            code: 0x30,
            jt: 0,
            jf: 0,
            k: 0x00000014,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 3,
            jf: 0,
            k: 0x00000006,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 3,
            k: 0x0000002c,
        },
        libc::sock_filter {
            code: 0x30,
            jt: 0,
            jf: 0,
            k: 0x00000036,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: 0x00000006,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x00040000,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x00000000,
        },
    ];

    let ipv4_addrs: std::collections::BTreeSet<u32> = upstreams
        .iter()
        .filter_map(|addr| match addr.ip() {
            IpAddr::V4(ip) => Some(u32::from(ip)),
            IpAddr::V6(_) => None,
        })
        .collect();

    // Keep the TCP-only fallback when address checks would exceed Linux's 4096 instructions.
    if ipv4_addrs.len() <= (4096 - 15) / 4 {
        filter[3].jt = 8; // IPv4 TCP continues past the original accept/reject instructions.
        for offset in [26, 30] {
            filter.push(libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: offset,
            });
            for &ip in &ipv4_addrs {
                filter.push(libc::sock_filter {
                    code: 0x15,
                    jt: 0,
                    jf: 1,
                    k: ip,
                });
                filter.push(libc::sock_filter {
                    code: 0x06,
                    jt: 0,
                    jf: 0,
                    k: 0x00040000,
                });
            }
        }
        filter.push(libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0,
        });
    }
    filter
}

fn attach_bpf_filter(fd: RawFd, upstreams: &[SocketAddr]) -> Result<(), SnifferError> {
    let filter = build_bpf_filter(upstreams);
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &prog as *const libc::sock_fprog as *const libc::c_void,
            mem::size_of::<libc::sock_fprog>() as u32,
        )
    };
    if ret < 0 {
        return Err(SnifferError::FilterAttach(io::Error::last_os_error()));
    }

    info!("BPF filter attached (TCP, IPv4 upstream filtering when within instruction limit)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixDatagram;
    use std::time::Duration;

    fn ipv4_frame(src: [u8; 4], dst: [u8; 4], protocol: u8, ihl: usize) -> Vec<u8> {
        let mut frame = vec![0; 14 + ihl * 4 + 20];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame[14] = 0x40 | ihl as u8;
        frame[23] = protocol;
        frame[26..30].copy_from_slice(&src);
        frame[30..34].copy_from_slice(&dst);
        frame
    }

    fn captured(upstreams: &[SocketAddr], frame: &[u8]) -> bool {
        let (rx, tx) = UnixDatagram::pair().unwrap();
        rx.set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        attach_bpf_filter(rx.as_raw_fd(), upstreams).unwrap();
        tx.send(frame).unwrap();
        let mut buf = vec![0; frame.len().max(1)];
        match rx.recv(&mut buf) {
            Ok(n) => {
                assert_eq!(&buf[..n], frame);
                true
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                false
            }
            Err(e) => panic!("recv failed: {e}"),
        }
    }

    #[test]
    fn kernel_filter_keeps_upstream_tcp_and_ipv6_behavior() {
        let upstreams = [
            "188.114.99.0:443".parse().unwrap(),
            "104.18.32.47:443".parse().unwrap(),
            "188.114.99.0:8443".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
        ];
        let local = [192, 168, 0, 198];
        for remote in [[188, 114, 99, 0], [104, 18, 32, 47]] {
            for ihl in [5, 6, 15] {
                assert!(captured(&upstreams, &ipv4_frame(local, remote, 6, ihl)));
                assert!(captured(&upstreams, &ipv4_frame(remote, local, 6, ihl)));
            }
        }
        assert!(!captured(
            &upstreams,
            &ipv4_frame(local, [8, 8, 8, 8], 6, 5)
        ));
        assert!(!captured(
            &upstreams,
            &ipv4_frame(local, [188, 114, 99, 0], 17, 5)
        ));
        assert!(!captured(&upstreams, &[0; 10]));
        assert!(!captured(&[], &ipv4_frame(local, [188, 114, 99, 0], 6, 5)));

        let mut ipv6 = vec![0; 82];
        ipv6[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        ipv6[14] = 0x60;
        ipv6[20] = 6;
        assert!(captured(&upstreams, &ipv6));
        ipv6[20] = 44;
        ipv6[54] = 6;
        assert!(captured(&upstreams, &ipv6));
        ipv6[54] = 17;
        assert!(!captured(&upstreams, &ipv6));
        ipv6[20] = 17;
        assert!(!captured(&upstreams, &ipv6));
    }

    #[test]
    fn kernel_filter_handles_instruction_limit_without_losing_upstreams() {
        let mut upstreams: Vec<SocketAddr> = (0..1020u32)
            .map(|ip| SocketAddr::new(std::net::Ipv4Addr::from(ip).into(), 443))
            .collect();
        assert_eq!(build_bpf_filter(&upstreams).len(), 4095);
        assert!(captured(
            &upstreams,
            &ipv4_frame([1, 2, 3, 4], [0, 0, 3, 251], 6, 5)
        ));
        upstreams.push("203.0.113.7:443".parse().unwrap());
        assert_eq!(build_bpf_filter(&upstreams).len(), 12);
        assert!(captured(
            &upstreams,
            &ipv4_frame([1, 2, 3, 4], [203, 0, 113, 7], 6, 5)
        ));
    }
}
