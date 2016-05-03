// Copyright (C) 2016 James Peach. All rights reserved.
//
// netlink.rs: Netlink socket helpers

extern crate nix;
extern crate libc;

use std::fmt;
use std::os::unix::io::RawFd;
use self::libc::c_int;

use self::nix::sys::*;

// From <netlink/netlink.h>
pub const NETLINK_ROUTE: c_int = 0; /* Routing/device hook */
pub const NETLINK_UNUSED: c_int = 1; /* Unused number */
pub const NETLINK_USERSOCK: c_int = 2; /* Reserved for user mode socket protocols */
pub const NETLINK_FIREWALL: c_int = 3; /* Unused number, formerly ip_queue */
pub const NETLINK_SOCK_DIAG: c_int = 4; /* socket monitoring */
pub const NETLINK_NFLOG: c_int = 5; /* netfilter/iptables ULOG */
pub const NETLINK_XFRM: c_int = 6; /* ipsec */
pub const NETLINK_SELINUX: c_int = 7; /* SELinux event notifications */
pub const NETLINK_ISCSI: c_int = 8; /* Open-iSCSI */
pub const NETLINK_AUDIT: c_int = 9; /* auditing */
pub const NETLINK_FIB_LOOKUP: c_int = 10;
pub const NETLINK_CONNECTOR: c_int = 11;
pub const NETLINK_NETFILTER: c_int = 12; /* netfilter subsystem */
pub const NETLINK_IP6_FW: c_int = 13;
pub const NETLINK_DNRTMSG: c_int = 14; /* DECnet routing messages */
pub const NETLINK_KOBJECT_UEVENT: c_int = 15; /* Kernel messages to userspace */
pub const NETLINK_GENERIC: c_int = 16;
pub const NETLINK_SCSITRANSPORT: c_int = 18; /* SCSI Transports */
pub const NETLINK_ECRYPTFS: c_int = 19;
pub const NETLINK_RDMA: c_int = 20;
pub const NETLINK_CRYPTO: c_int = 21; /* Crypto layer */

// Netlink request flags.
#[allow(dead_code)]
const NLM_F_REQUEST: u16 = 1; /* It is request message. */
#[allow(dead_code)]
const NLM_F_MULTI: u16 = 2; /* Multipart message, terminated by NLMSG_DONE */
#[allow(dead_code)]
const NLM_F_ACK: u16 = 4; /* Reply with ack, with zero or error code */
#[allow(dead_code)]
const NLM_F_ECHO: u16 = 8; /* Echo this request */
#[allow(dead_code)]
const NLM_F_DUMP_INTR: u16 = 16; /* Dump was inconsistent due to sequence change */
#[allow(dead_code)]
const NLM_F_DUMP_FILTERED: u16 = 32;/* Dump was filtered as requested */

// Modifiers to GET request.
#[allow(dead_code)]
const NLM_F_ROOT: u16 = 0x100;   /* specify tree root    */
#[allow(dead_code)]
const NLM_F_MATCH: u16 = 0x200;   /* return all matching  */
#[allow(dead_code)]
const NLM_F_ATOMIC: u16 = 0x400;   /* atomic GET           */
#[allow(dead_code)]
const NLM_F_DUMP: u16 = (NLM_F_ROOT | NLM_F_MATCH);

// Netlink response codes.
#[allow(dead_code)]
const NLMSG_NOOP: u16 = 0x1; /* Nothing. */
#[allow(dead_code)]
const NLMSG_ERROR: u16 = 0x2; /* Error */
#[allow(dead_code)]
const NLMSG_DONE: u16 = 0x3; /* End of a dump */
#[allow(dead_code)]
const NLMSG_OVERRUN: u16 = 0x4; /* Data lost */

#[allow(dead_code)]
const TCPDIAG_GETSOCK: u16 = 18;
#[allow(dead_code)]
const SOCK_DIAG_BY_FAMILY: u16 = 20;
#[allow(dead_code)]
const SOCK_DESTROY: u16 = 21;

// netlink(7) message header.
#[repr(C)]
struct nlmsghdr {
    nlmsg_len: u32, // Length of message including header.
    nlmsg_type: u16, // Type of message content.
    nlmsg_flags: u16, // Additional flags.
    nlmsg_seq: u32, // Sequence number.
    nlmsg_pid: u32, // Sender port ID.
}

impl Default for nlmsghdr {
    fn default() -> nlmsghdr {
        nlmsghdr {
            nlmsg_len: 0,
            nlmsg_type: 0,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        }
    }
}

impl fmt::Display for nlmsghdr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "{{len: {}, type: {}, flags: 0x{:x}, seq: {}, pid: {}}}",
               self.nlmsg_len,
               self.nlmsg_type,
               self.nlmsg_flags,
               self.nlmsg_seq,
               self.nlmsg_pid)
    }
}

// From <linux/inet_diag.h>. Socket identity.
#[repr(C)]
struct inet_diag_sockid {
    idiag_sport: u16, // __be16
    idiag_dport: u16, // __be16
    idiag_src: [u32; 4], // __be32
    idiag_dst: [u32; 4], // __be32
    idiag_if: u32, // __u32
    idiag_cookie: [u32; 2], // __u32
}

// Zero-initialized default constructor.
impl Default for inet_diag_sockid {
    fn default() -> inet_diag_sockid {
        inet_diag_sockid {
            idiag_sport: 0,
            idiag_dport: 0,
            idiag_src: [0; 4],
            idiag_dst: [0; 4],
            idiag_if: 0,
            idiag_cookie: [0; 2],
        }
    }
}

// From <linux/inet_diag.h>. Request structure.
#[repr(C)]
struct inet_diag_req_v2 {
    sdiag_family: u8,
    sdiag_protocol: u8,
    idiag_ext: u8,
    pad: u8,
    idiag_states: u32,
    id: inet_diag_sockid,
}

impl Default for inet_diag_req_v2 {
    fn default() -> inet_diag_req_v2 {
        inet_diag_req_v2 {
            sdiag_family: 0,
            sdiag_protocol: 0,
            idiag_ext: 0,
            pad: 0,
            idiag_states: 0,
            id: inet_diag_sockid::default(),
        }
    }
}

const NLMSG_ALIGNTO: usize = 4;

fn nlmsg_align(value: usize) -> usize {
    // NLMSG_ALIGN() macro. Note that rust uses ! in place of ~.
    return (value + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1);
}

fn nlmsg_hdrlen() -> usize {
    use std::mem::size_of;
    return nlmsg_align(size_of::<nlmsghdr>());
}

fn nlmsg_length<T>() -> usize {
    use std::mem::size_of;
    return nlmsg_hdrlen() + nlmsg_align(size_of::<T>());
}

// Discard the Result<T> from the given expression.
macro_rules! discard {
    ($expression:expr) => {
        match $expression {
            Ok(_) => (),
            Err(_) => (),
        }
    }
}

fn bytes_of<'a, T: 'a>(value: &'a T) -> &'a [u8] {
    use std::mem;
    use std::slice;
    use std::mem::size_of;
    unsafe { slice::from_raw_parts(mem::transmute(value), size_of::<T>()) }
}

fn mut_bytes_of<'a, T: 'a>(value: &'a mut T) -> &'a mut [u8] {
    use std::mem;
    use std::slice;
    use std::mem::size_of;
    unsafe { slice::from_raw_parts_mut(mem::transmute(value), size_of::<T>()) }
}

use self::nix::sys::uio::IoVec;

fn as_iovec<'a, T: 'a>(value: &'a T) -> IoVec<&[u8]> {
    IoVec::from_slice(bytes_of(value))
}

fn as_mut_iovec<'a, T: 'a>(value: &'a mut T) -> IoVec<&mut [u8]> {
    IoVec::from_mut_slice(mut_bytes_of(value))
}

pub struct Netlink {
    fd: RawFd,
}

impl Netlink {
    // Construct a new netlink socket of the given protocol.
    pub fn new(proto: c_int) -> nix::Result<Self> {
        let sock = socket::socket(socket::AddressFamily::Netlink,
                                  socket::SockType::Datagram,
                                  socket::SOCK_CLOEXEC,
                                  proto);

        match sock {
            Ok(fd) => {
                return Ok(Netlink { fd: fd });
            }
            Err(error) => {
                return Err(error);
            }
        }
    }

    // Bind the netlink socket to our receiver address.
    pub fn bind(&self) -> nix::Result<()> {
        let addr = socket::SockAddr::new_netlink(self::nix::unistd::getpid() as u32, 0);
        return socket::bind(self.fd, &addr);
    }

    pub fn tcp_diag(&self) {
        let dst = socket::SockAddr::new_netlink(0 /* kernel target pid */, 0);

        let mut nlhdr = nlmsghdr::default();
        let mut diags = inet_diag_req_v2::default();

        nlhdr.nlmsg_type = SOCK_DIAG_BY_FAMILY;
        nlhdr.nlmsg_len = nlmsg_length::<inet_diag_req_v2>() as u32;
        nlhdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

        diags.sdiag_family = libc::AF_INET as u8;
        diags.sdiag_protocol = libc::IPPROTO_TCP as u8;
        diags.idiag_states = 0xffffffffu32;

        let iov = [as_iovec(&nlhdr), as_iovec(&diags)];
        socket::sendmsg(self.fd, &iov, &[], socket::MsgFlags::empty(), Some(&dst));

        while true {
            let mut bytes = [0u8; 8192];

            match self.recv(&mut bytes) {
                Err(e) => {
                    println!("recv error {}", e);
                    return ();
                }
                Ok(nlhdr) => {
                    println!("nlmsghdr {}", nlhdr);
                    println!("{} multipart response",
                             if (nlhdr.nlmsg_flags & NLM_F_MULTI) != 0 {
                                 "is"
                             } else {
                                 "is not"
                             });
                    match nlhdr.nlmsg_type {
                        NLMSG_ERROR => {
                            break;
                        }
                        NLMSG_NOOP => {}
                        NLMSG_DONE => {
                            println!("done");
                            break;
                        }
                        NLMSG_OVERRUN => {}
                        _ => {}
                    }

                }
            }

        }
    }

    fn recv(&self, bytes: &mut [u8]) -> nix::Result<nlmsghdr> {
        let mut nlhdr = nlmsghdr::default();

        {
            // We need an inner scops so that the liftime of iov is
            // over before we return the netlink header.
            let iov = [as_mut_iovec(&mut nlhdr), IoVec::from_mut_slice(bytes)];
            match socket::recvmsg::<()>(self.fd, &iov, None, socket::MsgFlags::empty()) {
                Result::Err(e) => {
                    return Err(e);
                }
                Result::Ok(msg) => {
                    println!("recv -> {} bytes", msg.bytes);
                }
            }
        }

        Ok(nlhdr)
    }
}

impl Drop for Netlink {
    // Netlink destructor. Just close the socket and squelch
    // and possible errors since the caller can't handle them.
    fn drop(&mut self) {
        discard!(nix::unistd::close(self.fd));
    }
}
