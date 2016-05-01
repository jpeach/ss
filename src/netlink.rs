// Copyright (C) 2016 James Peach. All rights reserved.
//
// netlink.rs: Netlink socket helpers

extern crate nix;
extern crate libc;

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
}

impl Drop for Netlink {
    // Netlink destructor. Just close the socket and squelch
    // and possible errors since the caller can't handle them.
    fn drop(&mut self) {
        match nix::unistd::close(self.fd) {
            Ok(_) => (),
            Err(_) => (),
        }
    }
}
