// Copyright (C) 2016 James Peach. All rights reserved.

extern crate ss;

fn main() {
    let nl = ss::netlink::Netlink::new(ss::netlink::NETLINK_SOCK_DIAG).unwrap();
}
