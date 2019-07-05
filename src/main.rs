// Main Entry Point :: A fuse_mt test program.
//
// Copyright (c) 2016-2017 by William R. Fraser
//

use std::env;
use std::ffi::{OsStr, OsString};

extern crate libc;
extern crate parity_daemonize;
extern crate time;

use io::Write;
use parity_daemonize::daemonize;
use std::{io, process};
use parity_daemonize::AsHandle;

#[macro_use]
extern crate log;

extern crate fuse_mt;

mod libc_extras;
mod libc_wrappers;
mod passthrough;

struct ConsoleLogger;

impl log::Log for ConsoleLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        println!("{}: {}: {}", record.target(), record.level(), record.args());
    }

    fn flush(&self) {}
}

static LOGGER: ConsoleLogger = ConsoleLogger;

fn main() {
    match daemonize("pid_file.txt") {
        // we are now in the daemon, use this handle to detach from the parent process
        Ok(mut handle) => {
            log::set_logger(&LOGGER).unwrap();
            log::set_max_level(log::LevelFilter::Debug);

            let args: Vec<OsString> = env::args_os().collect();

            if args.len() != 3 {
                println!(
                    "usage: {} <target> <mountpoint>",
                    &env::args().next().unwrap()
                );
                ::std::process::exit(-1);
            }

            let filesystem = passthrough::PassthroughFS::new(args[1].clone());

            let fuse_args: Vec<&OsStr> = vec![&OsStr::new("-o"), &OsStr::new("auto_unmount")];

            unsafe{
                let res = fuse_mt::spawn_mount(fuse_mt::FuseMT::new(filesystem, 1), &args[2], &fuse_args);

                //fuse_mt::mount(fuse_mt::FuseMT::new(filesystem, 1), &args[2], &fuse_args).unwrap();

                handle.detach_with_msg("run in background daemon\n");
                std::thread::sleep(std::time::Duration::new(std::u64::MAX,0));

                res.unwrap();
            }
        }
        // the daemon or the parent process may receive this error,
        // just print it and exit
        Err(e) => {
            // if this is the daemon, this is piped to the parent's stderr
            eprintln!("{}", e);
            // don't forget to flush
            let _s = io::stderr().flush();
            process::exit(1);
        }
    }
}
