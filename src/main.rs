//! Voidgate binary entry point.
//!
//! All logic lives in the `voidgate` library crate so it can be exercised by
//! integration tests; this shim only maps the CLI result onto a process exit
//! code (0 = ok, 1 = config error, 2 = runtime error).

use std::process::ExitCode;

fn main() -> ExitCode {
    voidgate::cli::run()
}
