use clap::Parser;
use log::error;
use sysinfo::{ProcessExt, System, SystemExt};
use yai::{inject_into, InjectorError};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(
    name = "yai",
    version = "0.1.3",
    about = "Yet Another Injector for windows x64 dlls."
)]
struct Args {
    /// Process name to inject into
    #[clap(short, long, value_parser)]
    target: String,

    /// Relative path to payload dll
    #[clap(short, long, value_parser)]
    payload: String,
}

fn main() -> Result<(), InjectorError> {
    std::env::set_var("RUST_LOG", "trace");
    pretty_env_logger::init();

    let args = Args::parse();
    let process_name = &args.target;
    let payload_location = &args.payload;

    let mut current_dir = std::env::current_dir()?;
    current_dir.push(payload_location);
    let payload_location = current_dir.as_path();

    match payload_location.exists() {
        true => {}
        false => {
            error!("Payload does not exist");
            return Err(InjectorError::PayloadMissing(args.payload));
        }
    }

    let mut sys = System::new_all();
    sys.refresh_processes();
    let process = sys.processes_by_name(process_name).next();

    let process = match process {
        Some(process) => process,
        None => {
            error!("Process does not exist/is not actively running");
            return Err(InjectorError::ProcessNotActive(args.target));
        }
    };

    inject_into(payload_location, process.pid())
}
