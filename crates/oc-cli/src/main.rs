//! `oc` — OpenChat command-line client (thin binary over `oc_cli`).

fn main() {
    if let Err(error) = oc_cli::run_cli_from(std::env::args_os().collect()) {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}
