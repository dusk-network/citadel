use colored::Colorize;
use std::env;
use std::process::exit;

use citadel::service::Service;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 {
        if args[1].eq("server") {
            Service::run_service_provider(args[2].clone());
        } else if args[1].eq("client") {
            Service::run_user(args[2].clone(), args[3].clone());
        } else if args[1].eq("setup") {
            Service::generate_setup_to_file();
        } else if args[1].eq("clean") {
            Service::clean();
        }

        exit(0);
    }

    println!(
        "\n{}\n",
        format!("-------------- Citadel --------------")
            .bold()
            .red()
    );

    println!("USAGE: cargo run --release [arg]\n");
    println!("Where [arg] can be:");
    println!("server [port]: Run the Citadel Server on a given port.");
    println!("client [ip] [port]: Run the Citadel Client to authenticate on a server given its IP and port.");
    println!("setup : Generate the SRS.");
    println!("clean : Delete all the generated files.\n");
}
