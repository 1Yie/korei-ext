fn main() {
    if agent_code_mode::worker_main().is_err() {
        std::process::exit(1);
    }
}
