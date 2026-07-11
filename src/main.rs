#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    antitheft_cli::run_cli().await
}
