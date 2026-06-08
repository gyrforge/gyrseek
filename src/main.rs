use std::env;
#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    gyrseek::run(args).await;
}
