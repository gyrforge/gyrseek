use std::env;
#[tokio::main]
async fn main() {
    // nosemgrep: rust.lang.security.args.args "Rule is to not use the first element of args, which we don't"
    let args: Vec<String> = env::args().skip(1).collect();
    gyrseek::run(args).await;
}
