use inmor::*;
#[tokio::main]
async fn main() {
    let _ = add_subordinate("https://satosa-test-1.sunet.se").await;
}
