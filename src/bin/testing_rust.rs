use inmor::*;
use tokio;
#[tokio::main]
async fn main() {
    add_subordinate("https://satosa-test-1.sunet.se").await;
}
