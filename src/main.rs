use std::env;

const TARGET: &str = "https://agentrouter.org";
const DEFAULT_PORT: u16 = 7187;

fn port_from_args(mut args: impl Iterator<Item = String>) -> Result<u16, std::num::ParseIntError> {
    args.next().map_or(Ok(DEFAULT_PORT), |value| value.parse())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = port_from_args(env::args().skip(1))?;
    let listen_addr = format!("127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(5)
        .pool_idle_timeout(std::time::Duration::from_secs(20))
        .tcp_keepalive(std::time::Duration::from_secs(15))
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()?;
    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;

    println!("RAPE listening on http://{listen_addr} -> {TARGET}");
    axum::serve(listener, rape::app(client, TARGET.to_owned())).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn positional_port_defaults_when_missing() {
        assert_eq!(super::port_from_args(std::iter::empty()).unwrap(), 7187);
    }

    #[test]
    fn positional_port_is_used_when_present() {
        assert_eq!(
            super::port_from_args(["8080".to_owned()].into_iter()).unwrap(),
            8080
        );
    }
}
