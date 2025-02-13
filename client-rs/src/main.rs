use clap::{Arg, Command};
use futures_util::{future, pin_mut, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::{
    connect_async, connect_async_tls_with_config, tungstenite::protocol::Message, Connector,
};
use url::Url;

#[tokio::main]
async fn main() {
    let matches = Command::new("ws-client")
        .arg(
            Arg::new("target")
                .long("target")
                .required(true)
                .value_name("URL")
                .help("WebSocket target URL (ws:// or wss://)"),
        )
        .arg(
            Arg::new("insecure")
                .action(clap::ArgAction::SetTrue)
                .default_value("false")
                .long("insecure")
                .help("Ignore certificate validation errors"),
        )
        .get_matches();

    let target = matches.get_one::<String>("target").unwrap();
    let insecure = matches.get_flag("insecure");
    let url = Url::parse(target).unwrap();

    let (stdin_tx, stdin_rx) = futures_channel::mpsc::unbounded();
    tokio::spawn(read_stdin(stdin_tx));

    let (ws_stream, _) = if url.scheme() == "wss" && insecure {
        let mut tls = native_tls::TlsConnector::builder();
        tls.danger_accept_invalid_certs(true);
        let connector = Some(Connector::NativeTls(tls.build().unwrap()));
        connect_async_tls_with_config(target, None, false, connector)
            .await
            .expect("Failed to connect")
    } else {
        connect_async(target).await.expect("Failed to connect")
    };

    let (write, read) = ws_stream.split();

    let stdin_to_ws = stdin_rx.map(Ok).forward(write);
    let ws_to_stdout = {
        read.for_each(|message| async {
            let data = message.unwrap().into_data();
            tokio::io::stdout().write_all(&data).await.unwrap();
        })
    };

    pin_mut!(stdin_to_ws, ws_to_stdout);
    future::select(stdin_to_ws, ws_to_stdout).await;
}

async fn read_stdin(tx: futures_channel::mpsc::UnboundedSender<Message>) {
    let mut stdin = tokio::io::stdin();
    loop {
        let mut buf = vec![0; 1024];
        let n = match stdin.read(&mut buf).await {
            Err(_) | Ok(0) => break,
            Ok(n) => n,
        };
        buf.truncate(n);
        tx.unbounded_send(Message::binary(buf)).unwrap();
    }
}
