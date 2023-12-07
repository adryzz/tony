mod hot;

#[tokio::main]
async fn main() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:1069").await.unwrap();

    loop {
        let mut buffer = [0u8; 1024]; // Buffer to store received data

        // Receive data from the UDP socket
        let (size, _addr) = socket.recv_from(&mut buffer).await.expect("Failed to receive data");

        // Convert the received bytes to a string
        let received_string = String::from_utf8_lossy(&buffer[..size]);
        
        // Process the received string as needed
        let msg = hot::LogMessage::try_parse(&received_string);

        dbg!(msg);
    }
}
