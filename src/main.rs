#[allow(unused_imports)]
use std::net::UdpSocket;

use codecrafters_dns_server::DnsPacketBuffer;

fn main() {
    println!("Logs from your program will appear here!");
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let mut parser = DnsPacketBuffer::new(&buf);

                let id = parser
                    .get_u16()
                    .expect("Packet too short for Transaction ID");
                let flags = parser.get_u16().expect("Packet too short for Flags");

                let qr = (flags >> 15) & 1;
                let opcode = (flags >> 11) & 0xF;
                let aa = (flags >> 10) & 1;

                println!("Transaction ID: {id}");
                println!("QR (Query=0/Response=1): {qr}");
                println!("Opcode: {opcode}");
                println!("AA (Authoritative): {aa}");
                println!("Received {} bytes from {}", size, source);
                let id: [u8; 2] = 1234u16.to_be_bytes();
                let response = [id[0], id[1], 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
