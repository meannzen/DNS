use std::net::UdpSocket;
use std::time::Duration;

use codecrafters_dns_server::{Answer, DnsHeader, MessageWriter, QClass, QType, Question};

fn read_u16_be(buf: &[u8], pos: usize) -> Option<u16> {
    if pos + 2 > buf.len() {
        None
    } else {
        Some(u16::from_be_bytes([buf[pos], buf[pos + 1]]))
    }
}

fn parse_name(packet: &[u8], start_pos: usize) -> Result<(String, usize), String> {
    if start_pos >= packet.len() {
        return Err("start_pos out of range".into());
    }

    let mut labels = Vec::new();
    let mut pos = start_pos;
    let mut jumped = false;
    let mut jump_pos = 0usize;
    let mut steps = 0usize;

    loop {
        if steps > 128 {
            return Err("too many label steps (possible loop)".into());
        }
        steps += 1;

        if pos >= packet.len() {
            return Err("out of range while parsing name".into());
        }

        let len = packet[pos];
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= packet.len() {
                return Err("pointer truncated".into());
            }
            let b2 = packet[pos + 1];
            let pointer = (((len as u16 & 0x3F) as u16) << 8) | (b2 as u16);
            let pointer = pointer as usize;
            if pointer >= packet.len() {
                return Err("pointer out of range".into());
            }
            if !jumped {
                jump_pos = pos + 2;
            }
            pos = pointer;
            jumped = true;
            continue;
        } else if len == 0 {
            pos += 1;
            break;
        } else {
            let len_usize = len as usize;
            if pos + 1 + len_usize > packet.len() {
                return Err("label extends past packet".into());
            }
            let label = &packet[pos + 1..pos + 1 + len_usize];
            match std::str::from_utf8(label) {
                Ok(s) => labels.push(s.to_string()),
                Err(_) => return Err("invalid UTF-8 in label".into()),
            }
            pos += 1 + len_usize;
        }
    }

    let name = labels.join(".");
    let next_pos = if jumped { jump_pos } else { pos };
    Ok((name, next_pos))
}

fn qtype_from_u16(v: u16) -> Option<QType> {
    match v {
        1 => Some(QType::A),
        5 => Some(QType::CNAME),
        _ => None,
    }
}

fn qclass_from_u16(v: u16) -> Option<QClass> {
    match v {
        1 => Some(QClass::IN),
        2 => Some(QClass::CS),
        _ => None,
    }
}

fn main() {
    let socket = match UdpSocket::bind("127.0.0.1:2053") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to bind UDP socket: {}", e);
            return;
        }
    };

    let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));

    println!("Listening on 127.0.0.1:2053 for DNS queries");

    let mut buf = [0u8; 512];

    loop {
        match socket.recv_from(&mut buf) {
            Ok((size, src)) => {
                let packet = &buf[..size];
                if packet.len() < 12 {
                    eprintln!(
                        "Received packet too small from {}: {} bytes",
                        src,
                        packet.len()
                    );
                    continue;
                }

                let id = u16::from_be_bytes([packet[0], packet[1]]);

                let qdcount = match read_u16_be(packet, 4) {
                    Some(v) => v,
                    None => {
                        eprintln!("Malformed packet from {}: cannot read QDCOUNT", src);
                        continue;
                    }
                };
                if qdcount == 0 {
                    eprintln!("No questions in packet from {}", src);
                    continue;
                }

                let qstart = 12usize;
                let (qname, after_name) = match parse_name(packet, qstart) {
                    Ok((n, p)) => (n, p),
                    Err(e) => {
                        eprintln!("Failed to parse QNAME from {}: {}", src, e);
                        continue;
                    }
                };

                if after_name + 4 > packet.len() {
                    eprintln!(
                        "Packet from {} truncated after qname (need 4 more bytes, have {})",
                        src,
                        packet.len() - after_name
                    );
                    continue;
                }

                let qtype_u16 = u16::from_be_bytes([packet[after_name], packet[after_name + 1]]);
                let qclass_u16 =
                    u16::from_be_bytes([packet[after_name + 2], packet[after_name + 3]]);

                let qtype = qtype_from_u16(qtype_u16).unwrap_or(QType::A);
                let qclass = qclass_from_u16(qclass_u16).unwrap_or(QClass::IN);

                println!(
                    "Query from {}: id={}, name='{}', qtype={}, qclass={}",
                    src, id, qname, qtype_u16, qclass_u16
                );

                let header = DnsHeader::response_with_id(id);
                let question = Question::with_type_class(&qname, qtype, qclass);

                let answer = Answer::new(&qname, [8, 8, 8, 8], 60);

                let writer = MessageWriter::new(header, question, answer);

                match writer.to_vec() {
                    Ok(resp) => match socket.send_to(&resp, src) {
                        Ok(n) => {
                            println!("Sent {} bytes response to {}", n, src);
                        }
                        Err(e) => {
                            eprintln!("Failed to send response to {}: {}", src, e);
                        }
                    },
                    Err(e) => {
                        eprintln!("Failed to serialize DNS response for {}: {:?}", src, e);
                    }
                }
            }
            Err(e) => {
                eprintln!("recv_from error: {}", e);
            }
        }
    }
}
