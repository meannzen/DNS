#![allow(dead_code)]
#![allow(clippy::missing_const_for_fn)]

#[derive(Debug)]
pub enum BufferError {
    EndOfBuffer,
}

pub type Result<T> = std::result::Result<T, BufferError>;

pub struct DnsPacketBuffer<'input> {
    buf: &'input [u8],
    pos: usize,
}

impl<'input> DnsPacketBuffer<'input> {
    pub fn new(input: &'input [u8]) -> Self {
        DnsPacketBuffer { buf: input, pos: 0 }
    }

    fn get_u8(&mut self) -> Result<u8> {
        if self.pos >= self.buf.len() {
            Err(BufferError::EndOfBuffer)
        } else {
            let value = self.buf[self.pos];
            self.pos += 1;
            Ok(value)
        }
    }

    pub fn get_u16(&mut self) -> Result<u16> {
        let high = self.get_u8()? as u16;
        let low = self.get_u8()? as u16;
        Ok(high << 8 | low)
    }

    #[allow(dead_code)]
    fn skip(&mut self, n: usize) -> Result<()> {
        if self.pos + n > self.buf.len() {
            Err(BufferError::EndOfBuffer)
        } else {
            self.pos += n;
            Ok(())
        }
    }

    #[allow(dead_code)]
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct DnsHeader {
    packet_id: u16,

    query_response_indicator: bool, // QR
    opcode: u8,                     // 4 bits
    authoritative_answer: bool,     // AA
    truncation: bool,               // TC
    recursion_desired: bool,        // RD

    recursion_available: bool, // RA
    reserved: u8,              // Z (must be 0)
    response_code: u8,         // RCODE (4 bits)

    question_count: u16,          // QDCOUNT
    answer_record_count: u16,     // ANCOUNT
    authority_record_count: u16,  // NSCOUNT
    additional_record_count: u16, // ARCOUNT
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QType {
    A = 1,
    CNAME = 5,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QClass {
    IN = 1,
    CS = 2,
}

pub struct Question {
    qname: String,
    qtype: QType,
    qclass: QClass,
}

impl Question {
    pub fn new(name: &str) -> Question {
        Question {
            qname: name.to_string(),
            qtype: QType::A,
            qclass: QClass::IN,
        }
    }

    pub fn with_type_class(name: &str, qtype: QType, qclass: QClass) -> Question {
        Question {
            qname: name.to_string(),
            qtype,
            qclass,
        }
    }

    pub fn encode_qname(&self, buf: &mut [u8]) -> Result<usize> {
        encode_domain_name(&self.qname, buf)
    }
}

/// RDATA types. `Unknown` holds raw bytes for unsupported/unparsed types.
pub enum RData {
    A([u8; 4]),
    CNAME(String),
    Unknown(Vec<u8>),
}

pub struct Answer {
    qname: String,
    qtype: QType,
    qclass: QClass,
    ttl: u32,
    rdata: RData,
}

impl Answer {
    pub fn new(name: &str, addr: [u8; 4], ttl: u32) -> Answer {
        Answer {
            qname: name.to_string(),
            qtype: QType::A,
            qclass: QClass::IN,
            ttl,
            rdata: RData::A(addr),
        }
    }

    /// Encode the answer into `buf` starting at offset 0 and return number of bytes written.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        let mut off = 0usize;

        // encode NAME
        let written = encode_domain_name(&self.qname, &mut buf[off..])?;
        off += written;

        // helper to write numbers
        fn write_u16(buf: &mut [u8], off: usize, val: u16) -> Result<()> {
            if off + 2 > buf.len() {
                return Err(BufferError::EndOfBuffer);
            }
            let bytes = val.to_be_bytes();
            buf[off] = bytes[0];
            buf[off + 1] = bytes[1];
            Ok(())
        }
        fn write_u32(buf: &mut [u8], off: usize, val: u32) -> Result<()> {
            if off + 4 > buf.len() {
                return Err(BufferError::EndOfBuffer);
            }
            let bytes = val.to_be_bytes();
            buf[off..off + 4].copy_from_slice(&bytes);
            Ok(())
        }

        // TYPE
        let t = match self.qtype {
            QType::A => 1u16,
            QType::CNAME => 5u16,
        };
        write_u16(buf, off, t)?;
        off += 2;

        // CLASS
        let c = match self.qclass {
            QClass::IN => 1u16,
            QClass::CS => 2u16,
        };
        write_u16(buf, off, c)?;
        off += 2;

        // TTL
        write_u32(buf, off, self.ttl)?;
        off += 4;

        // Reserve space for RDLENGTH (u16), we'll write actual RDATA after computing it
        let rdlength_pos = off;
        off += 2; // placeholder for RDLENGTH

        // Write RDATA based on variant
        let rdata_start = off;
        match &self.rdata {
            RData::A(a) => {
                if off + 4 > buf.len() {
                    return Err(BufferError::EndOfBuffer);
                }
                buf[off..off + 4].copy_from_slice(a);
                off += 4;
            }
            RData::CNAME(name) => {
                // encode domain name for the CNAME target
                let written = encode_domain_name(name, &mut buf[off..])?;
                off += written;
            }
            RData::Unknown(bytes) => {
                if off + bytes.len() > buf.len() {
                    return Err(BufferError::EndOfBuffer);
                }
                buf[off..off + bytes.len()].copy_from_slice(bytes);
                off += bytes.len();
            }
        }

        // compute and write RDLENGTH
        let rdlen = (off - rdata_start) as u16;
        if rdlength_pos + 2 > buf.len() {
            return Err(BufferError::EndOfBuffer);
        }
        let rdbytes = rdlen.to_be_bytes();
        buf[rdlength_pos] = rdbytes[0];
        buf[rdlength_pos + 1] = rdbytes[1];

        Ok(off)
    }
}

struct Message {
    header: DnsHeader,
    questions: Vec<Question>,
    answers: Vec<Answer>,
}

pub struct MessageWriter {
    message: Message,
}

impl MessageWriter {
    pub fn new(header: DnsHeader, question: Question, answer: Answer) -> MessageWriter {
        MessageWriter {
            message: Message {
                header,
                questions: vec![question],
                answers: vec![answer],
            },
        }
    }

    pub fn new_with_sections(
        header: DnsHeader,
        questions: Vec<Question>,
        answers: Vec<Answer>,
    ) -> MessageWriter {
        MessageWriter {
            message: Message {
                header,
                questions,
                answers,
            },
        }
    }

    pub fn write(&self, buf: &mut [u8]) -> Result<usize> {
        fn write_u16(buf: &mut [u8], off: usize, val: u16) -> Result<()> {
            if off + 2 > buf.len() {
                return Err(BufferError::EndOfBuffer);
            }
            let bytes = val.to_be_bytes();
            buf[off] = bytes[0];
            buf[off + 1] = bytes[1];
            Ok(())
        }
        fn write_u32(buf: &mut [u8], off: usize, val: u32) -> Result<()> {
            if off + 4 > buf.len() {
                return Err(BufferError::EndOfBuffer);
            }
            let bytes = val.to_be_bytes();
            buf[off..off + 4].copy_from_slice(&bytes);
            Ok(())
        }

        let mut offset = 0usize;

        if buf.len() < 12 {
            return Err(BufferError::EndOfBuffer);
        }

        write_u16(buf, offset, self.message.header.packet_id)?;
        offset += 2;

        let mut flags: u16 = 0;
        if self.message.header.query_response_indicator {
            flags |= 1 << 15;
        }
        flags |= ((self.message.header.opcode as u16) & 0xF) << 11;
        if self.message.header.authoritative_answer {
            flags |= 1 << 10;
        }
        if self.message.header.truncation {
            flags |= 1 << 9;
        }
        if self.message.header.recursion_desired {
            flags |= 1 << 8;
        }
        if self.message.header.recursion_available {
            flags |= 1 << 7;
        }
        flags |= ((self.message.header.reserved as u16) & 0x7) << 4;
        flags |= (self.message.header.response_code as u16) & 0xF;

        write_u16(buf, offset, flags)?;
        offset += 2;

        let qdcount = if self.message.header.question_count != 0 {
            self.message.header.question_count
        } else {
            self.message.questions.len() as u16
        };
        write_u16(buf, offset, qdcount)?;
        offset += 2;

        let ancount = if self.message.header.answer_record_count != 0 {
            self.message.header.answer_record_count
        } else {
            self.message.answers.len() as u16
        };
        write_u16(buf, offset, ancount)?;
        offset += 2;

        let nscount = if self.message.header.authority_record_count != 0 {
            self.message.header.authority_record_count
        } else {
            0u16
        };
        write_u16(buf, offset, nscount)?;
        offset += 2;

        let arcount = if self.message.header.additional_record_count != 0 {
            self.message.header.additional_record_count
        } else {
            0u16
        };
        write_u16(buf, offset, arcount)?;
        offset += 2;

        for q in &self.message.questions {
            let written_qname = q.encode_qname(&mut buf[offset..])?;
            offset += written_qname;

            let qtype_u16 = match q.qtype {
                QType::A => 1u16,
                QType::CNAME => 5u16,
            };
            write_u16(buf, offset, qtype_u16)?;
            offset += 2;

            let qclass_u16 = match q.qclass {
                QClass::IN => 1u16,
                QClass::CS => 2u16,
            };
            write_u16(buf, offset, qclass_u16)?;
            offset += 2;
        }

        for a in &self.message.answers {
            let answer_written = a.encode(&mut buf[offset..])?;
            offset += answer_written;
        }

        Ok(offset)
    }

    pub fn to_vec(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 512];
        let len = self.write(&mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }
}

impl DnsHeader {
    pub fn parse(parser: &mut DnsPacketBuffer) -> Result<DnsHeader> {
        let packet_id = parser.get_u16()?;

        let flags = parser.get_u16()?;
        let query_response_indicator = (flags >> 15) & 1 == 1;
        let opcode = ((flags >> 11) & 0xF) as u8;
        let authoritative_answer = (flags >> 10) & 1 == 1;
        let truncation = (flags >> 9) & 1 == 1;
        let recursion_desired = (flags >> 8) & 1 == 1;
        let recursion_available = (flags >> 7) & 1 == 1;
        let reserved = ((flags >> 4) & 0x7) as u8; // bits 4–6 (should be 0)
        let response_code = (flags & 0xF) as u8;

        let question_count = parser.get_u16()?;
        let answer_record_count = parser.get_u16()?;
        let authority_record_count = parser.get_u16()?;
        let additional_record_count = parser.get_u16()?;

        Ok(DnsHeader {
            packet_id,
            query_response_indicator,
            opcode,
            authoritative_answer,
            truncation,
            recursion_desired,
            recursion_available,
            reserved,
            response_code,
            question_count,
            answer_record_count,
            authority_record_count,
            additional_record_count,
        })
    }

    pub fn response_with_id(id: u16) -> DnsHeader {
        DnsHeader::response_with_id_and_counts(id, 0, false, 1, 0, 0, 0)
    }

    pub fn response_with_id_and_rd(id: u16, recursion_desired: bool) -> DnsHeader {
        DnsHeader::response_with_id_and_counts(id, 0, recursion_desired, 1, 0, 0, 0)
    }

    pub fn response_with_id_and_counts(
        id: u16,
        opcode: u8,
        recursion_desired: bool,
        qdcount: u16,
        ancount: u16,
        nscount: u16,
        arcount: u16,
    ) -> DnsHeader {
        let response_code = if opcode == 0 { 0 } else { 4 };
        DnsHeader {
            packet_id: id,
            query_response_indicator: true,
            opcode,
            authoritative_answer: false,
            truncation: false,
            recursion_desired,
            recursion_available: false,
            reserved: 0,
            response_code,
            question_count: qdcount,
            answer_record_count: ancount,
            authority_record_count: nscount,
            additional_record_count: arcount,
        }
    }

    pub fn response_with_id_full(id: u16, opcode: u8, recursion_desired: bool) -> DnsHeader {
        DnsHeader::response_with_id_and_counts(id, opcode, recursion_desired, 1, 0, 0, 0)
    }
}

/// Helper: encode a domain name (dot-separated) into DNS label format into `buf`.
/// Returns number of bytes written.
fn encode_domain_name(name: &str, buf: &mut [u8]) -> Result<usize> {
    let mut offset = 0usize;

    for label in name.split('.') {
        let len = label.len();
        if len == 0 {
            continue;
        }
        if offset + 1 + len > buf.len() {
            return Err(BufferError::EndOfBuffer);
        }
        buf[offset] = len as u8;
        offset += 1;
        buf[offset..offset + len].copy_from_slice(label.as_bytes());
        offset += len;
    }

    if offset >= buf.len() {
        return Err(BufferError::EndOfBuffer);
    }
    buf[offset] = 0;
    offset += 1;

    Ok(offset)
}
