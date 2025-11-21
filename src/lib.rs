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
