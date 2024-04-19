#[derive(Debug, Clone, PartialEq)]
pub struct DomainName(String);

impl DomainName {
    pub fn new() -> Self {
        Self(String::new())
    }

    pub fn read_bytes(&mut self, buf: &mut impl bytes::Buf, lookup_table: &mut LookupTable) {
        loop {
            // length of label
            let len = buf.get_u8();

            if len == 0 {
                // end of domain name -> store into lookup table
                lookup_table.insert(self);
                break;
            }

            // Label with pointer -> get from lookup table
            if (len & 0xC0) == 0xC0 {
                // two MSB 0xC000 (in binary 11000000) marks pointer
                let next_byte = buf.get_u8() as u16;
                let pos = (((len as u16) ^ 0xC0) << 8) | next_byte;

                let label = lookup_table
                    .decompress(pos)
                    .expect("label should be stored in lookup table in previous steps");

                self.0.push_str(label);

                break;
            }

            for _i in 0..len {
                // read one label
                let c = buf.get_u8() as char;
                self.0.push(c);
            }
            self.0.push('.');
        }
    }

    pub fn from_bytes(buf: &mut impl bytes::Buf, lookup_table: &mut LookupTable) -> Self {
        let mut domain_name = Self::new();
        domain_name.read_bytes(buf, lookup_table);
        domain_name
    }

    pub fn write_bytes(&self, buf: &mut impl bytes::BufMut, lookup_table: &mut LookupTable) {
        if let Some(&pos) = lookup_table.compress(self) {
            // two MSB 0xC000 (in binary 11000000 00000000) marks pointer
            let pos = pos | 0xC000;
            buf.put_u16(pos);
            return;
        }

        for label in self.0.split('.') {
            let len = label.len() as u8;
            buf.put_u8(len);
            buf.put(label.as_bytes());
        }

        lookup_table.insert(self);
    }
}

impl From<String> for DomainName {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for DomainName {
    fn from(s: &str) -> Self {
        Self(String::from(s))
    }
}

use std::collections::HashMap;

/// For message compression and decompression
/// https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4
pub struct LookupTable {
    decompression: Decompression,
    compression: Compression,
}

impl LookupTable {
    pub fn new(pos: u16) -> Self {
        Self {
            decompression: Decompression::new(pos),
            compression: Compression::new(),
        }
    }

    pub fn insert(&mut self, domain_name: &DomainName) {
        let mut labels: Vec<(u16, String)> = Vec::new();
        let mut pos = self.decompression.pos;

        for label in domain_name.0.split('.') {
            let mut label = label.to_string();
            if label.is_empty() {
                break;
            }
            label.push('.');
            let len = label.len() as u16;
            labels.push((pos, label));
            pos += len;
        }

        labels.reverse();

        while let Some((pos, mut label)) = labels.pop() {
            for (_, next_label) in labels.iter().rev() {
                label.push_str(next_label);
            }
            self.decompression.map.insert(pos, label.to_string());
            self.compression.map.insert(label.to_string(), pos);
            self.decompression.pos = pos;
        }
    }

    pub fn decompress(&self, pos: u16) -> Option<&String> {
        self.decompression.map.get(&pos)
    }

    pub fn compress(&self, domain_name: &DomainName) -> Option<&u16> {
        self.compression.map.get(&domain_name.0)
    }
}

struct Decompression {
    pos: u16, // position
    map: HashMap<u16, String>,
}

impl Decompression {
    fn new(pos: u16) -> Self {
        Self {
            pos,
            map: HashMap::new(),
        }
    }
}

struct Compression {
    map: HashMap<String, u16>,
}

impl Compression {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}
