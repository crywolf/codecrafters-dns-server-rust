#[derive(Debug, Clone, PartialEq)]
pub struct DomainName(String);

impl DomainName {
    pub fn new() -> Self {
        Self(String::new())
    }

    pub fn read_bytes(&mut self, buf: &mut impl bytes::Buf) {
        loop {
            // length of label
            let len = buf.get_u8();

            if len == 0 {
                // end of domain name
                break;
            }

            for _i in 0..len {
                // read one label
                self.0.push(buf.get_u8() as char);
            }
            self.0.push('.');
        }
    }

    pub fn from_bytes(buf: &mut impl bytes::Buf) -> Self {
        let mut domain_name = Self::new();
        domain_name.read_bytes(buf);
        domain_name
    }

    pub fn write_bytes(&self, buf: &mut impl bytes::BufMut) {
        for label in self.0.split('.') {
            let len = label.len() as u8;
            buf.put_u8(len);
            buf.put(label.as_bytes());
        }
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
