use std::net::Ipv4Addr;

use crate::domain_name::{DomainName, LookupTable};

/// Resource record format
///
/// The answer, authority, and additional sections all share the same
/// format: a variable number of resource records, where the number of
/// records is specified in the corresponding count field in the header.
/// Each resource record has the following format:
///
/// https://www.rfc-editor.org/rfc/rfc1035#section-4.1.3
///
/// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                               |
/// /                                               /
/// /                      NAME                     /
/// |                                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      TYPE                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     CLASS                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      TTL                      |
/// |                                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                   RDLENGTH                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
/// /                     RDATA                     /
/// /                                               /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///
/// where:
///
/// NAME            a domain name to which this resource record pertains.
///
/// TYPE            two octets containing one of the RR TYPE codes.
///
/// CLASS           two octets which specify the class of the data in the RDATA field.
///
/// TTL             a 32 bit unsigned integer that specifies the time
///                 interval (in seconds) that the resource record may be
///                 cached before it should be discarded.  Zero values are
///                 interpreted to mean that the RR can only be used for the
///                 transaction in progress, and should not be cached.
///
/// RDLENGTH        an unsigned 16 bit integer that specifies the length in
///                 octets of the RDATA field.
///
/// RDATA           a variable length string of octets that describes the
///                 resource.  The format of this information varies
///                 according to the TYPE and CLASS of the resource record.
///                 For example, the if the TYPE is A and the CLASS is IN,
///                 the RDATA field is a 4 octet ARPA Internet address.
///
#[derive(Debug, Clone, PartialEq)]
pub struct DnsRecord {
    pub domain_name: DomainName,
    pub record_type: RecordType,
    pub class: RecordClass,
    pub ttl: u32,
    pub length: u16,
    pub data: Ipv4Addr,
}

impl DnsRecord {
    pub fn new(
        domain_name: DomainName,
        record_type: RecordType,
        class: RecordClass,
        ttl: u32,
        data: Ipv4Addr,
    ) -> Self {
        Self {
            domain_name,
            record_type,
            class,
            ttl,
            length: 4,
            data,
        }
    }

    pub fn from_bytes(buf: &mut impl bytes::Buf, lookup_table: &mut LookupTable) -> Self {
        let domain_name = DomainName::from_bytes(buf, lookup_table);
        let query_type = RecordType::from(buf.get_u16());
        let class = RecordClass::from(buf.get_u16());
        let ttl = buf.get_u32();
        let _length = buf.get_u16();
        let data = Ipv4Addr::new(buf.get_u8(), buf.get_u8(), buf.get_u8(), buf.get_u8());

        Self::new(domain_name, query_type, class, ttl, data)
    }

    pub fn write_bytes(&self, buf: &mut impl bytes::BufMut, lookup_table: &mut LookupTable) {
        self.domain_name.write_bytes(buf, lookup_table);
        buf.put_u16(RecordType::A.into());
        buf.put_u16(RecordClass::IN.into());
        buf.put_u32(self.ttl);
        buf.put_u16(self.length);
        buf.put(&self.data.octets()[..]);
    }
}

#[allow(clippy::upper_case_acronyms)]
#[repr(u16)]
#[derive(Debug, Clone, PartialEq)]
pub enum RecordType {
    A = 1, // 1 a host address
    UNKNOWN(u16),
}

impl From<u16> for RecordType {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::A,
            n => Self::UNKNOWN(n),
        }
    }
}

impl From<RecordType> for u16 {
    fn from(value: RecordType) -> u16 {
        match value {
            RecordType::A => 1,
            RecordType::UNKNOWN(n) => n,
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[repr(u16)]
#[derive(Debug, Clone, PartialEq)]
pub enum RecordClass {
    IN = 1, // 1 the Internet
    CS = 2, // 2 the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH = 3, // 3 the CHAOS class
    HS = 4, // 4 Hesiod [Dyer 87]
    UNKNOWN(u16),
}

impl From<RecordClass> for u16 {
    fn from(value: RecordClass) -> Self {
        match value {
            RecordClass::IN => 1,
            RecordClass::CS => 2,
            RecordClass::CH => 3,
            RecordClass::HS => 4,
            RecordClass::UNKNOWN(n) => n,
        }
    }
}

impl From<u16> for RecordClass {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::IN,
            2 => Self::CS,
            3 => Self::CH,
            4 => Self::HS,
            n => Self::UNKNOWN(n),
        }
    }
}
