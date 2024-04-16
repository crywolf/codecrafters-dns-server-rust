/// https://www.rfc-editor.org/rfc/rfc1035#section-4.1.2
/// 1  1  1  1  1  1
/// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                               |
/// /                     QNAME                     /
/// /                                               /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     QTYPE                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     QCLASS                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// where:
///
/// QNAME     a domain name represented as a sequence of labels, where
///           each label consists of a length octet followed by that
///           number of octets.  The domain name terminates with the
///           zero length octet for the null label of the root.  Note
///           that this field may be an odd number of octets; no
///           padding is used.
///
/// QTYPE     a two octet code which specifies the type of the query.
///           The values for this field include all codes valid for a
///           TYPE field, together with some more general codes which
///           can match more than one type of RR.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsQuestion {
    pub domain_name: String,
    pub query_type: QueryType,
    pub class: QueryClass,
}

impl DnsQuestion {
    pub fn new(domain_name: String, query_type: QueryType, class: QueryClass) -> Self {
        Self {
            domain_name,
            query_type,
            class,
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[repr(u16)]
#[derive(Debug, Clone, PartialEq)]
pub enum QueryType {
    A = 1, // 1 a host address
    UNKNOWN(u16),
}

impl From<u16> for QueryType {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::A,
            n => Self::UNKNOWN(n),
        }
    }
}

impl From<QueryType> for u16 {
    fn from(value: QueryType) -> u16 {
        match value {
            QueryType::A => 1,
            QueryType::UNKNOWN(n) => n,
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[repr(u16)]
#[derive(Debug, Clone, PartialEq)]
pub enum QueryClass {
    IN = 1, // 1 the Internet
    CS = 2, // 2 the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH = 3, // 3 the CHAOS class
    HS = 4, // 4 Hesiod [Dyer 87]
    UNKNOWN(u16),
}

impl From<QueryClass> for u16 {
    fn from(value: QueryClass) -> Self {
        match value {
            QueryClass::IN => 1,
            QueryClass::CS => 2,
            QueryClass::CH => 3,
            QueryClass::HS => 4,
            QueryClass::UNKNOWN(n) => n,
        }
    }
}

impl From<u16> for QueryClass {
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
