#[allow(clippy::upper_case_acronyms, dead_code)]
#[derive(Default, Debug, Clone, PartialEq)]
pub enum ResultCode {
    // No error condition
    #[default]
    NOERROR = 0,

    // Format error - The name server was unable to interpret the query.
    FORMERR = 1,

    // Server failure - The name server was unable to process this query due to a problem with the name server.
    SERVFAIL = 2,

    // Name Error - Meaningful only for responses from an authoritative name server,
    // this code signifies that the domain name referenced in the query does not exist.
    NXDOMAIN = 3,

    // Not Implemented - The name server does not support the requested kind of query.
    NOTIMP = 4,

    // Refused - The name server refuses to perform the specified operation for policy reasons.
    // For example, a name server may not wish to provide the information to the particular requester,
    // or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data.
    REFUSED = 5,
}

impl From<u8> for ResultCode {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::FORMERR,
            2 => Self::SERVFAIL,
            3 => Self::NXDOMAIN,
            4 => Self::NOTIMP,
            5 => Self::REFUSED,
            _ => Self::NOERROR,
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct DnsHeader {
    /// Packet Identifier (ID)
    /// A random identifier is assigned to query packets. Response packets must reply with the same id.
    /// This is needed to differentiate responses due to the stateless nature of UDP.
    pub id: u16, // 16 bits

    /// Query/Response Indicator (QR)
    /// 1 for a reply packet, 0 for a question packet.
    pub response: bool, // 1 bit

    /// Operation Code (OPCODE)
    /// Specifies the kind of query in a message. Typically always 0, see RFC1035 for details.
    pub opcode: u8, // 4 bits

    /// Authoritative Answer (AA)
    /// 1 if the responding server "owns" the domain queried, i.e., it's authoritative.
    pub authoritative_answer: bool, // 1 bit

    /// Truncation (TC)
    /// 1 if the message is larger than 512 bytes. Always 0 in UDP responses.
    pub truncated_message: bool, // 1 bit

    /// Recursion Desired (RD)
    /// Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
    pub recursion_desired: bool, // 1 bit

    /// Recursion Available (RA)
    /// Server sets this to 1 to indicate that recursion is available.
    pub recursion_available: bool, // 1 bit

    /// Reserved (Z) - 3 bits
    /// Originally reserved for later use, but now used for DNSSEC queries.
    pub checking_disabled: bool, // 1 bit
    pub authed_data: bool, // 1 bit
    pub z: bool,           // 1 bit

    /// Response Code (RCODE)
    /// Set by the server to indicate the status of the response, i.e. whether or not it was successful or failed,
    /// and in the latter case providing details about the cause of the failure.
    pub rescode: ResultCode, // 4 bits

    /// Question Count (QDCOUNT)
    /// The number of entries in the Question Section
    pub question_entries: u16, // 16 bits

    /// Answer Record Count (ANCOUNT)
    /// The number of entries in the Answer Section
    pub answer_entries: u16, // 16 bits

    /// Authority Record Count (NSCOUNT)
    /// The number of entries in the Authority Section
    pub authoritative_entries: u16, // 16 bits

    /// Additional Record Count (ARCOUNT)
    /// The number of entries in the Additional Section
    pub additional_entries: u16, // 16 bits
}

impl DnsHeader {
    pub fn new() -> Self {
        Self::default()
    }
}
