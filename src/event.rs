#[derive(Copy, Clone, Debug)]
#[repr(u16)]
/// An event type.
pub enum EventType {
    Type1 = 0,
    Type2 = 1,
}

#[derive(thiserror::Error, Debug)]
#[error("Unknown event type {0}")]
pub struct UnknownEventTypeError(u16);

impl TryFrom<u16> for EventType {
    type Error = UnknownEventTypeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            x if x == EventType::Type1 as u16 => Ok(EventType::Type1),
            x if x == EventType::Type2 as u16 => Ok(EventType::Type2),
            _ => Err(UnknownEventTypeError(value))
        }
    }
}

#[derive(Debug)]
#[repr(C, packed)]
/// The event header.
pub struct EventHeader {
    timestamp: u64,
    tgid_tid: u64,
    evt_type: EventType,
    params_num: u16,
    len: u32,
}