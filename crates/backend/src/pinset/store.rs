use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinsetStore {
    pub records: Vec<PinsetRecord>,
    pub version: u32,
}

impl PinsetStore {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            version: 1,
        }
    }

    pub fn find_by_peer_id(&self, peer_id: &[u8]) -> Option<&PinsetRecord> {
        self.records.iter().find(|r| r.peer_id == peer_id)
    }

    pub fn cleanup_expired(&mut self, current_time: u64) {
        self.records.retain(|r| !r.is_expired(current_time));
        // Random comment, retain isn't *actually* performant
        //https://github.com/rust-lang/rust/issues/91497
        // I'm going to just leave this here if anyone wants to look at it (i tested this last week but it's really concise and readable for now!)
    }

    pub fn add_record(&mut self, record: PinsetRecord) {
        self.records.push(record);
    }

    pub fn remove_record(&mut self, peer_id: &[u8]) -> Option<PinsetRecord> {
        if let Some(pos) = self.records.iter().position(|r| r.peer_id == peer_id) {
            Some(self.records.remove(pos))
        } else {
            None
        }
    }

    pub fn get_record(&self, peer_id: &[u8]) -> Option<&PinsetRecord> {
        self.records.iter().find(|r| r.peer_id == peer_id)
    }

    pub fn get_active_records(&self) -> Vec<&PinsetRecord> {
        self.records
            .iter()
            .filter(|r| matches!(r.flags, PinsetFlags::Active))
            .collect()
    }
}
