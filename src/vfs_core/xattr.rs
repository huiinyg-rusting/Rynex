use crate::serial;

pub const XATTR_NAME_MAX: usize = 255;
pub const XATTR_SIZE_MAX: usize = 65536;
pub const MAX_XATTR_PER_INODE: usize = 16;

#[derive(Clone, Copy)]
pub struct XattrEntry {
    pub name: [u8; XATTR_NAME_MAX],
    pub name_len: u16,
    pub value_len: u32,
    pub value_off: u32,
}

impl XattrEntry {
    pub const fn empty() -> Self {
        XattrEntry {
            name: [0; XATTR_NAME_MAX],
            name_len: 0,
            value_len: 0,
            value_off: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct XattrBlock {
    pub entries: [XattrEntry; MAX_XATTR_PER_INODE],
    pub count: u16,
    pub data_block: u64,
}

impl XattrBlock {
    pub const fn empty() -> Self {
        XattrBlock {
            entries: [XattrEntry::empty(); MAX_XATTR_PER_INODE],
            count: 0,
            data_block: 0,
        }
    }

    pub fn find(&self, name: &[u8]) -> Option<usize> {
        for i in 0..self.count as usize {
            let e = &self.entries[i];
            if e.name_len as usize == name.len() {
                let ename = &e.name[..e.name_len as usize];
                if ename == name {
                    return Some(i);
                }
            }
        }
        None
    }

    pub fn set(&mut self, name: &[u8], value: &[u8]) -> Result<usize, &'static str> {
        if name.len() > XATTR_NAME_MAX {
            return Err("xattr name too long");
        }
        if value.len() > XATTR_SIZE_MAX {
            return Err("xattr value too long");
        }

        if let Some(idx) = self.find(name) {
            self.entries[idx].value_len = value.len() as u32;
            return Ok(idx);
        }

        if (self.count as usize) >= MAX_XATTR_PER_INODE {
            return Err("xattr table full");
        }

        let idx = self.count as usize;
        self.entries[idx].name_len = name.len() as u16;
        self.entries[idx].value_len = value.len() as u32;
        for i in 0..name.len() {
            self.entries[idx].name[i] = name[i];
        }
        self.count += 1;
        Ok(idx)
    }

    pub fn get(&self, name: &[u8]) -> Option<&XattrEntry> {
        self.find(name).map(|i| &self.entries[i])
    }

    pub fn remove(&mut self, name: &[u8]) -> bool {
        if let Some(idx) = self.find(name) {
            let last = self.count as usize - 1;
            self.entries[idx] = self.entries[last];
            self.entries[last] = XattrEntry::empty();
            self.count -= 1;
            true
        } else {
            false
        }
    }
}

pub type XattrHandler = fn(ino: u64, name: &[u8], value: &mut [u8]) -> Result<usize, &'static str>;

pub struct XattrManager {
    handlers: [Option<(XattrHandler, &'static str)>; 8],
    count: usize,
}

impl XattrManager {
    pub const fn new() -> Self {
        XattrManager {
            handlers: [None; 8],
            count: 0,
        }
    }

    pub fn register(&mut self, prefix: &'static str, handler: XattrHandler) -> Result<(), &'static str> {
        if self.count >= 8 {
            return Err("xattr handler table full");
        }
        self.handlers[self.count] = Some((handler, prefix));
        self.count += 1;
        Ok(())
    }

    pub fn handle(&self, full_name: &[u8], value: &mut [u8], ino: u64) -> Result<usize, &'static str> {
        for i in 0..self.count {
            if let Some((handler, prefix)) = &self.handlers[i] {
                let pbytes = prefix.as_bytes();
                if full_name.starts_with(pbytes) {
                    let attr_name = &full_name[pbytes.len()..];
                    return handler(ino, attr_name, value);
                }
            }
        }
        Err("no handler for xattr namespace")
    }
}

pub static XATTR_MGR: XattrManager = XattrManager::new();

pub fn init() {
    serial::write_str("VFS: xattr initialized\n");
}
