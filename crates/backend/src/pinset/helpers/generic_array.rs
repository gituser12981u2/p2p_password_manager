#![expect(dead_code, reason = "not currently used but will be")]
use crate::pinset::types::{PinsetError, Result};

use core::ops::{Index, IndexMut};
use std::borrow::Cow;

#[derive(Debug, Clone, Copy)]
/// A simple stack-allocated array with convenience methods for string/byte operations.
pub struct GenericArray<const N: usize> {
    /// The underlying byte buffer with fixed capacity N
    buf: [u8; N],
    /// Current length of valid data (excluding null terminator)
    len: usize,
}

impl<const N: usize> GenericArray<N> {
    pub const fn new() -> Self {
        // Do we use maybeuninit here until initialised?
        // Do we also used unchecked methods? seems pointless to use plain indexing if the bounds are already checked
        // I've avoided this because I don't want to necessarily add unsafe code with no perf gain (some people have fiery opinions about it!)
        let mut buf = [0u8; N];
        buf[0] = 0;
        Self { buf, len: 0 }
    }

    /// Creates a GenericArray from a byte slice or string slice.
    ///
    /// `input` - A type that can be converted to a byte slice (&str, &[u8], String, etc.)
    pub fn try_from_bytes<T: AsRef<[u8]>>(input: T) -> Result<Self> {
        let bytes = input.as_ref();

        if bytes.len() + 1 > N {
            return Err(PinsetError::BufferFull(N));
        }

        let mut buf = [0u8; N];
        let mut len = 0;

        while len < bytes.len() {
            buf[len] = bytes[len];
            len += 1;
        }

        buf[len] = 0; // null terminator

        Ok(Self { buf, len })
    }

    pub const fn push(&mut self, byte: u8) -> Result<()> {
        if self.len + 1 >= N {
            return Err(PinsetError::BufferFull(N));
        }
        self.buf[self.len] = byte;
        self.len += 1;
        self.buf[self.len] = 0;
        Ok(())
    }

    pub const fn get(&self, index: usize) -> Result<u8> {
        if index >= self.len {
            return Err(PinsetError::OutOfBounds {
                index,
                len: self.len,
            });
        }
        Ok(self.buf[index])
    }

    pub const fn as_str(&self) -> Result<&str> {
        // SAFETY: We know len is within ranghe and the buffer is never null
        // This avoids unnecessary UB checks
        let bytes = unsafe { &*std::ptr::slice_from_raw_parts(self.as_ptr(), self.len) };

        match core::str::from_utf8(bytes) {
            Ok(s) => Ok(s),
            Err(e) => Err(PinsetError::Utf8Error(e)),
        }
    }

    pub fn to_str_lossy(&self) -> Cow<'_, str> {
        let bytes = &self.buf[..self.len];
        String::from_utf8_lossy(bytes)
    }

    pub const fn as_ptr(&self) -> *const u8 {
        self.buf.as_ptr()
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn capacity(&self) -> usize {
        N
    }
}

impl<const N: usize> Index<usize> for GenericArray<N> {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        if index >= self.len {
            panic!(
                "index out of bounds: the len is {} but the index is {index}",
                self.len
            );
        }
        &self.buf[index]
    }
}

impl<const N: usize> IndexMut<usize> for GenericArray<N> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        if index >= self.len {
            panic!(
                "index out of bounds: the len is {} but the index is {}",
                self.len, index
            );
        }
        &mut self.buf[index]
    }
}

#[test]
fn generic_array_functionality() {
    let mut arr: GenericArray<10> = GenericArray::new();
    assert_eq!(arr.len(), 0);
    assert_eq!(arr.capacity(), 10);

    arr.push(b'h').expect("push h");
    arr.push(b'i').expect("push i");
    assert_eq!(arr.len(), 2);

    assert_eq!(arr.get(0).expect("get 0"), b'h');
    assert_eq!(arr.get(1).expect("get 1"), b'i');
    assert!(arr.get(2).is_err()); // Out of bounds

    assert_eq!(arr[0], b'h');
    assert_eq!(arr[1], b'i');

    let str_arr = GenericArray::<10>::try_from_bytes("test").expect("from_str");
    assert_eq!(str_arr.as_str().expect("as_str"), "test");
    assert_eq!(str_arr.len(), 4);

    // buffer full too long
    let result = GenericArray::<3>::try_from_bytes("toolong");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        crate::pinset::types::PinsetError::BufferFull(3)
    ));
}
