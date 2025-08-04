//! Basic emulation of a program's virtual address space.

use std::ops::ControlFlow;
use std::{
    borrow::Cow,
    io::{Read, Write},
};

use bitvec::{BitArr, array::BitArray, bitarr};
use fxhash::FxHashMap;

use super::image::ImageView;

#[derive(Debug, Clone)]
struct MemoryBlock {
    bytes: [u8; Self::SIZE],
    is_known: BitArr!(for Self::SIZE),
}

impl MemoryBlock {
    const SIZE: usize = 64;
}

impl Default for MemoryBlock {
    fn default() -> Self {
        Self {
            bytes: [0; Self::SIZE],
            is_known: BitArray::ZERO,
        }
    }
}

impl MemoryBlock {
    #[inline(always)]
    fn known_slices<T>(
        &self,
        mut offset: usize,
        max_offset: usize,
        mut cb: impl FnMut(u64, &[u8]) -> ControlFlow<T>,
    ) -> ControlFlow<T> {
        while offset < max_offset {
            let start = offset + self.is_known[offset..max_offset].leading_zeros();
            let end = start + self.is_known[start..max_offset].leading_ones();
            if start != end {
                cb(start as u64, &self.bytes[start..end])?;
            }
            offset = end;
        }
        ControlFlow::Continue(())
    }
}

#[derive(Clone)]
pub struct MemoryStore<I: ImageView> {
    blocks: FxHashMap<usize, MemoryBlock>,
    image: I,
}

impl<I: ImageView> MemoryStore<I> {
    pub fn new(image: I) -> Self {
        Self {
            blocks: Default::default(),
            image,
        }
    }

    pub fn new_initialized<B: AsRef<[u8]>>(
        image: I,
        known_memory: impl IntoIterator<Item = (u64, B)>,
    ) -> Self {
        let mut s = Self::new(image);
        for (addr, mem) in known_memory {
            s.write(addr, mem.as_ref());
        }
        s
    }

    pub fn image(&self) -> &I {
        &self.image
    }

    pub fn read<'b>(&self, addr: u64, out_buf: &'b mut [u8]) -> Option<&'b mut [u8]> {
        if out_buf.is_empty() {
            return Some(out_buf);
        }

        let (i_start_block, start_ofs) = Self::block_and_offset(addr);
        let (i_end_block, end_ofs) = Self::block_and_offset(addr + out_buf.len() as u64 - 1);

        if i_start_block == i_end_block {
            let block = self.get_block(i_start_block)?;
            block.is_known[start_ofs..=end_ofs].all().then(|| {
                out_buf.copy_from_slice(&block.bytes[start_ofs..=end_ofs]);
            })?;
        }
        else {
            let mut out_cursor = &mut *out_buf;

            let start_block = self.get_block(i_start_block)?;
            start_block.is_known[start_ofs..]
                .all()
                .then(|| out_cursor.write_all(&start_block.bytes[start_ofs..]).unwrap())?;

            for i_mid_block in (i_start_block + 1)..(i_end_block - 1) {
                let mid_block = self.get_block(i_mid_block)?;
                mid_block.is_known.all().then(|| {
                    out_cursor.write_all(&mid_block.bytes).unwrap();
                })?;
            }

            let end_block = self.get_block(i_end_block)?;
            end_block.is_known[..end_ofs]
                .all()
                .then(|| out_cursor.write_all(&end_block.bytes[..=end_ofs]).unwrap())?;
        }

        Some(out_buf)
    }

    pub fn write(&mut self, addr: u64, mut buf: &[u8]) {
        if buf.is_empty() {
            return;
        }

        let (i_start_block, start_ofs) = Self::block_and_offset(addr);
        let (i_end_block, end_ofs) =
            Self::block_and_offset(addr.saturating_add(buf.len() as u64 - 1));

        if i_start_block == i_end_block {
            let block = self.get_block_mut(i_start_block);
            block.is_known[start_ofs..=end_ofs].fill(true);
            block.bytes[start_ofs..=end_ofs].copy_from_slice(buf);
        }
        else {
            let start_block = self.get_block_mut(i_start_block);
            start_block.is_known[start_ofs..].fill(true);
            buf.read_exact(&mut start_block.bytes[start_ofs..]).unwrap();

            for i_mid_block in (i_start_block + 1)..(i_end_block - 1) {
                let mid_block = self.get_block_mut(i_mid_block);
                mid_block.is_known.fill(true);
                buf.read_exact(&mut mid_block.bytes).unwrap();
            }

            let end_block = self.get_block_mut(i_end_block);
            end_block.is_known[..end_ofs].fill(true);
            buf.read_exact(&mut end_block.bytes[..=end_ofs]).unwrap();
        }
    }

    pub fn invalidate(&mut self, addr: u64, count: usize) {
        if count == 0 {
            return;
        }

        let (i_start_block, start_ofs) = Self::block_and_offset(addr);
        let (i_end_block, end_ofs) = Self::block_and_offset(addr + count as u64 - 1);

        if i_start_block == i_end_block {
            let block = self.get_block_mut(i_start_block);
            block.is_known[start_ofs..=end_ofs].fill(false);
        }
        else {
            let start_block = self.get_block_mut(i_start_block);
            start_block.is_known[start_ofs..].fill(false);

            for i_mid_block in (i_start_block + 1)..(i_end_block - 1) {
                let mid_block = self.get_block_mut(i_mid_block);
                mid_block.is_known.fill(false);
            }

            let end_block = self.get_block_mut(i_end_block);
            end_block.is_known[..end_ofs].fill(false);
        }
    }

    pub fn read_int(&self, addr: u64, size: usize) -> Option<u64> {
        if size > 8 {
            panic!("integers of size >8 not supported by read_int");
        }

        let mut read_buf = [0u8; 8];
        self.read(addr, &mut read_buf[..size])?;
        Some(u64::from_le_bytes(read_buf))
    }

    pub fn write_int(&mut self, addr: u64, val: Option<u64>, size: usize) {
        match (val, size) {
            (None, _) => self.invalidate(addr, size),
            (Some(val), ..=8) => self.write(addr, &val.to_le_bytes()[..size]),
            (Some(_), 9..) => panic!("integers of size >8 not supported by write_int"),
        }
    }

    fn block_and_offset(addr: u64) -> (usize, usize) {
        (
            addr as usize / MemoryBlock::SIZE,
            addr as usize % MemoryBlock::SIZE,
        )
    }

    fn get_block(&self, i_block: usize) -> Option<Cow<MemoryBlock>> {
        self.blocks.get(&i_block).map(Cow::Borrowed).or_else(|| {
            let bytes = self.image.read((i_block * MemoryBlock::SIZE) as u64, MemoryBlock::SIZE)?
                [..MemoryBlock::SIZE]
                .try_into()
                .unwrap();

            Some(Cow::Owned(MemoryBlock {
                bytes,
                is_known: bitarr![1; MemoryBlock::SIZE],
            }))
        })
    }

    fn get_block_mut(&mut self, i_block: usize) -> &mut MemoryBlock {
        self.blocks.entry(i_block).or_insert_with(|| {
            self.image
                .read((i_block * MemoryBlock::SIZE) as u64, MemoryBlock::SIZE)
                .map(|bytes| MemoryBlock {
                    bytes: bytes[..MemoryBlock::SIZE].try_into().unwrap(),
                    is_known: bitarr![1; MemoryBlock::SIZE],
                })
                .unwrap_or_default()
        })
    }
}

impl<I: ImageView> std::fmt::Debug for MemoryStore<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut blocks_sorted = self.blocks.iter().collect::<Vec<_>>();
        blocks_sorted.sort_by_key(|(b, _)| **b);

        let mut map = f.debug_map();
        for (block_id, block) in blocks_sorted {
            block.known_slices::<()>(0, MemoryBlock::SIZE, |ofs, bytes| {
                map.entry(&((block_id * MemoryBlock::SIZE) as u64 + ofs), &bytes);
                ControlFlow::Continue(())
            });
        }
        map.finish()?;
        Ok(())
    }
}
