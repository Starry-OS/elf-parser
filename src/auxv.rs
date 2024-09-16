//! Some constant in the elf file
extern crate alloc;
use alloc::collections::BTreeMap;
use log::info;
use memory_addr::PAGE_SIZE_4K;

use crate::get_elf_base_addr;

const AT_PHDR: u8 = 3;
const AT_PHENT: u8 = 4;
const AT_PHNUM: u8 = 5;
const AT_PAGESZ: u8 = 6;
#[allow(unused)]
const AT_BASE: u8 = 7;
#[allow(unused)]
const AT_ENTRY: u8 = 9;
const AT_RANDOM: u8 = 25;

/// To parse the elf file and get the auxv vectors
///
/// # Arguments
///
/// * `elf` - The elf file
/// * `elf_base_addr` - The base address of the elf file if the file will be loaded to the memory
pub fn get_auxv_vector(elf: &xmas_elf::ElfFile, elf_base_addr: usize) -> BTreeMap<u8, usize> {
    // Some elf will load ELF Header (offset == 0) to vaddr 0. In that case, base_addr will be added to all the LOAD.
    let kernel_offset = get_elf_base_addr(elf, elf_base_addr).unwrap();
    info!("ELF header addr: 0x{:x}", kernel_offset);
    let mut map = BTreeMap::new();

    if let Some(ph) = elf
        .program_iter()
        .find(|ph| ph.get_type() == Ok(xmas_elf::program::Type::Load))
    {
        // The first LOAD segment is the lowest one. And its virtual address is the base address of the ELF file.
        map.insert(
            AT_PHDR,
            kernel_offset + (ph.virtual_addr() + elf.header.pt2.ph_offset()) as usize,
        );
    } else {
        map.insert(AT_PHDR, 0);
    }

    map.insert(AT_PHENT, elf.header.pt2.ph_entry_size() as usize);
    map.insert(AT_PHNUM, elf.header.pt2.ph_count() as usize);
    map.insert(AT_RANDOM, 0);
    map.insert(AT_PAGESZ, PAGE_SIZE_4K);
    map
}
