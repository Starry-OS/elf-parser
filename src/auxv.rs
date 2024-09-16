//! Some constant in the elf file
extern crate alloc;
use alloc::collections::BTreeMap;
use log::info;
use memory_addr::PAGE_SIZE_4K;

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
pub fn get_auxv_vector(
    elf: &xmas_elf::ElfFile,
    elf_base_addr: Option<usize>,
) -> BTreeMap<u8, usize> {
    // Some elf will load ELF Header (offset == 0) to vaddr 0. In that case, base_addr will be added to all the LOAD.
    let elf_header_vaddr: usize = if elf
        .program_iter()
        .find(|ph| ph.get_type() == Ok(xmas_elf::program::Type::Load) && ph.virtual_addr() == 0)
        .is_some()
    {
        assert!(
            elf.header.pt2.type_().as_type() != xmas_elf::header::Type::Executable,
            "ELF Header is loaded to vaddr 0, but the ELF file is executable"
        );
        elf_base_addr.expect("ELF Header is loaded to vaddr 0, but no base_addr is provided")
    } else {
        0
    };
    info!("ELF header addr: 0x{:x}", elf_header_vaddr);
    let mut map = BTreeMap::new();
    map.insert(
        AT_PHDR,
        elf_header_vaddr + elf.header.pt2.ph_offset() as usize,
    );
    map.insert(AT_PHENT, elf.header.pt2.ph_entry_size() as usize);
    map.insert(AT_PHNUM, elf.header.pt2.ph_count() as usize);
    map.insert(AT_RANDOM, 0);
    map.insert(AT_PAGESZ, PAGE_SIZE_4K);
    map
}
