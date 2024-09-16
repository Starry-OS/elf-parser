#![no_std]
#![doc = include_str!("../README.md")]

pub mod arch;
extern crate alloc;
use alloc::{collections::btree_map::BTreeMap, string::String, vec::Vec};
use log::info;
use memory_addr::{VirtAddr, PAGE_SIZE_4K};

use page_table_entry::MappingFlags;

mod auxv;
pub use auxv::get_auxv_vector;
use user_stack::init_stack;
mod user_stack;

pub use crate::arch::get_relocate_pairs;

/// The segment of the elf file, which is used to map the elf file to the memory space
pub struct ELFSegment {
    /// The start virtual address of the segment
    pub vaddr: VirtAddr,
    /// The size of the segment
    pub size: usize,
    /// The flags of the segment which is used to set the page table entry
    pub flags: MappingFlags,
    /// The data of the segment
    pub data: Option<Vec<u8>>,
}

/// To parse the elf file and return the segments of the elf file
///
/// # Arguments
///
/// * `elf_data` - The elf file data
/// * `elf_base_addr` - The base address of the elf file if the file will be loaded to the memory
///
/// # Return
/// Return the entry point, the segments of the elf file and the relocate pairs
///
/// # Warning
/// It can't be used to parse the elf file which need the dynamic linker, but you can do this by calling this function recursively
pub fn get_elf_segments(elf: &xmas_elf::ElfFile, elf_base_addr: Option<usize>) -> Vec<ELFSegment> {
    let elf_header = elf.header;
    let magic = elf_header.pt1.magic;
    assert_eq!(magic, [0x7f, 0x45, 0x4c, 0x46], "invalid elf!");

    // Some elf will load ELF Header (offset == 0) to vaddr 0. In that case, base_addr will be added to all the LOAD.
    let base_addr = if let Some(header) = elf
        .program_iter()
        .find(|ph| ph.get_type() == Ok(xmas_elf::program::Type::Load))
    {
        // Loading ELF Header into memory.
        let vaddr = header.virtual_addr() as usize;

        if vaddr == 0 {
            if let Some(addr) = elf_base_addr {
                addr
            } else {
                panic!("ELF Header is loaded to vaddr 0, but no base_addr is provided");
            }
        } else {
            0
        }
    } else {
        0
    };
    info!("Base addr for the elf: 0x{:x}", base_addr);
    let mut segments = Vec::new();
    // Load Elf "LOAD" segments at base_addr.
    elf.program_iter()
        .filter(|ph| ph.get_type() == Ok(xmas_elf::program::Type::Load))
        .for_each(|ph| {
            let mut start_va = ph.virtual_addr() as usize + base_addr;
            let end_va = (ph.virtual_addr() + ph.mem_size()) as usize + base_addr;
            let mut start_offset = ph.offset() as usize;
            let end_offset = (ph.offset() + ph.file_size()) as usize;

            // Virtual address from elf may not be aligned.
            assert_eq!(start_va % PAGE_SIZE_4K, start_offset % PAGE_SIZE_4K);
            let front_pad = start_va % PAGE_SIZE_4K;
            start_va -= front_pad;
            start_offset -= front_pad;

            let mut flags = MappingFlags::USER;
            if ph.flags().is_read() {
                flags |= MappingFlags::READ;
            }
            if ph.flags().is_write() {
                flags |= MappingFlags::WRITE;
            }
            if ph.flags().is_execute() {
                flags |= MappingFlags::EXECUTE;
            }
            let data = Some(elf.input[start_offset..end_offset].to_vec());
            segments.push(ELFSegment {
                vaddr: VirtAddr::from(start_va),
                size: end_va - start_va,
                flags,
                data,
            });
        });

    segments
}

/// To parse the elf file and return the segments of the elf file
///
/// # Arguments
///
/// * `elf_data` - The elf file data
/// * `elf_base_addr` - The base address of the elf file if the file will be loaded to the memory
///
/// # Return
/// Return the entry point
///
/// # Warning
/// It can't be used to parse the elf file which need the dynamic linker, but you can do this by calling this function recursively
pub fn get_elf_entry(elf: &xmas_elf::ElfFile, elf_base_addr: Option<usize>) -> VirtAddr {
    let elf_header = elf.header;
    let magic = elf_header.pt1.magic;
    assert_eq!(magic, [0x7f, 0x45, 0x4c, 0x46], "invalid elf!");

    // Some elf will load ELF Header (offset == 0) to vaddr 0. In that case, base_addr will be added to all the LOAD.
    let base_addr = if let Some(header) = elf
        .program_iter()
        .find(|ph| ph.get_type() == Ok(xmas_elf::program::Type::Load))
    {
        // Loading ELF Header into memory.
        let vaddr = header.virtual_addr() as usize;

        if vaddr == 0 {
            if let Some(addr) = elf_base_addr {
                addr
            } else {
                panic!("ELF Header is loaded to vaddr 0, but no base_addr is provided");
            }
        } else {
            0
        }
    } else {
        0
    };
    info!("Base addr for the elf: 0x{:x}", base_addr);

    let entry = elf.header.pt2.entry_point() as usize + base_addr;
    entry.into()
}

/// To get the app stack and the information on the stack from the ELF file
///
/// # Arguments
///
/// * `args` - The arguments of the app
/// * `envs` - The environment variables of the app
/// * `auxv` - The auxv vector of the app
/// * `stack_top` - The top address of the stack
/// * `stack_size` - The size of the stack.
///
/// # Return
///
/// `(stack_content, real_stack_bottom)`
///
/// * `stack_content`: the stack data from the low address to the high address, which will be used to map in the memory
///
/// * `real_stack_bottom`: The initial stack bottom is `stack_top + stack_size`.After push arguments into the stack, it will return the real stack bottom
///
/// The return data will be divided into two parts.
/// * The first part is the free stack content, which is all 0.
/// * The second part is the content carried by the user stack when it is initialized, such as args, auxv, etc.
///
/// The detailed format is described in <https://articles.manugarg.com/aboutelfauxiliaryvectors.html>
pub fn get_app_stack_region(
    args: Vec<String>,
    envs: &[String],
    auxv: BTreeMap<u8, usize>,
    stack_top: VirtAddr,
    stack_size: usize,
) -> (Vec<u8>, usize) {
    let ustack_top = stack_top;
    let ustack_bottom = ustack_top + stack_size;
    // The stack variable is actually the information carried by the stack
    let stack = init_stack(args, envs, auxv, ustack_bottom.into());
    let ustack_bottom = stack.get_sp();
    let mut data = [0_u8].repeat(stack_size - stack.get_len());
    data.extend(stack.get_data_front_ref());
    (data, ustack_bottom)
}
