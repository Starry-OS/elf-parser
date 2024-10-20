//! Relocate .rela sections for ELF file under riscv64 architecture.
//! aarch: <https://github.com/ARM-software/abi-aa/releases/download/2023Q3/aaelf64.pdf>

extern crate alloc;
use core::mem::size_of;

use super::RelocatePair;
use alloc::vec::Vec;
use log::info;
use memory_addr::VirtAddr;
use xmas_elf::symbol_table::Entry;

pub const R_AARCH32_GLOBAL_DATA: u32 = 181;
pub const R_AARCH64_GLOBAL_DATA: u32 = 1025;
pub const R_AARCH64_JUMP_SLOT: u32 = 1026;
pub const R_AARCH64_RELATIVE: u32 = 1027;

/// Read relocate pairs from the elf file.
///
/// # Arguments
///
/// * `elf` - The [`xmas_elf::ElfFile`] data
/// * `base_addr` - The base address of the elf file if the file will be loaded to the memory
///
/// # Return
/// A vector of [`super::RelocatePair`] which contains the source
/// and destination address of the relocation.
pub fn relocate_pairs(elf: &xmas_elf::ElfFile, base_addr: usize) -> Vec<RelocatePair> {
    let elf_header = elf.header;
    let magic = elf_header.pt1.magic;
    assert_eq!(magic, [0x7f, 0x45, 0x4c, 0x46], "invalid elf!");
    let mut pairs = Vec::new();
    info!("Base addr for the elf: 0x{:x}", base_addr);
    if let Some(rela_dyn) = elf.find_section_by_name(".rela.dyn") {
        let data = match rela_dyn.get_data(elf) {
            Ok(xmas_elf::sections::SectionData::Rela64(data)) => data,
            _ => panic!("Invalid data in .rela.dyn section"),
        };

        if let Some(dyn_sym_table) = elf.find_section_by_name(".dynsym") {
            let dyn_sym_table = match dyn_sym_table.get_data(elf) {
                Ok(xmas_elf::sections::SectionData::DynSymbolTable64(dyn_sym_table)) => {
                    dyn_sym_table
                }
                _ => panic!("Invalid data in .dynsym section"),
            };

            info!("Relocating .rela.dyn");
            for entry in data {
                let dyn_sym = &dyn_sym_table[entry.get_symbol_table_index() as usize];
                let destination = base_addr + entry.get_offset() as usize;
                // S: (when used on its own) is the address of the symbol.
                // Warn: in riscv and x86, it stands for the value, why in arm it stand for the address?
                let symbol_value = dyn_sym.value() as usize; // Represents the value of the symbol whose index resides in the relocation entry.
                let addend = entry.get_addend() as usize; // Represents the addend used to compute the value of the relocatable field.

                match entry.get_type() {
                    R_AARCH32_GLOBAL_DATA => {
                        if dyn_sym.shndx() == 0 {
                            let name = dyn_sym.get_name(elf).unwrap();
                            panic!(r#"Symbol "{}" not found"#, name);
                        }
                        pairs.push(RelocatePair {
                            src: VirtAddr::from(symbol_value + addend),
                            dst: VirtAddr::from(destination),
                            count: 4,
                        })
                    }
                    R_AARCH64_GLOBAL_DATA => {
                        if dyn_sym.shndx() == 0 {
                            let name = dyn_sym.get_name(elf).unwrap();
                            panic!(r#"Symbol "{}" not found"#, name);
                        }
                        pairs.push(RelocatePair {
                            src: VirtAddr::from(symbol_value + addend),
                            dst: VirtAddr::from(destination),
                            count: 8,
                        })
                    }
                    R_AARCH64_JUMP_SLOT => {
                        if dyn_sym.shndx() == 0 {
                            let name = dyn_sym.get_name(elf).unwrap();
                            panic!(r#"Symbol "{}" not found"#, name);
                        }
                        pairs.push(RelocatePair {
                            src: VirtAddr::from(symbol_value + addend),
                            dst: VirtAddr::from(destination),
                            count: 8,
                        })
                    }
                    R_AARCH64_RELATIVE => {
                        // Delta (S) if s is a normal symbol, resolves to the difference between the static link address of s and theexecution address of s.
                        // If s is the null symbol (ELF symbol index 0), resolves to the diference between the staticlink address of p and the execution address of P.
                        pairs.push(RelocatePair {
                            src: VirtAddr::from(base_addr + addend),
                            dst: VirtAddr::from(destination),
                            count: 8,
                        })
                    }

                    other => panic!("Unknown relocation type: {}", other),
                }
            }
        }
    }

    // Relocate .rela.plt sections
    if let Some(rela_plt) = elf.find_section_by_name(".rela.plt") {
        let data = match rela_plt.get_data(elf) {
            Ok(xmas_elf::sections::SectionData::Rela64(data)) => data,
            _ => panic!("Invalid data in .rela.plt section"),
        };
        if elf.find_section_by_name(".dynsym").is_some() {
            let dyn_sym_table = match elf
                .find_section_by_name(".dynsym")
                .expect("Dynamic Symbol Table not found for .rela.plt section")
                .get_data(elf)
            {
                Ok(xmas_elf::sections::SectionData::DynSymbolTable64(dyn_sym_table)) => {
                    dyn_sym_table
                }
                _ => panic!("Invalid data in .dynsym section"),
            };

            info!("Relocating .rela.plt");
            for entry in data {
                let dyn_sym = &dyn_sym_table[entry.get_symbol_table_index() as usize];
                let destination = base_addr + entry.get_offset() as usize;
                match entry.get_type() {
                    R_AARCH64_JUMP_SLOT => {
                        let symbol_value = if dyn_sym.shndx() != 0 {
                            dyn_sym.value() as usize
                        } else {
                            let name = dyn_sym.get_name(elf).unwrap();
                            panic!(r#"Symbol "{}" not found"#, name);
                        }; // Represents the value of the symbol whose index resides in the relocation entry.
                        pairs.push(RelocatePair {
                            src: VirtAddr::from(symbol_value + base_addr),
                            dst: VirtAddr::from(destination),
                            count: size_of::<usize>(),
                        });
                    }
                    other => panic!("Unknown relocation type: {}", other),
                }
            }
        }
    }
    info!("Relocating done");
    pairs
}
