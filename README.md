# elf-parser

A lightweight ELF parser written in Rust, providing assistance for loading applications into the kernel.

It reads the data of the ELF file, and generates Sections, Relocations, Segments and so on.

It also generate a layout of the user stack according to the given user parameters and environment variables. It will be 
used for loading a given application into the physical memory in the kernel.

## Examples

```rust
let args: Vec<String> = vec![1, 2, 3];
let envs: Vec<String> = vec!["LOG=file"];
let auxv: BTreeMap<u8, usize> = BTreeMap::new();

// The top of the user stack
let stack_top = uspace.end() - stack_size;

let (stack_data, stack_bottom) = elf_parser::get_app_stack_region(
    args,
    &envs,
    auxv,
    stack_top,
    stack_size,
);

uspace.map_alloc(stack_top, stack_size, MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER)?;

unsafe {
    core::ptr::copy_nonoverlapping(
        stack_data.as_ptr(),
        phys_to_virt(stack_top).as_mut_ptr(),
        stack_data.len(),
    );
}

// The stack_bottom is the real stack pointer after inserting some auxiliary data on the user stack.
ucontext.sp = stack_bottom;

```