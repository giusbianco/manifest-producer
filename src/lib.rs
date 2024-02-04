//use capstone::arch::{self, BuildsCapstone};
//use capstone::Capstone;
use goblin::elf::Elf;
use std::fs::File;
use std::process::Command;
use std::io::{BufRead, BufReader, Read, Write};
use std::vec;
use serde::Serialize;
use std::collections::HashSet;
use libc::c_int;

pub mod error;
use error::{Error, Result};

#[derive(Debug, Serialize)]
pub struct Manifest {
    architecture: String,
    stripped: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_found: Option<Vec<String>>,
    syscall_features: Option<SyscallFeatures>,
}
impl Manifest {
    pub fn new() -> Self{
        Self { 
            architecture: "".to_string(), 
            stripped: true, 
            api_found: None, 
            syscall_features: None 
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SyscallFeatures {
    network: Option<HashSet<String>>,
    device: Option<HashSet<String>>,
    disk: Option<HashSet<String>>,
    memory:Option<HashSet<String>>,
}
impl SyscallFeatures {
    pub fn new() -> Self {
        Self { 
            network: Some(HashSet::new()), 
            device: Some(HashSet::new()), 
            disk: Some(HashSet::new()),
            memory: Some(HashSet::new()),
        }
    }
}

pub fn elf_analysis(file_path: &str) -> Result<()> {
    let elf_data = read_elf_file(file_path)?;
    let elf = Elf::parse(&elf_data)?;
    
    // Retrieve the architecture from the ELF header
    let architecture = arch_recovery(&elf);
    if architecture == "Unknown" {
        return Err(Error::InvalidElf {
            source: goblin::error::Error::Malformed("Unsupported architecture".to_string()),
        });
    }
    let stripped = is_stripped(&elf);
    
    // Initialize the manifest
    let mut dyn_manifest = Manifest::new();
    dyn_manifest.architecture = architecture.to_string();
    dyn_manifest.stripped = stripped;

    let mut st_manifest = Manifest::new();
    st_manifest.architecture = architecture.to_string();
    st_manifest.stripped = stripped;

    // If not stripped, search for APIs
    if !stripped {
        // JOB1
        dyn_manifest.api_found = Some(api_search(&elf));
        st_manifest.api_found = Some(api_search(&elf)); 
    }

    // JOB2 with strace
    let syscall_categories = syscall_tracing(file_path)?;
    dyn_manifest.syscall_features = Some(syscall_categories);

    // JOB2 with the mapping table
    let syscall_categories = syscall_mapping_table(&elf, elf_data.clone())?;
    st_manifest.syscall_features = Some(syscall_categories);

    // JOB2 with hex pattern - PSEUDO-code
    // syscall_pattern(&elf, elf_data.clone())?;

    // Serialize the manifest to JSON and print it
    write_manifest_to_json(&dyn_manifest, "./dyn_manifest.json")?;
    write_manifest_to_json(&st_manifest, "./st_manifest.json")?;
    
    Ok(())
}
/*
*
*   PRE-JOB FUNCTIONS: arch_recovery, is_stripped, read_elf_file
*
*/

pub fn read_elf_file(file_path: &str) -> Result<Vec<u8>> {
    let mut file = File::open(&file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

// Function for retrieving the architecture from the ELF file
pub fn arch_recovery<'a>(elf: &'a Elf<'a>) -> &'a str {
    match elf.header.e_machine {
        goblin::elf::header::EM_X86_64 =>  "x86-64",
        goblin::elf::header::EM_386 =>  "x86",
        goblin::elf::header::EM_XTENSA =>  "Xtensa",
        _ =>  "Unknown",
    }
}

// Check for the presence of the specified sections
fn has_sections(elf: &Elf, section_type: u32) -> bool {
    elf.section_headers
        .iter()
        .any(|section| section.sh_type == section_type)
}

// Check for the presence of the .symtab and .strtab sections to understand if the file is stripped
pub fn is_stripped(elf: &Elf) -> bool {
    match elf.header.e_ident[goblin::elf::header::EI_CLASS] {
        goblin::elf::header::ELFCLASS64
        | goblin::elf::header::ELFCLASS32 => {
            !has_sections(&elf, goblin::elf::section_header::SHT_SYMTAB)
                || !has_sections(&elf, goblin::elf::section_header::SHT_STRTAB)
        }
        _ => true,
    }
}

/*
*
*   JOB1 FUNCTIONS: api_search
*
*/

fn get_function_name<'a>(elf: &'a Elf, symbol: &'a goblin::elf::Sym) -> Option<&'a str> {
    let name_offset = symbol.st_name as usize;
    // Reference to the string in the string table
    let name_str: &'a str = elf.strtab.get_at(name_offset)?;
    Some(name_str)
}

// Function to search for APIs in the symbol table
pub fn api_search(elf: &Elf) -> Vec<String> {
    let api_list = vec!["turnLampOn", "turnLampOff"];
    let mut api_found = Vec::new();
    for symbol in elf.syms.iter() {
        if symbol.st_type() == goblin::elf::sym::STT_FUNC && symbol.st_shndx != 0 {
            if let Some(function_name) = get_function_name(&elf, &symbol) {
                if api_list.contains(&function_name) {
                    api_found.push(function_name.to_string());
                }
            }
        }
    }
    api_found
}

/* 
*
*   JOB2 - common code
*
*/

fn insert_into_category(category: &mut Option<HashSet<String>>, syscall: &str) {
    if let Some(ref mut category_set) = category {
        category_set.insert(syscall.to_string());
    }
}

/*
*
*   JOB2 - strace strategy: syscall_tracing
*
*/

fn launch_strace(binary_path: &str) -> Result<()> {
    // Launch the strace command
    Command::new("strace")
        .arg("-o")
        .arg("./binaries/strace_output.txt")
        .arg(binary_path)
        .output()?;
    
    Ok(())
}

fn process_strace_output(syscall_categories: &mut SyscallFeatures) -> Result<()> {
    // Open the strace output file for reading
    let file = std::fs::File::open("./binaries/strace_output.txt")?;
    let reader = BufReader::new(file);
    // Process each line in the strace output
    for line in reader.lines() {
        if let Ok(line) = line {
            if let Some((category, syscall)) = categorize_syscall(&line) {
                // Categorize syscalls based on their type
                match category {
                    "network" => insert_into_category(&mut syscall_categories.network, syscall),
                    "device" => insert_into_category(&mut syscall_categories.device, syscall),
                    "disk" => insert_into_category(&mut syscall_categories.disk, syscall),
                    "memory" => insert_into_category(&mut syscall_categories.memory, syscall),
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

fn categorize_syscall<'a>(syscall: &'a str) -> Option<(&'a str, &'a str)> {
    if syscall.contains("write") {
        Some(("disk", "write_disk"))
    } else if syscall.contains("connect") {
        Some(("network", "connection_attempt"))
    } else if syscall.contains("recvfrom") {
        Some(("network", "recv_data"))
    } else if syscall.contains("sendto") {
        Some(("network", "send_data"))
    } else if syscall.contains("ioctl") {
        Some(("device", "I/O_control"))
    } else if syscall.contains("mmap") {
        Some(("memory", "access_memory"))
    } else {
        None
    }
}

fn syscall_tracing(binary_path: &str) -> Result<SyscallFeatures> {
    let mut syscall_categories = SyscallFeatures::new();
    // Launch the strace command
    launch_strace(binary_path)?;
    // Process the strace output file to categorize syscalls
    process_strace_output(&mut syscall_categories)?;
    Ok(syscall_categories)
}


/*
*
*   JOB2 - syscall table mapping strategy: syscall_mapping_table
*
*/

fn process_syscalls(syscalls_data: &[u8], syscall_names: &Vec<(&str, c_int)>, syscall_categories: &mut SyscallFeatures) {
    // Iterate over each 4-byte entry in the system call section
    for syscall_entry in syscalls_data.chunks_exact(4) {
        // Extract the system call number from the 4-byte entry
        let syscall_number = u32::from_le_bytes([
            syscall_entry[0],
            syscall_entry[1],
            syscall_entry[2],
            syscall_entry[3],
        ]);
        // Look up the name of the system call in the table
        if let Some(syscall_name) = syscall_names.iter().find(|(_, num)| *num == syscall_number as c_int) {
            match syscall_name.0 {
                "sys_write" | "sys_fsync" => insert_into_category(&mut syscall_categories.disk, syscall_name.0),
                "send_data" | "recv_data" | "sys_socket" | "connection_attempt" => insert_into_category(&mut syscall_categories.network, syscall_name.0),
                "I/O_control" => insert_into_category(&mut syscall_categories.device, syscall_name.0),
                "access_memory" => insert_into_category(&mut syscall_categories.memory, syscall_name.0),
                _ => {} // Ignore other system calls 
            }
        }
    }
}

pub fn syscall_mapping_table(elf: &Elf, buffer: Vec<u8>) -> Result<SyscallFeatures> {
    // Define a mapping table between numbers and system call names
    let syscall_names: Vec<(&str, c_int)> = vec![
        ("write_disk", libc::SYS_write.try_into().unwrap()),
        ("send_data", libc::SYS_sendto.try_into().unwrap()),
        ("I/O_control", libc::SYS_ioctl.try_into().unwrap()),
        ("recv_data", libc::SYS_recvfrom.try_into().unwrap()),
        ("sys_socket", libc::SYS_socket.try_into().unwrap()),
        ("connection_attempt", libc::SYS_connect.try_into().unwrap()),
        ("sys_fsync", libc::SYS_fsync.try_into().unwrap()),
        ("access_memory", libc::SYS_mmap.try_into().unwrap()),
        // Add more system calls as needed
    ];
    let mut syscall_categories = SyscallFeatures::new();
    // Find the system call section (code section in this case)
    let syscalls_section = elf
        .section_headers
        .iter()
        .find(|section| elf.shdr_strtab.get_at(section.sh_name) == Some(".text"))
        .ok_or_else(|| Error::NoSyscallSec)?;
    // Access the data in the system call section
    let syscalls_data = &buffer[syscalls_section.sh_offset as usize
        ..(syscalls_section.sh_offset + syscalls_section.sh_size) as usize];
    // Process each syscall entry and categorize them
    process_syscalls(syscalls_data, &syscall_names, &mut syscall_categories);
    Ok(syscall_categories)
}

/*
*
*   JOB2 - pattern strategy PSEUDO-code
*

// Define the system call patterns of interest
const WRITE_PATTERN: &[u8] = &[0x0F, 0x05]; // This is an example pattern for syscall write on x86-64

pub fn syscall_pattern(elf: &Elf, elf_data: Vec<u8>) -> Result<()> {
    // Initialize Capstone for x86-64 architecture
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .build()?;

    // Find the .text section
    let text_section = elf
    .section_headers
    .iter()
    .find(|section| elf.shdr_strtab.get_at(section.sh_name) == Some(".text"))
    .ok_or_else(|| Error::NoSyscallSec)?;

    // Use the virtual address of the .text section as the starting address
    let start_address = text_section.sh_addr;
    let end_address = text_section.sh_size;

    let mut addr = start_address;
    let syscall_patterns: HashSet<&[u8]> = vec![WRITE_PATTERN].into_iter().collect();

    while addr < end_address {
        let instr = cs.disasm_all(&elf_data[addr as usize..], addr)?;

        for i in instr.as_ref() {
            let instr_bytes = i.bytes();
            if syscall_patterns.contains(instr_bytes) {
                // Section in which the categorization of the system call is managed
            }
        }
        addr += instr.len() as u64;
    }

    Ok(())
}*/

/*
*
*   ManifestJSON - file generation 
*
*/

pub fn write_manifest_to_json(manifest: &Manifest, json_path: &str) -> Result<()> {
    let manifest_json = serde_json::to_string_pretty(manifest)?;
    let mut file = File::create(json_path)?;
    write!(file, "{}", manifest_json)?;
    Ok(())
}
