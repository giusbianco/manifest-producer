use goblin::elf::Elf;
use std::fs::File;
use std::process::Command;
use std::io::{BufRead, BufReader, Write};
use std::vec;
use serde::Serialize;
use std::collections::HashSet;

mod error;
use error::{Result, Error};

#[derive(Debug, Serialize)]
struct Manifest {
    architecture: String,
    stripped: bool,
    api_found: Option<Vec<String>>,
    syscall_categories: Option<SyscallFeatures>,
}

#[derive(Debug, Serialize)]
struct SyscallFeatures {
    network: Option<HashSet<String>>,
    device: Option<HashSet<String>>,
    disk: Option<HashSet<String>>,
    memory:Option<HashSet<String>>,
}

pub fn elf_analysis(file_path: &str) -> Result<()> {
    // Load the ELF file
    let elf_data = std::fs::read(file_path)?;

    // Parse the ELF file
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
    let mut manifest = Manifest {
        architecture: architecture.to_string(),
        stripped,
        api_found: None,
        syscall_categories: None,
    };

    // If not stripped, search for APIs
    if !stripped {
        manifest.api_found = Some(api_search(&elf));
    }

    // Dynamic analysis with strace
    let syscall_categories = syscall_tracing(file_path);
    manifest.syscall_categories = Some(syscall_categories?);

    // Serialize the manifest to JSON and print it
    let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();

    let json_file_path = "./manifest.json";
    let mut file = File::create(json_file_path)?;
    file.write_all(manifest_json.as_bytes())?;

    Ok(())
}

// Function for retrieving the architecture from the ELF file
fn arch_recovery<'a>(elf: &'a Elf<'a>) -> &'a str {
    match elf.header.e_machine {
        goblin::elf::header::EM_X86_64 =>  "x86-64",
        goblin::elf::header::EM_386 =>  "x86",
        goblin::elf::header::EM_XTENSA =>  "Xtensa",
        _ =>  "Unknown",
    }
}

// Check for the presence of the .symtab and .strtab sections to understand if the file is stripped
fn is_stripped(elf: &Elf) -> bool {
    match elf.header.e_ident[goblin::elf::header::EI_CLASS] {
        goblin::elf::header::ELFCLASS64 => {
            !has_sections(&elf, goblin::elf::section_header::SHT_SYMTAB)
                || !has_sections(&elf, goblin::elf::section_header::SHT_STRTAB)
        }
        goblin::elf::header::ELFCLASS32 => {
            !has_sections(&elf, goblin::elf::section_header::SHT_SYMTAB)
                || !has_sections(&elf, goblin::elf::section_header::SHT_STRTAB)
        }
        _ => true, // We cannot accurately determine for other ELF classes
    }
}

// Check for the presence of the specified sections
fn has_sections(elf: &Elf, section_type: u32) -> bool {
    elf.section_headers
        .iter()
        .any(|section| section.sh_type == section_type)
}

// Function to search for APIs in the symbol table
fn api_search(elf: &Elf) -> Vec<String> {
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

fn get_function_name<'a>(elf: &'a Elf, symbol: &'a goblin::elf::Sym) -> Option<&'a str> {
    let name_offset = symbol.st_name as usize;
        
    // Reference to the string in the string table
    let name_str: &'a str = elf.strtab.get_at(name_offset)?;

    return Some(name_str);
}

fn syscall_tracing(binary_path: &str) -> Result<SyscallFeatures> {

    Command::new("strace")
    .arg("-o")
    .arg("./binaries/strace_output.txt")
    .arg(binary_path)
    .output()?;

    let file = std::fs::File::open("./binaries/strace_output.txt")?;
    let reader = BufReader::new(file);
    let mut syscall_categories = SyscallFeatures {
        network: Some(HashSet::new()),
        device: Some(HashSet::new()),
        disk: Some(HashSet::new()),
        memory: Some(HashSet::new()),
    };

    for line in reader.lines() {
        if let Ok(line) = line {
            if let Some((category, syscall)) = categorize_syscall(&line) {
                match category {
                    "network" => {
                        if let Some(network_category) = &mut syscall_categories.network {
                            network_category.insert(syscall.to_string());
                        }
                    }
                    "device" => {
                        if let Some(device_category) = &mut syscall_categories.device {
                            device_category.insert(syscall.to_string());
                        }
                    }
                    "disk" => {
                        if let Some(disk_category) = &mut syscall_categories.disk {
                            disk_category.insert(syscall.to_string());
                        }
                    }
                    "memory" => {
                        if let Some(mem_category) = &mut syscall_categories.memory {
                            mem_category.insert(syscall.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(syscall_categories)
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
        Some(("device", "I/O control"))
    } else if syscall.contains("mmap") {
        Some(("memory", "access_memory"))
    } else {
        None
    }
}

