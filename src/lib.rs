use goblin::elf::Elf;
use std::fs::File;
use std::process::Command;
use std::io::{BufRead, BufReader, Read, Write};
use std::vec;
use serde::Serialize;
use std::collections::HashSet;
use libc::c_int;

mod error;
use error::{Result, Error};

#[derive(Debug, Serialize)]
struct Manifest {
    architecture: String,
    stripped: bool,
    api_found: Option<Vec<String>>,
    syscall_features: Option<SyscallFeatures>,
}

#[derive(Debug, Serialize)]
struct SyscallFeatures {
    network: Option<HashSet<String>>,
    device: Option<HashSet<String>>,
    disk: Option<HashSet<String>>,
    memory:Option<HashSet<String>>,
}

pub fn elf_analysis(file_path: &str) -> Result<()> {
    let elf_data = std::fs::read(file_path)?;
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
        syscall_features: None,
    };

    // If not stripped, search for APIs
    if !stripped {
        manifest.api_found = Some(api_search(&elf));
    }

    // Dynamic analysis with strace
    let syscall_categories = syscall_tracing(file_path)?;
    manifest.syscall_features = Some(syscall_categories);

    // Static analysis with the mapping table
    /*let mut file = File::open(&file_path)?;
        // Leggi il contenuto del file ELF
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let syscall_categories = syscall_mapping_table(&elf, elf_data.clone())?;
    manifest.syscall_features = Some(syscall_categories);*/


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
        Some(("device", "I/O_control"))
    } else if syscall.contains("mmap") {
        Some(("memory", "access_memory"))
    } else {
        None
    }
}

/*fn syscall_mapping_table(elf: &Elf, buffer: Vec<u8>) -> Result<SyscallFeatures> {

    let mut syscall_categories = SyscallFeatures {
        network: Some(HashSet::new()),
        device: Some(HashSet::new()),
        disk: Some(HashSet::new()),
        memory: Some(HashSet::new()),
    };
    
    // Trova la sezione delle chiamate di sistema
    let syscalls_section = elf
        .section_headers
        .iter()
        .find(|section| {
            if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                name == ".text"
            } else {
                false
            }
        })
        .expect("Failed to find syscall section");

     // Accedi ai dati della sezione delle chiamate di sistema
    let syscalls_data = &buffer[syscalls_section.sh_offset as usize
        ..(syscalls_section.sh_offset + syscalls_section.sh_size) as usize];

    // Definisci una tabella di mapping tra numeri e nomi di chiamate di sistema
    let syscall_names: Vec<(&str, c_int)> = vec![
        ("sys_write", libc::SYS_write.try_into().unwrap()),
        ("sys_sendto", libc::SYS_sendto.try_into().unwrap()),
        ("sys_ioctl", libc::SYS_ioctl.try_into().unwrap()),
        ("sys_recvfrom", libc::SYS_recvfrom.try_into().unwrap()),
        ("sys_socket", libc::SYS_socket.try_into().unwrap()),
        ("sys_connect", libc::SYS_connect.try_into().unwrap()),
        ("sys_fsync", libc::SYS_fsync.try_into().unwrap()),
        ("sys_mmap", libc::SYS_mmap.try_into().unwrap())
        // Aggiungi altre chiamate di sistema secondo necessità
    ];      

    for syscall_entry in syscalls_data.chunks_exact(4) {
        let syscall_number = u32::from_le_bytes([
            syscall_entry[0],
            syscall_entry[1],
            syscall_entry[2],
            syscall_entry[3],
        ]);

        // Cerca il nome della chiamata di sistema nella tabella
        if let Some(syscall_name) = syscall_names.iter().find(|(_, num)| *num == syscall_number as c_int) {
            // Popolare syscall_categories qui
            match syscall_name.0 {
                "sys_write" | "sys_fsync" => {
                    if let Some(disk_category) = &mut syscall_categories.disk {
                        disk_category.insert("access_disk".to_string());
                    }
                }
                "sys_sendto" | "sys_recvfrom" | "sys_socket" | "sys_connect" => {
                    if let Some(network_category) = &mut syscall_categories.network {
                        network_category.insert(syscall_name.0.to_string());
                    }
                }
                "I/sys_ioctl" => {
                    if let Some(device_category) = &mut syscall_categories.device {
                        device_category.insert("I/O_control".to_string());
                    }
                }
                "sys_mmap" => {
                    if let Some(memory_category) = &mut syscall_categories.memory {
                        memory_category.insert("access_memory".to_string());
                    }
                }
                _ => {}
            }
        }
    }

    Ok(syscall_categories)
}*/
