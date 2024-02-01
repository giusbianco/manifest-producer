use goblin::elf::Elf;
use std::process::Command;
use std::io::{BufReader, BufRead};

mod error;
use error::Result;

pub fn elf_analysis(file_path: &str) -> Result<()> {
    // Load the ELF file
    let elf_data = std::fs::read(file_path)?;

    // Parse the ELF file
    let elf = Elf::parse(&elf_data)?;

    // Retrieve the architecture from the ELF header
    let architecture = arch_recovery(&elf);
    println!("Architecture: {}", architecture);
    // TODO: handle return if 'unknown'

    if !is_stripped(&elf) {
        api_search(&elf)
    }

    syscall_tracing(file_path);

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
fn api_search(elf: &Elf) {
    let api_list = vec!["turnLampOn", "turnLampOff"];

    for symbol in elf.syms.iter() {
        if symbol.st_type() == goblin::elf::sym::STT_FUNC 
        && symbol.st_shndx != 0 
        {
            if let Some(function_name) = get_function_name(&elf, &symbol) {
                if api_list.contains(&function_name) {
                    println!("API [{}] found!", function_name);
                }
            }
        }
    }
}

fn get_function_name<'a>(elf: &'a Elf, symbol: &'a goblin::elf::Sym) -> Option<&'a str> {
    let name_offset = symbol.st_name as usize;
        
    // Reference to the string in the string table
    let name_str: &'a str = elf.strtab.get_at(name_offset)?;
    
    // Return the string reference directly
    return Some(name_str);
}

fn syscall_tracing(binary_path: &str) {

    let output = Command::new("strace")
    .arg("-o")
    .arg("./binaries/strace_output.txt")
    .arg(binary_path)
    .output()
    .expect("Failed to execute strace");

    if !output.status.success() {
        println!("Error executing strace");
        return;
    }

    let file = std::fs::File::open("./binaries/strace_output.txt").expect("Failed to open strace output file");
    let reader = BufReader::new(file);

    for line in reader.lines() {
        if let Ok(line) = line {
            if let Some(category) = categorize_syscall(&line) {
                println!("Categoria: {},", category);
            }
        }
    }
}

fn categorize_syscall(syscall: &str) -> Option<&str> {
    if syscall.contains("write") {
        Some("Scrittura su disco")
    } else if syscall.contains("connect") || syscall.contains("sendto") || syscall.contains("recvfrom") {
        Some("Accesso alla rete")
    } else if syscall.contains("ioctl") || syscall.contains("read") {
        Some("Accesso ai driver di dispositivo")
    } else {
        None
    }
}

