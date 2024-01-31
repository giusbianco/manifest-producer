use goblin::elf::Elf;

mod error;
use error::Result;

pub fn elf_analysis(file_path: &str) -> Result<()> {
    // Carica il file ELF
    let elf_data = std::fs::read(file_path)?;

    // Effettua il parsing del file ELF
    let elf = Elf::parse(&elf_data)?;

    // Recupera l'architettura dall'header ELF
    let architecture = arch_recovery(&elf);
    println!("Architecture: {}", architecture);

    if is_stripped(&elf) {
        println!("Is Stripped.");
    } else {
        println!("Is not Stripped.");
        api_search(&elf)
    }

    Ok(())
}

// Funzione per il recupero dell'architettura dal file ELF
fn arch_recovery<'a>(elf: &'a Elf<'a>) -> &'a str {
    match elf.header.e_machine {
        goblin::elf::header::EM_X86_64 =>  "x86-64",
        goblin::elf::header::EM_386 =>  "x86",
        goblin::elf::header::EM_XTENSA =>  "Xtensa",
        _ =>  "Unknown",
    }
}

// Verifica la presenza delle sezioni .symtab e .strtab
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
        _ => true, // Non possiamo determinare accuratamente per altre classi ELF
    }
}


/// Verifica la presenza delle sezioni specificate
fn has_sections(elf: &Elf, section_type: u32) -> bool {
    elf.section_headers
        .iter()
        .any(|section| section.sh_type == section_type)
}

/// Funzione per la ricerca di API nella tabella dei simboli
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
        
    // Otteniamo un riferimento alla stringa nella tabella delle stringhe
    let name_str: &'a str = elf.strtab.get_at(name_offset)?;
    
    // Restituisci direttamente il riferimento alla stringa
    return Some(name_str);
}

