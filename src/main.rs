use manifest_producer::elf_analysis;
mod error;

fn main() {
    let elf_file_path = "./binaries/debug-info/fake-firmware-c";
    //let elf_file_path = "./binaries/stripped/fake-firmware-c";

    match elf_analysis(elf_file_path) {
        Ok(_) => {
            println!("Manifest created.");
            println!("End of binary analysis.");
        }
        Err(error) => {
            eprintln!("Error: {}", error);
        }
    }
}

