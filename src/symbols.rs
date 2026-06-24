use goblin::mach::Mach;
use goblin::Object;
use std::collections::HashMap;

/// Mappa indirizzo virtuale → nome simbolo grezzo (non demangled)
pub type SymbolMap = HashMap<u64, String>;

pub fn build_symbol_map(bytes: &[u8]) -> SymbolMap {
    let mut map = HashMap::new();

    match Object::parse(bytes) {
        Ok(Object::Elf(elf)) => {
            for sym in elf.syms.iter().chain(elf.dynsyms.iter()) {
                if sym.st_value == 0 {
                    continue;
                }
                let name = elf
                    .strtab
                    .get_at(sym.st_name)
                    .or_else(|| elf.dynstrtab.get_at(sym.st_name))
                    .unwrap_or("")
                    .to_string();
                if !name.is_empty() {
                    map.insert(sym.st_value, name);
                }
            }
        }
        Ok(Object::PE(pe)) => {
            // Simboli statici — export della DLL/EXE
            for export in &pe.exports {
                if let Some(name) = export.name {
                    let addr = export.rva as u64 + pe.image_base as u64;
                    map.insert(addr, name.to_string());
                }
            }

            // Simboli dinamici — import dalle DLL esterne
            for import in &pe.imports {
                let addr = import.rva as u64 + pe.image_base as u64;
                // Formato "DllName.dll!FunctionName" come IDA Pro
                let name = format!("{}!{}", import.dll, import.name);
                map.insert(addr, name);
            }
        }
        Ok(Object::Mach(mach)) => {
            if let Mach::Binary(m) = mach {
                // Symbol table (nlist)
                if let Some(symbols) = &m.symbols {
                    for res in symbols.into_iter() {
                        if let Ok((name, nlist)) = res {
                            if nlist.n_value != 0 && !name.is_empty() {
                                map.insert(nlist.n_value, name.to_string());
                            }
                        }
                    }
                }

                // Export trie — più affidabile per i simboli dinamici
                if let Ok(exports) = m.exports() {
                    for export in exports {
                        if export.size != 0 {
                            map.insert(export.offset, export.name.to_string());
                        }
                    }
                }

                // Import — simboli dinamici da librerie esterne
                if let Ok(imports) = m.imports() {
                    for import in imports {
                        let name = format!("{}!{}", import.dylib, import.name);
                        map.insert(import.address, name);
                    }
                }
            }
        }
        _ => {}
    }

    map
}
