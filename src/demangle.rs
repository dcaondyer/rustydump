use cpp_demangle::Symbol as CppSymbol;
use rustc_demangle::demangle as rust_demangle;

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub enum DemangleStyle {
    #[default]
    None, // sub_XXXXXXXX
    Auto, // -C  → prova Rust, poi C++, poi raw
    Rust, // --demangle=rust
    Cpp,  // --demangle=cpp
}

impl std::str::FromStr for DemangleStyle {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "rust" => Ok(Self::Rust),
            "cpp" | "c++" => Ok(Self::Cpp),
            "" | "none" => Ok(Self::None),
            other => Err(format!("unknown style '{other}'. Values: auto, rust, cpp")),
        }
    }
}

/// Entry point principale: dato un nome simbolo e lo stile, restituisce
/// la stringa demangled oppure "sub_XXXXXXXX" se il simbolo è sconosciuto.
pub fn demangle_symbol(name: &str, addr: u64, style: DemangleStyle) -> String {
    match style {
        DemangleStyle::None => format!("sub_{addr:08X}"),
        DemangleStyle::Rust => try_rust(name).unwrap_or_else(|| format!("sub_{addr:08X}")),
        DemangleStyle::Cpp => try_cpp(name).unwrap_or_else(|| format!("sub_{addr:08X}")),
        DemangleStyle::Auto => try_rust(name)
            .or_else(|| try_cpp(name))
            .unwrap_or_else(|| format!("sub_{addr:08X}")),
    }
}

/// Restituisce Some(demangled) solo se il nome era effettivamente mangled,
/// None se era già leggibile o non riconoscibile.
pub fn try_demangle(name: &str, style: DemangleStyle) -> Option<String> {
    match style {
        DemangleStyle::None => None,
        DemangleStyle::Rust => try_rust(name),
        DemangleStyle::Cpp => try_cpp(name),
        DemangleStyle::Auto => try_rust(name).or_else(|| try_cpp(name)),
    }
}

fn try_rust(name: &str) -> Option<String> {
    // rustc-demangle restituisce sempre qualcosa, ma se non è mangled
    // la rappresentazione Debug contiene il nome originale invariato.
    // Usiamo questo per discriminare.
    let demangled = rust_demangle(name);
    let demangled = format!("{demangled:#}"); // # = no hash finale
    if demangled != name {
        Some(demangled)
    } else {
        None
    }
}

fn try_cpp(name: &str) -> Option<String> {
    let sym = CppSymbol::new(name).ok()?;
    let demangled = sym.demangle().ok()?;
    if demangled != name && !demangled.is_empty() {
        Some(demangled)
    } else {
        None
    }
}
