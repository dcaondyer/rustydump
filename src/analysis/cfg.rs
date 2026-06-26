use crate::analysis::basic_block::BasicBlock;
use crate::decode::{Flow, InstIR};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as FmtWrite;

pub struct CFG {
    pub blocks: Vec<BasicBlock>,
    pub addr_to_block: HashMap<u64, usize>,
    pub entry: usize,
}

impl CFG {
    /// Costruisce il CFG a partire dalla lista piatta di istruzioni
    /// già decodificate e sollevate in InstIR
    pub fn build(instructions: Vec<InstIR>) -> Self {
        if instructions.is_empty() {
            return Self {
                blocks: Vec::new(),
                addr_to_block: HashMap::new(),
                entry: 0,
            };
        }

        // Passo 1: identifica i leader
        // Un leader è:
        // - la prima istruzione
        // - il target di un salto (condizionale o incondizionale)
        // - l'istruzione immediatamente dopo un salto/call/ret
        let mut leaders: HashSet<u64> = HashSet::new();
        leaders.insert(instructions[0].addr);

        for (i, instr) in instructions.iter().enumerate() {
            match &instr.flow {
                Flow::Jump(target) => {
                    leaders.insert(*target);
                    // L'istruzione dopo è irraggiungibile ma la marchiamo
                    // comunque per sicurezza (potrebbe essere target di altro)
                    if let Some(next) = instructions.get(i + 1) {
                        leaders.insert(next.addr);
                    }
                }
                Flow::Conditional(target, fallthrough) => {
                    leaders.insert(*target);
                    leaders.insert(*fallthrough);
                }
                Flow::Call(target) => {
                    // Il target della call è entry di un'altra funzione,
                    // non splittiamo il blocco corrente per le call —
                    // ma il return address (istruzione dopo) è un leader
                    leaders.insert(*target);
                    if let Some(next) = instructions.get(i + 1) {
                        leaders.insert(next.addr);
                    }
                }
                Flow::Return => {
                    if let Some(next) = instructions.get(i + 1) {
                        leaders.insert(next.addr);
                    }
                }
                Flow::Next => {}
            }
        }

        // Passo 2: partiziona le istruzioni in blocchi base
        let mut blocks: Vec<BasicBlock> = Vec::new();
        let mut addr_to_block: HashMap<u64, usize> = HashMap::new();
        let mut current_block = BasicBlock::new(0, instructions[0].addr);

        for instr in instructions {
            // Se questa istruzione è un leader e non è la prima del blocco
            // corrente, chiudi il blocco e aprine uno nuovo
            if leaders.contains(&instr.addr) && !current_block.is_empty() {
                let id = blocks.len();
                current_block.end_addr = instr.addr;
                addr_to_block.insert(current_block.addr, id);
                blocks.push(current_block);
                current_block = BasicBlock::new(id + 1, instr.addr);
            }

            let next_addr = instr.addr + instr.size as u64;
            current_block.end_addr = next_addr;
            current_block.instructions.push(instr);
        }

        // Chiudi l'ultimo blocco
        if !current_block.is_empty() {
            let id = blocks.len();
            addr_to_block.insert(current_block.addr, id);
            blocks.push(current_block);
        }

        // Passo 3: collega i blocchi (edges del CFG)
        // Prima raccogliamo tutti gli edge da aggiungere
        let edges: Vec<(usize, usize)> = blocks
            .iter()
            .filter_map(|block| {
                let term = block.terminator()?;
                let from = block.id;
                match &term.flow {
                    Flow::Next => {
                        // Fallthrough al blocco successivo
                        let next_addr = term.addr + term.size as u64;
                        let to = *addr_to_block.get(&next_addr)?;
                        Some(vec![(from, to)])
                    }
                    Flow::Jump(target) => {
                        let to = *addr_to_block.get(target)?;
                        Some(vec![(from, to)])
                    }
                    Flow::Conditional(target, fallthrough) => {
                        let mut edges = Vec::new();
                        if let Some(&to) = addr_to_block.get(target) {
                            edges.push((from, to));
                        }
                        if let Some(&to) = addr_to_block.get(fallthrough) {
                            edges.push((from, to));
                        }
                        Some(edges)
                    }
                    Flow::Call(_) => {
                        // Collega al return address (istruzione dopo la call)
                        let next_addr = term.addr + term.size as u64;
                        let to = *addr_to_block.get(&next_addr)?;
                        Some(vec![(from, to)])
                    }
                    Flow::Return => None, // nessun successore nel CFG locale
                }
            })
            .flatten()
            .collect();

        // Applica gli edge
        for (from, to) in edges {
            blocks[from].successors.push(to);
            blocks[to].predecessors.push(from);
        }

        let entry = *addr_to_block.get(&blocks[0].addr).unwrap_or(&0);

        Self {
            blocks,
            addr_to_block,
            entry,
        }
    }

    /// Analisi del CFG
    /// Visita in ampiezza (BFS) a partire dall'entry point
    pub fn bfs(&self) -> Vec<usize> {
        let mut visited = vec![false; self.blocks.len()];
        let mut order = Vec::new();
        let mut queue = VecDeque::new();

        queue.push_back(self.entry);
        visited[self.entry] = true;

        while let Some(id) = queue.pop_front() {
            order.push(id);
            for &succ in &self.blocks[id].successors {
                if !visited[succ] {
                    visited[succ] = true;
                    queue.push_back(succ);
                }
            }
        }
        order
    }

    /// Visita in profondità (DFS) — utile per rilevare back-edge (loop)
    pub fn dfs(&self) -> Vec<usize> {
        let mut visited = vec![false; self.blocks.len()];
        let mut order = Vec::new();
        self.dfs_visit(self.entry, &mut visited, &mut order);
        order
    }

    fn dfs_visit(&self, id: usize, visited: &mut Vec<bool>, order: &mut Vec<usize>) {
        if visited[id] {
            return;
        }
        visited[id] = true;
        order.push(id);
        for &succ in &self.blocks[id].successors {
            self.dfs_visit(succ, visited, order);
        }
    }

    /// Rileva i back-edge (A → B dove B è antenato di A nel DFS tree)
    /// Ogni back-edge indica un loop nel CFG
    pub fn back_edges(&self) -> Vec<(usize, usize)> {
        let mut visited = vec![false; self.blocks.len()];
        let mut in_stack = vec![false; self.blocks.len()];
        let mut result = Vec::new();
        self.find_back_edges(self.entry, &mut visited, &mut in_stack, &mut result);
        result
    }

    fn find_back_edges(
        &self,
        id: usize,
        visited: &mut Vec<bool>,
        in_stack: &mut Vec<bool>,
        result: &mut Vec<(usize, usize)>,
    ) {
        visited[id] = true;
        in_stack[id] = true;

        for &succ in &self.blocks[id].successors {
            if !visited[succ] {
                self.find_back_edges(succ, visited, in_stack, result);
            } else if in_stack[succ] {
                result.push((id, succ)); // back-edge trovato
            }
        }

        in_stack[id] = false;
    }

    /// Blocchi raggiungibili dall'entry (esclude dead code)
    pub fn reachable_blocks(&self) -> HashSet<usize> {
        self.bfs().into_iter().collect()
    }

    /// Blocchi non raggiungibili (dead code)
    pub fn dead_blocks(&self) -> Vec<usize> {
        let reachable = self.reachable_blocks();
        (0..self.blocks.len())
            .filter(|id| !reachable.contains(id))
            .collect()
    }

    /// Stampa
    pub fn print(&self) {
        for block in &self.blocks {
            println!(
                "Block #{} @ 0x{:x}..0x{:x}  ({} instrs)",
                block.id,
                block.addr,
                block.end_addr,
                block.instructions.len()
            );
            if !block.predecessors.is_empty() {
                println!("  preds: {:?}", block.predecessors);
            }
            if !block.successors.is_empty() {
                println!("  succs: {:?}", block.successors);
            }
            for instr in &block.instructions {
                println!("    0x{:x}  [{:?}]", instr.addr, instr.op);
            }
            println!();
        }

        let back = self.back_edges();
        if !back.is_empty() {
            println!("Back-edges (loop headers):");
            for (from, to) in &back {
                println!(
                    "  Block #{} → Block #{} (0x{:x})",
                    from, to, self.blocks[*to].addr
                );
            }
        }

        let dead = self.dead_blocks();
        if !dead.is_empty() {
            println!("Dead blocks: {:?}", dead);
        }
    }

    pub fn to_dot(&self, graph_name: &str) -> String {
        let mut out = String::new();

        // Sanitizza il nome per DOT (no caratteri speciali)
        let safe_name = graph_name.replace(['.', '/', '-'], "_");

        writeln!(out, "digraph {} {{", safe_name).unwrap();
        writeln!(out, "    graph [fontname=\"monospace\" rankdir=TB];").unwrap();
        writeln!(
            out,
            "    node  [fontname=\"monospace\" shape=box style=filled];"
        )
        .unwrap();
        writeln!(out, "    edge  [fontname=\"monospace\"];").unwrap();
        writeln!(out).unwrap();

        let back_edges: std::collections::HashSet<(usize, usize)> =
            self.back_edges().into_iter().collect();
        let dead = self.reachable_blocks();

        // Nodi
        for block in &self.blocks {
            let is_dead = !dead.contains(&block.id);
            let is_entry = block.id == self.entry;
            let is_returning = block
                .terminator()
                .map_or(false, |t| matches!(t.flow, crate::decode::Flow::Return));

            // Colore nodo
            let fillcolor = if is_entry {
                "#cce5ff"
            }
            // blu chiaro
            else if is_returning {
                "#d4edda"
            }
            // verde chiaro
            else if is_dead {
                "#f8d7da"
            }
            // rosso chiaro
            else {
                "#ffffff"
            };

            // Label: indirizzo + istruzioni
            let label = self.block_label(block);

            writeln!(
                out,
                "    b{} [label=\"{}\" fillcolor=\"{}\" {}];",
                block.id,
                label,
                fillcolor,
                if is_entry { "penwidth=2" } else { "" },
            )
            .unwrap();
        }

        writeln!(out).unwrap();

        // Edge
        for block in &self.blocks {
            for &succ in &block.successors {
                let is_back = back_edges.contains(&(block.id, succ));

                // Per i condizionali, distingui true/false branch
                let edge_label = self.edge_label(block, succ);

                writeln!(
                    out,
                    "    b{} -> b{} [label=\"{}\" color=\"{}\" {}];",
                    block.id,
                    succ,
                    edge_label,
                    if is_back { "red" } else { "black" },
                    if is_back {
                        "style=dashed constraint=false"
                    } else {
                        ""
                    },
                )
                .unwrap();
            }
        }

        writeln!(out, "}}").unwrap();
        out
    }

    fn block_label(&self, block: &BasicBlock) -> String {
        let mut label = String::new();

        // Header del blocco
        write!(
            label,
            "Block #{}\\n0x{:x}..0x{:x}\\n",
            block.id, block.addr, block.end_addr
        )
        .unwrap();

        // Istruzioni (max 12 per non appesantire il grafo)
        let shown = block.instructions.iter().take(12);
        for instr in shown {
            write!(label, "0x{:x}  {:?}\\n", instr.addr, instr.op).unwrap();
        }
        if block.instructions.len() > 12 {
            write!(label, "... ({} more)\\n", block.instructions.len() - 12).unwrap();
        }

        // Escape delle virgolette per DOT
        label.replace('"', "\\\"")
    }

    fn edge_label(&self, from: &BasicBlock, to_id: usize) -> &'static str {
        if let Some(term) = from.terminator() {
            if let crate::decode::Flow::Conditional(target, fallthrough) = &term.flow {
                let to_addr = self.blocks[to_id].addr;
                if to_addr == *target {
                    return "T";
                }
                if to_addr == *fallthrough {
                    return "F";
                }
            }
        }
        ""
    }
}
