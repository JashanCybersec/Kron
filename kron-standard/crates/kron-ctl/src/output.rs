//! Terminal output helpers for `kron-ctl`.
//!
//! Provides plain-text table rendering and status line formatting.
//! Uses no external crates — output is written directly to stdout.

use std::fmt::Write as FmtWrite;

// ─── Status indicators ────────────────────────────────────────────────────────

/// Print a green-ish OK status line.
pub fn ok(label: &str, detail: &str) {
    println!("  [OK]   {label:<24} {detail}");
}

/// Print a FAIL status line.
pub fn fail(label: &str, detail: &str) {
    println!("  [FAIL] {label:<24} {detail}");
}

/// Print a WARN status line.
pub fn warn(label: &str, detail: &str) {
    println!("  [WARN] {label:<24} {detail}");
}

/// Print a section header.
pub fn header(title: &str) {
    println!("\n{title}");
    println!("{}", "─".repeat(title.len()));
}

// ─── Table rendering ─────────────────────────────────────────────────────────

/// A simple ASCII table built from rows of string cells.
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    /// Create a new table with the given column headers.
    #[must_use]
    pub fn new(headers: Vec<&str>) -> Self {
        Self {
            headers: headers.into_iter().map(str::to_owned).collect(),
            rows: Vec::new(),
        }
    }

    /// Append a row to the table.
    pub fn add_row(&mut self, cells: Vec<String>) {
        self.rows.push(cells);
    }

    /// Render the table to stdout.
    pub fn print(&self) {
        // Compute column widths.
        let ncols = self.headers.len();
        let mut widths: Vec<usize> = self.headers.iter().map(|h| h.len()).collect();

        for row in &self.rows {
            for (i, cell) in row.iter().enumerate() {
                if i < ncols {
                    widths[i] = widths[i].max(cell.len());
                }
            }
        }

        // Header row.
        let mut line = String::new();
        for (i, h) in self.headers.iter().enumerate() {
            if i > 0 {
                line.push_str("  ");
            }
            let _ = write!(line, "{h:<width$}", width = widths[i]);
        }
        println!("{line}");

        // Separator.
        let sep: String = widths
            .iter()
            .map(|w| "─".repeat(*w))
            .collect::<Vec<_>>()
            .join("  ");
        println!("{sep}");

        // Data rows.
        for row in &self.rows {
            let mut rline = String::new();
            for (i, cell) in row.iter().enumerate() {
                if i >= ncols {
                    break;
                }
                if i > 0 {
                    rline.push_str("  ");
                }
                // Truncate long values so the table stays readable.
                let display = if cell.len() > widths[i] + 20 {
                    format!("{}…", &cell[..widths[i] + 19])
                } else {
                    cell.clone()
                };
                let _ = write!(rline, "{display:<width$}", width = widths[i]);
            }
            println!("{rline}");
        }

        if self.rows.is_empty() {
            println!("  (no results)");
        }
    }
}
