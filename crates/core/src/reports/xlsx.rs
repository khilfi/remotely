//! FD-05: the inventory's sheets as an Excel workbook (`rust_xlsxwriter`). Text cells are written with
//! `write_string`, so a name like `=HYPERLINK(...)` or `+1` is a string in the file, never a formula (the tests read
//! the workbook's XML back: no `<f>` element anywhere). Each sheet has a bold header row that stays in view, a filter
//! on its columns and set widths. The workbook names no author.

use rust_xlsxwriter::{DocProperties, Format, Workbook, XlsxError};

use super::table::{Cell, Sheet};
use crate::error::{CoreError, Result};

/// Rows a sheet takes at most, below Excel's 1,048,576 (the header row is one more).
pub const MAX_ROWS: usize = 1_000_000;

fn xlsx_error(err: XlsxError) -> CoreError {
    CoreError::InvalidInput(format!("the Excel file could not be made: {err}"))
}

/// The workbook's bytes: one worksheet per sheet, in order. `title` goes in the file's properties.
pub fn workbook(title: &str, sheets: &[&Sheet]) -> Result<Vec<u8>> {
    let mut book = Workbook::new();
    book.set_properties(&DocProperties::new().set_title(super::table::clean(title)));
    let bold = Format::new().set_bold();
    for sheet in sheets {
        let ws = book.add_worksheet();
        ws.set_name(sheet.title).map_err(xlsx_error)?;
        for (c, column) in sheet.columns.iter().enumerate() {
            let c = u16::try_from(c).map_err(|_| CoreError::InvalidInput("too many columns".into()))?;
            ws.write_string_with_format(0, c, column.title, &bold)
                .map_err(xlsx_error)?;
            ws.set_column_width(c, column.width).map_err(xlsx_error)?;
        }
        let mut last_row = 0u32;
        for (r, row) in sheet.rows.iter().take(MAX_ROWS).enumerate() {
            let r = u32::try_from(r + 1).map_err(|_| CoreError::InvalidInput("too many rows".into()))?;
            last_row = r;
            for (c, cell) in row.iter().enumerate() {
                let c = u16::try_from(c).map_err(|_| CoreError::InvalidInput("too many columns".into()))?;
                match cell {
                    Cell::Text(text) => {
                        ws.write_string(r, c, text.as_str()).map_err(xlsx_error)?;
                    }
                    Cell::Int(n) => {
                        // An f64 holds every whole number up to 2^53 exactly; larger ones go in as text.
                        if n.unsigned_abs() < (1u64 << 53) {
                            #[allow(clippy::cast_precision_loss)]
                            ws.write_number(r, c, *n as f64).map_err(xlsx_error)?;
                        } else {
                            ws.write_string(r, c, n.to_string()).map_err(xlsx_error)?;
                        }
                    }
                    Cell::Number(n) => {
                        ws.write_number(r, c, *n).map_err(xlsx_error)?;
                    }
                    Cell::Empty => {}
                }
            }
        }
        if let Some(last_col) = sheet.columns.len().checked_sub(1) {
            let last_col = u16::try_from(last_col).map_err(|_| CoreError::InvalidInput("too many columns".into()))?;
            ws.set_freeze_panes(1, 0).map_err(xlsx_error)?;
            ws.autofilter(0, 0, last_row, last_col).map_err(xlsx_error)?;
        }
    }
    book.save_to_buffer().map_err(xlsx_error)
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::super::table::col;
    use super::*;

    /// Every member's text, by name.
    pub(crate) fn members(bytes: &[u8]) -> Vec<(String, String)> {
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        (0..zip.len())
            .map(|i| {
                let mut file = zip.by_index(i).unwrap();
                let mut text = String::new();
                let _ = file.read_to_string(&mut text);
                (file.name().map(|n| n.into_owned()).unwrap_or_default(), text)
            })
            .collect()
    }

    #[test]
    fn text_that_looks_like_a_formula_stays_text() {
        let mut sheet = Sheet::new("vms", "VMs", &[col("Name", 20.0), col("vCPU", 6.0)]);
        for name in [
            "=HYPERLINK(\"http://example.com\",\"x\")",
            "+1",
            "-2",
            "@SUM(A1)",
            "=1+1",
        ] {
            sheet.push(vec![Cell::text(name), Cell::int(2)]);
        }
        let bytes = workbook("Inventory", &[&sheet]).unwrap();
        let files = members(&bytes);
        let sheet_xml = &files.iter().find(|(n, _)| n == "xl/worksheets/sheet1.xml").unwrap().1;
        assert!(!sheet_xml.contains("<f>") && !sheet_xml.contains("<f "), "{sheet_xml}");
        assert!(sheet_xml.contains("t=\"s\""), "text cells are shared strings");
        let strings = &files.iter().find(|(n, _)| n == "xl/sharedStrings.xml").unwrap().1;
        assert!(
            strings.contains("=HYPERLINK(&quot;http://example.com&quot;,&quot;x&quot;)")
                || strings.contains("=HYPERLINK(\"http://example.com\",\"x\")"),
            "{strings}"
        );
        assert!(strings.contains(">+1<") && strings.contains(">@SUM(A1)<"), "{strings}");
        assert!(files.iter().all(|(_, text)| !text.contains("<f>")));
    }

    #[test]
    fn sheets_are_named_with_a_header_and_numbers_are_numbers() {
        let mut a = Sheet::new("vms", "VMs", &[col("Name", 20.0), col("RAM (GB)", 8.0)]);
        a.push(vec![Cell::text("web01"), Cell::number(8.0)]);
        let b = Sheet::new("hosts", "Hosts", &[col("Name", 20.0)]);
        let files = members(&workbook("Inventory", &[&a, &b]).unwrap());
        let book = &files.iter().find(|(n, _)| n == "xl/workbook.xml").unwrap().1;
        assert!(
            book.contains("name=\"VMs\"") && book.contains("name=\"Hosts\""),
            "{book}"
        );
        let sheet = &files.iter().find(|(n, _)| n == "xl/worksheets/sheet1.xml").unwrap().1;
        assert!(sheet.contains("<v>8</v>"), "{sheet}");
        assert!(sheet.contains("autoFilter"), "{sheet}");
        let core = &files.iter().find(|(n, _)| n == "docProps/core.xml").unwrap().1;
        assert!(
            !core.contains("<dc:creator>") || core.contains("<dc:creator></dc:creator>"),
            "{core}"
        );
    }
}
