use csv::{ReaderBuilder, WriterBuilder};
use lsdc_common::crypto::Sha256Hash;
use lsdc_common::error::{LsdcError, Result};
use lsdc_common::liquid::{CsvTransformManifest, CsvTransformOp};
use std::collections::HashMap;

#[derive(Clone)]
struct CsvTable {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

pub fn apply_manifest(input_csv: &[u8], manifest: &CsvTransformManifest) -> Result<Vec<u8>> {
    let mut table = parse_csv(input_csv)?;

    for op in &manifest.ops {
        table = match op {
            CsvTransformOp::DropColumns { columns } => drop_columns(table, columns),
            CsvTransformOp::RedactColumns {
                columns,
                replacement,
            } => redact_columns(table, columns, replacement)?,
            CsvTransformOp::HashColumns { columns, salt } => {
                hash_columns(table, columns, salt)?
            }
            CsvTransformOp::RowFilter { column, equals } => row_filter(table, column, equals)?,
        };
    }

    write_csv(&table)
}

fn parse_csv(input_csv: &[u8]) -> Result<CsvTable> {
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .from_reader(input_csv);
    let headers = reader
        .headers()
        .map_err(csv_error)?
        .iter()
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let mut rows = Vec::new();
    for record in reader.records() {
        let record = record.map_err(csv_error)?;
        rows.push(record.iter().map(ToOwned::to_owned).collect());
    }
    Ok(CsvTable { headers, rows })
}

fn write_csv(table: &CsvTable) -> Result<Vec<u8>> {
    let mut writer = WriterBuilder::new().from_writer(Vec::new());
    writer.write_record(&table.headers).map_err(csv_error)?;
    for row in &table.rows {
        writer.write_record(row).map_err(csv_error)?;
    }
    writer
        .into_inner()
        .map_err(|err| csv_error(err.into_error().into()))
}

fn drop_columns(mut table: CsvTable, columns: &[String]) -> CsvTable {
    let keep_indices: Vec<usize> = table
        .headers
        .iter()
        .enumerate()
        .filter_map(|(index, header)| (!columns.iter().any(|column| column == header)).then_some(index))
        .collect();

    table.headers = keep_indices
        .iter()
        .map(|index| table.headers[*index].clone())
        .collect();
    table.rows = table
        .rows
        .into_iter()
        .map(|row| keep_indices.iter().map(|index| row[*index].clone()).collect())
        .collect();
    table
}

fn redact_columns(mut table: CsvTable, columns: &[String], replacement: &str) -> Result<CsvTable> {
    let indices = find_indices(&table.headers, columns)?;
    for row in &mut table.rows {
        for index in &indices {
            row[*index] = replacement.to_string();
        }
    }
    Ok(table)
}

fn hash_columns(mut table: CsvTable, columns: &[String], salt: &str) -> Result<CsvTable> {
    let indices = find_indices(&table.headers, columns)?;
    for row in &mut table.rows {
        for index in &indices {
            let value = format!("{salt}:{}", row[*index]);
            row[*index] = Sha256Hash::digest_bytes(value.as_bytes()).to_hex();
        }
    }
    Ok(table)
}

fn row_filter(mut table: CsvTable, column: &str, equals: &str) -> Result<CsvTable> {
    let indices = header_index_map(&table.headers);
    let Some(column_index) = indices.get(column).copied() else {
        return Err(LsdcError::ProofGeneration(format!(
            "missing filter column `{column}` in CSV input"
        )));
    };

    table.rows.retain(|row| row.get(column_index).is_some_and(|value| value == equals));
    Ok(table)
}

fn find_indices(headers: &[String], columns: &[String]) -> Result<Vec<usize>> {
    let index_map = header_index_map(headers);
    columns
        .iter()
        .map(|column| {
            index_map.get(column).copied().ok_or_else(|| {
                LsdcError::ProofGeneration(format!("missing column `{column}` in CSV input"))
            })
        })
        .collect()
}

fn header_index_map(headers: &[String]) -> HashMap<String, usize> {
    headers
        .iter()
        .enumerate()
        .map(|(index, header)| (header.clone(), index))
        .collect()
}

fn csv_error(err: csv::Error) -> LsdcError {
    LsdcError::ProofGeneration(format!("CSV transform failed: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsdc_common::liquid::{CsvTransformManifest, CsvTransformOp};

    #[test]
    fn test_apply_manifest() {
        let input = b"id,name,region\n1,Alice,EU\n2,Bob,US\n";
        let manifest = CsvTransformManifest {
            dataset_id: "dataset-1".into(),
            purpose: "analytics".into(),
            ops: vec![
                CsvTransformOp::RowFilter {
                    column: "region".into(),
                    equals: "EU".into(),
                },
                CsvTransformOp::RedactColumns {
                    columns: vec!["name".into()],
                    replacement: "***".into(),
                },
            ],
        };

        let output = apply_manifest(input, &manifest).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("***"));
        assert!(!output.contains("Bob"));
    }
}
