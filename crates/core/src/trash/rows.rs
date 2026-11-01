//! QL-27: table rows as JSON, column by column, so the trash keeps exactly what a deleted item's rows held (columns a
//! later version adds included) and puts it back the same way.
//!
//! A value is JSON null, an integer, a real, a string, or `{"blob": "<base64>"}`. Only the tables in [`TABLES`] are read
//! or written, and a restore writes only the columns the table has now (a column dropped since is left out; one added
//! since takes its default), each name quoted, so nothing in a snapshot can change the statement.

use base64::Engine as _;
use serde_json::{Map, Value};
use sqlx::sqlite::SqliteRow;
use sqlx::{Column, Row, SqliteConnection, TypeInfo, ValueRef};

use crate::error::{CoreError, Result};

/// One row: column name to value.
pub type RowValues = Map<String, Value>;

/// The tables the trash snapshots and restores.
pub const TABLES: [&str; 11] = [
    "sessions",
    "port_forwards",
    "container_hosts",
    "multiexec_group_members",
    "session_secret_grants",
    "command_favourites",
    "catalog_sizes",
    "catalog_images",
    "catalog_templates",
    "stacks",
    "notes",
];

fn known(table: &str) -> Result<&'static str> {
    TABLES
        .iter()
        .find(|t| **t == table)
        .copied()
        .ok_or_else(|| CoreError::InvalidInput(format!("the trash doesn't keep rows of {table}")))
}

/// Every column of `row` as JSON.
pub fn to_json(row: &SqliteRow) -> Result<RowValues> {
    let mut out = Map::new();
    for (i, column) in row.columns().iter().enumerate() {
        let raw = row.try_get_raw(i)?;
        let value = if raw.is_null() {
            Value::Null
        } else {
            let kind = raw.type_info().name().to_ascii_uppercase();
            match kind.as_str() {
                "INTEGER" | "BOOLEAN" | "INT" | "BIGINT" => Value::from(row.try_get_unchecked::<i64, _>(i)?),
                "REAL" | "FLOAT" | "DOUBLE" | "NUMERIC" => {
                    let real: f64 = row.try_get_unchecked(i)?;
                    serde_json::Number::from_f64(real).map_or(Value::Null, Value::Number)
                }
                "BLOB" => {
                    let bytes: Vec<u8> = row.try_get_unchecked(i)?;
                    let mut blob = Map::new();
                    blob.insert(
                        "blob".into(),
                        Value::String(base64::engine::general_purpose::STANDARD.encode(bytes)),
                    );
                    Value::Object(blob)
                }
                _ => Value::String(row.try_get_unchecked::<String, _>(i)?),
            }
        };
        out.insert(column.name().to_owned(), value);
    }
    Ok(out)
}

/// The rows of `table` whose `column` is `value` in the workspace, as JSON.
pub async fn read(
    conn: &mut SqliteConnection,
    table: &str,
    column: &str,
    value: &str,
    workspace: &str,
) -> Result<Vec<RowValues>> {
    let table = known(table)?;
    let column = quoted(column)?;
    let sql = format!("SELECT * FROM \"{table}\" WHERE {column} = ? AND workspace_id = ?");
    let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(value)
        .bind(workspace)
        .fetch_all(&mut *conn)
        .await?;
    rows.iter().map(to_json).collect()
}

/// The columns `table` has now.
pub async fn columns(conn: &mut SqliteConnection, table: &str) -> Result<Vec<String>> {
    let table = known(table)?;
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!("PRAGMA table_info(\"{table}\")")))
        .fetch_all(&mut *conn)
        .await?;
    rows.iter()
        .map(|r| r.try_get::<String, _>("name").map_err(Into::into))
        .collect()
}

/// Writes `row` into `table`: only the columns the table has now. False when the row's key is taken (`OR IGNORE`).
pub async fn insert(conn: &mut SqliteConnection, table: &str, row: &RowValues) -> Result<bool> {
    let table = known(table)?;
    let have = columns(conn, table).await?;
    let picked: Vec<(&String, &Value)> = row.iter().filter(|(name, _)| have.contains(name)).collect();
    if picked.is_empty() {
        return Err(CoreError::InvalidInput(format!("nothing to restore into {table}")));
    }
    let names = picked
        .iter()
        .map(|(name, _)| quoted(name))
        .collect::<Result<Vec<_>>>()?
        .join(", ");
    let marks = vec!["?"; picked.len()].join(", ");
    let sql = format!("INSERT OR IGNORE INTO \"{table}\" ({names}) VALUES ({marks})");
    let mut query = sqlx::query(sqlx::AssertSqlSafe(sql));
    for (_, value) in &picked {
        query = match value {
            Value::Null => query.bind(None::<String>),
            Value::Bool(b) => query.bind(i64::from(*b)),
            Value::Number(n) => match n.as_i64() {
                Some(i) => query.bind(i),
                None => query.bind(n.as_f64().unwrap_or_default()),
            },
            Value::String(s) => query.bind(s.clone()),
            Value::Object(o) => {
                let text = o.get("blob").and_then(Value::as_str).unwrap_or_default();
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(text)
                    .map_err(|_| CoreError::InvalidInput(format!("a value kept for {table} can't be read")))?;
                query.bind(bytes)
            }
            Value::Array(_) => {
                return Err(CoreError::InvalidInput(format!(
                    "a value kept for {table} can't be read"
                )));
            }
        };
    }
    let done = query.execute(&mut *conn).await?;
    Ok(done.rows_affected() > 0)
}

/// `"name"`, for a column name made of letters, digits and `_` only.
fn quoted(name: &str) -> Result<String> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(CoreError::InvalidInput(format!("'{name}' is not a column name")));
    }
    Ok(format!("\"{name}\""))
}

/// A text column's value, if it holds one.
pub fn text<'a>(row: &'a RowValues, column: &str) -> Option<&'a str> {
    row.get(column).and_then(Value::as_str)
}

/// An integer column's value, if it holds one.
pub fn integer(row: &RowValues, column: &str) -> Option<i64> {
    row.get(column).and_then(Value::as_i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn column_names_are_quoted_or_refused() {
        assert_eq!(quoted("folder_id").unwrap(), "\"folder_id\"");
        assert!(quoted("name\"; DROP TABLE sessions; --").is_err());
        assert!(quoted("").is_err());
    }

    #[test]
    fn only_known_tables_are_read_or_written() {
        assert!(known("sessions").is_ok());
        assert!(known("audit_log").is_err());
        assert!(known("vault_items").is_err());
    }
}
