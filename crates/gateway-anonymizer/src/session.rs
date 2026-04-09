use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use gateway_common::errors::SessionError;
use gateway_common::types::{Placeholder, PiiType};
use rusqlite::Connection;
use tokio::sync::Mutex;
use tracing::warn;

/// SQLite-backed session store for placeholder mappings.
///
/// All database I/O is offloaded to blocking threads via
/// `tokio::task::spawn_blocking` so the async runtime is never blocked.
/// The connection is protected by a `tokio::sync::Mutex` so only one
/// blocking task accesses SQLite at a time.
pub struct SessionStore {
    conn: Arc<Mutex<Connection>>,
}

/// Maximum number of retry attempts when SQLite reports a locked database.
const MAX_RETRIES: u32 = 3;
/// Base backoff duration between retries.
const RETRY_BACKOFF: Duration = Duration::from_millis(100);

impl SessionStore {
    /// Open (or create) the database at `path` and initialize the schema.
    pub async fn new(path: &str) -> Result<Self, SessionError> {
        let path = path.to_string();
        let conn = tokio::task::spawn_blocking(move || -> Result<Connection, SessionError> {
            let conn = Connection::open(&path)
                .map_err(|e| SessionError::DatabaseError(e.to_string()))?;
            conn.pragma_update(None, "journal_mode", "WAL")
                .map_err(|e| SessionError::DatabaseError(e.to_string()))?;
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS sessions (
                    id            INTEGER PRIMARY KEY,
                    session_id    TEXT    NOT NULL,
                    placeholder_text TEXT NOT NULL,
                    original_text TEXT    NOT NULL,
                    pii_type      TEXT    NOT NULL,
                    created_at    TEXT    NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_sessions_session_id
                    ON sessions(session_id);",
            )
            .map_err(|e| SessionError::DatabaseError(e.to_string()))?;
            Ok(conn)
        })
        .await
        .map_err(|e| SessionError::DatabaseError(format!("task join error: {e}")))?
        ?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Create an in-memory store (useful for tests).
    pub async fn in_memory() -> Result<Self, SessionError> {
        Self::new(":memory:").await
    }

    /// Store all placeholders for a session.
    pub async fn store(
        &self,
        session_id: &str,
        placeholders: &[Placeholder],
    ) -> Result<(), SessionError> {
        let conn = Arc::clone(&self.conn);
        let session_id = session_id.to_string();
        let placeholders: Vec<Placeholder> = placeholders.to_vec();
        let now = Utc::now().to_rfc3339();

        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            retry(MAX_RETRIES, || {
                let tx = guard
                    .unchecked_transaction()
                    .map_err(|e| SessionError::DatabaseError(e.to_string()))?;
                for p in &placeholders {
                    tx.execute(
                        "INSERT INTO sessions (session_id, placeholder_text, original_text, pii_type, created_at)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        rusqlite::params![
                            session_id,
                            p.placeholder_text,
                            p.original_text,
                            p.pii_type.placeholder_prefix(),
                            now,
                        ],
                    )
                    .map_err(|e| SessionError::DatabaseError(e.to_string()))?;
                }
                tx.commit()
                    .map_err(|e| SessionError::DatabaseError(e.to_string()))?;
                Ok(())
            })
        })
        .await
        .map_err(|e| SessionError::DatabaseError(format!("task join error: {e}")))?
    }

    /// Look up the original text for a single placeholder in a session.
    pub async fn lookup(
        &self,
        session_id: &str,
        placeholder_text: &str,
    ) -> Result<Option<String>, SessionError> {
        let conn = Arc::clone(&self.conn);
        let session_id = session_id.to_string();
        let placeholder_text = placeholder_text.to_string();

        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            retry(MAX_RETRIES, || {
                let mut stmt = guard
                    .prepare_cached(
                        "SELECT original_text FROM sessions
                         WHERE session_id = ?1 AND placeholder_text = ?2
                         LIMIT 1",
                    )
                    .map_err(|e| SessionError::DatabaseError(e.to_string()))?;
                let result = stmt
                    .query_row(
                        rusqlite::params![session_id, placeholder_text],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .map_err(|e| SessionError::DatabaseError(e.to_string()))?;
                Ok(result)
            })
        })
        .await
        .map_err(|e| SessionError::DatabaseError(format!("task join error: {e}")))?
    }

    /// Retrieve all placeholders stored for a session.
    pub async fn lookup_all(
        &self,
        session_id: &str,
    ) -> Result<Vec<Placeholder>, SessionError> {
        let conn = Arc::clone(&self.conn);
        let session_id = session_id.to_string();

        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            retry(MAX_RETRIES, || {
                let mut stmt = guard
                    .prepare_cached(
                        "SELECT placeholder_text, original_text, pii_type FROM sessions
                         WHERE session_id = ?1",
                    )
                    .map_err(|e| SessionError::DatabaseError(e.to_string()))?;
                let rows = stmt
                    .query_map(rusqlite::params![session_id], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    })
                    .map_err(|e| SessionError::DatabaseError(e.to_string()))?;

                let mut placeholders = Vec::new();
                for row in rows {
                    let (placeholder_text, original_text, pii_type_str) =
                        row.map_err(|e| SessionError::DatabaseError(e.to_string()))?;
                    let pii_type = parse_pii_type(&pii_type_str)?;
                    // Derive the short id from the placeholder text.
                    // Format: [TYPE_xxxxxxxx]
                    let id = placeholder_text
                        .trim_end_matches(']')
                        .rsplit('_')
                        .next()
                        .unwrap_or("")
                        .to_string();
                    placeholders.push(Placeholder {
                        id,
                        pii_type,
                        placeholder_text,
                        original_text,
                    });
                }
                Ok(placeholders)
            })
        })
        .await
        .map_err(|e| SessionError::DatabaseError(format!("task join error: {e}")))?
    }

    /// Delete sessions whose `created_at` is older than `ttl` from now.
    /// Returns the number of rows deleted.
    pub async fn cleanup_expired(&self, ttl: Duration) -> Result<usize, SessionError> {
        let conn = Arc::clone(&self.conn);

        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            let cutoff = Utc::now() - chrono::Duration::from_std(ttl)
                .map_err(|e| SessionError::DatabaseError(format!("duration conversion: {e}")))?;
            let cutoff_str = cutoff.to_rfc3339();

            retry(MAX_RETRIES, || {
                let deleted = guard
                    .execute(
                        "DELETE FROM sessions WHERE created_at < ?1",
                        rusqlite::params![cutoff_str],
                    )
                    .map_err(|e| SessionError::DatabaseError(e.to_string()))?;
                Ok(deleted)
            })
        })
        .await
        .map_err(|e| SessionError::DatabaseError(format!("task join error: {e}")))?
    }
}

/// Parse a placeholder prefix string back to a `PiiType`.
fn parse_pii_type(s: &str) -> Result<PiiType, SessionError> {
    match s {
        "PERSON" => Ok(PiiType::Person),
        "ORG" => Ok(PiiType::Organization),
        "LOCATION" => Ok(PiiType::Location),
        "EMAIL" => Ok(PiiType::Email),
        "PHONE" => Ok(PiiType::Phone),
        "SSN" => Ok(PiiType::Ssn),
        "CREDENTIAL" => Ok(PiiType::Credential),
        other => Err(SessionError::DatabaseError(format!(
            "unknown pii type: {other}"
        ))),
    }
}

/// Retry a closure up to `max` times when it returns a `DatabaseLocked` error.
fn retry<T, F>(max: u32, mut f: F) -> Result<T, SessionError>
where
    F: FnMut() -> Result<T, SessionError>,
{
    for attempt in 0..max {
        match f() {
            Ok(val) => return Ok(val),
            Err(SessionError::DatabaseError(ref msg)) if msg.contains("database is locked") => {
                warn!(attempt, "SQLite locked, retrying");
                if attempt + 1 < max {
                    std::thread::sleep(RETRY_BACKOFF * (attempt + 1));
                }
            }
            Err(e) => return Err(e),
        }
    }
    Err(SessionError::DatabaseLocked)
}

/// Extension trait to make `query_row` return `Option` on no rows.
trait OptionalExt<T> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error>;
}

impl<T> OptionalExt<T> for Result<T, rusqlite::Error> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(val) => Ok(Some(val)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
