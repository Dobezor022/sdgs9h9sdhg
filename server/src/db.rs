use anyhow::{Context, Result};
use rusqlite::Connection;
use std::{path::{Path, PathBuf}, sync::Arc};

#[derive(Clone)]
pub struct Db { path: Arc<PathBuf> }

impl Db {
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent)=path.parent() { tokio::fs::create_dir_all(parent).await?; }
        let db=Self{path:Arc::new(path)};
        db.run(|conn| migrate(conn)).await?;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(db.path.as_ref(), std::fs::Permissions::from_mode(0o600)).await?;
        }
        Ok(db)
    }

    pub fn path(&self) -> &Path { self.path.as_ref() }

    pub async fn ping(&self) -> Result<()> {
        self.run(|conn| { conn.query_row("SELECT 1", [], |_| Ok(()))?; Ok(()) }).await
    }

    pub async fn run<T, F>(&self, f: F) -> Result<T>
    where T: Send + 'static, F: FnOnce(&mut Connection) -> Result<T> + Send + 'static {
        let path=self.path.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn=open_connection(path.as_ref())?;
            f(&mut conn)
        }).await.context("sqlite worker join")?
    }
}

pub fn open_connection(path: &Path) -> Result<Connection> {
    let conn=Connection::open(path)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    conn.pragma_update(None, "cache_size", -32768)?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    conn.pragma_update(None, "mmap_size", 134_217_728_i64)?;
    conn.pragma_update(None, "wal_autocheckpoint", 1000)?;
    Ok(conn)
}

fn migrate(conn: &mut Connection) -> Result<()> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL) STRICT;")?;
    const MIGRATIONS: &[(i64,&str)] = &[
        (1, include_str!("../migrations/0001_core.sql")),
        (2, include_str!("../migrations/0002_provisioning.sql")),
        (3, include_str!("../migrations/0003_device_authentication.sql")),
        (4, include_str!("../migrations/0004_messaging.sql")),
        (5, include_str!("../migrations/0005_messaging_change_clock.sql")),
        (6, include_str!("../migrations/0006_default_chat_topology.sql")),
        (7, include_str!("../migrations/0007_message_lifecycle_typing_receipts.sql")),
        (8, include_str!("../migrations/0008_multi_device_linking.sql")),
        (9, include_str!("../migrations/0009_unlimited_media.sql")),
        (10, include_str!("../migrations/0010_chat_read_cursors.sql")),
        (11, include_str!("../migrations/0011_security_foundation.sql")),
        (12, include_str!("../migrations/0012_security_workflows.sql")),
        (13, include_str!("../migrations/0013_opaque_ratchet_fmk_completion.sql")),
        (14, include_str!("../migrations/0014_security2_blind_fabric.sql")),
    ];
    for (version, script) in MIGRATIONS {
        let applied:i64=conn.query_row("SELECT COUNT(*) FROM schema_migrations WHERE version=?1", [version], |r| r.get(0))?;
        if applied!=0 { continue; }
        let tx=conn.transaction()?;
        tx.execute_batch(script).with_context(|| format!("migration {version:04}"))?;
        tx.execute("INSERT INTO schema_migrations(version,applied_at) VALUES(?1,strftime('%Y-%m-%dT%H:%M:%fZ','now'))", [version])?;
        tx.commit()?;
    }
    Ok(())
}
