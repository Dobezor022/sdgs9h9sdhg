use fedmes_server::db::{open_connection, Db};
use std::{fs, path::PathBuf};
use uuid::Uuid;

fn temp_db() -> PathBuf {
    std::env::temp_dir().join(format!("fedmes-schema-{}.sqlite3", Uuid::new_v4()))
}

fn cleanup(path: &PathBuf) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(PathBuf::from(format!("{}-wal", path.display())));
    let _ = fs::remove_file(PathBuf::from(format!("{}-shm", path.display())));
}

#[tokio::test]
async fn fresh_database_reaches_schema_14_and_default_topology() {
    let path = temp_db();
    let db = Db::open(&path).await.expect("open fresh database");
    db.ping().await.expect("database ping");

    let conn = open_connection(&path).expect("open validation connection");
    let schema: i64 = conn
        .query_row("SELECT COALESCE(MAX(version),0) FROM schema_migrations", [], |row| row.get(0))
        .expect("schema version");
    assert_eq!(schema, 14);

    let chats: i64 = conn
        .query_row("SELECT COUNT(*) FROM chats", [], |row| row.get(0))
        .expect("chat count");
    assert_eq!(chats, 16);

    for username in ["grisha", "papa", "mama", "yura", "vasya"] {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM chat_members WHERE username=?1",
                [username],
                |row| row.get(0),
            )
            .expect("membership count");
        assert_eq!(count, 6, "unexpected chat membership count for {username}");
    }

    for table in ["blind_routes", "blind_objects", "account_security_state", "device_provisioning_requests"] {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .expect("table lookup");
        assert_eq!(count, 1, "required table is missing: {table}");
    }

    drop(conn);
    drop(db);
    cleanup(&path);
}
