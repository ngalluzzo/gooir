//! A generic CRUD runtime over the neutral data-model waist.
//!
//! One binary, any application: point it at a `.entities` file and it applies
//! the schema, then serves a validated REST surface. Nothing in it knows the
//! names of your entities -- routes, validation, and SQL are all read off the
//! model at request time. That is the "80% is generic over the entity" claim
//! made executable rather than asserted.
//!
//! PostgreSQL is reached through `psql`, keeping the authoritative client
//! authoritative and this workspace free of a driver stack. That is a milestone
//! choice, not an endorsement: a real deployment wants a pooled client.

mod http;
mod sql;
mod validate;

use std::net::TcpListener;
use std::process::Command;

use semantics_data_model_v1::{DataModel, EntityShape};
use serde_json::Value;
use sql::{application_default, quote_ident, value_to_sql};
use validate::Mode;

struct Db {
    host: String,
    port: String,
    user: String,
    name: String,
}

impl Db {
    fn from_env(name: &str) -> Self {
        Self {
            host: std::env::var("PGHOST").unwrap_or_else(|_| "127.0.0.1".into()),
            port: std::env::var("PGPORT").unwrap_or_else(|_| "5432".into()),
            user: std::env::var("PGUSER").unwrap_or_else(|_| "postgres".into()),
            name: name.to_owned(),
        }
    }

    fn run(&self, database: &str, sql: &str) -> Result<String, String> {
        let out = Command::new("psql")
            .args([
                "-h", &self.host, "-p", &self.port, "-U", &self.user, "-d", database,
            ])
            .args(["-tA", "-v", "ON_ERROR_STOP=1", "-c", sql])
            .output()
            .map_err(|e| format!("psql could not be started: {e}"))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
        }
    }

    fn query(&self, sql: &str) -> Result<String, String> {
        self.run(&self.name, sql)
    }
}

fn usage() -> String {
    "usage: app-runtime <file.entities> [--port N] [--database NAME] [--reset]\n\n\
     Connection is taken from PGHOST / PGPORT / PGUSER.\n\
     --reset drops and recreates the database before applying the schema."
        .to_owned()
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let spec_path = args
        .first()
        .filter(|a| !a.starts_with("--"))
        .ok_or_else(usage)?;
    let flag = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let port: u16 = flag("--port")
        .unwrap_or_else(|| "8080".into())
        .parse()
        .map_err(|_| usage())?;
    let dbname = flag("--database").unwrap_or_else(|| "gooi_app".into());
    let reset = args.iter().any(|a| a == "--reset");

    let text = std::fs::read_to_string(spec_path).map_err(|e| format!("{spec_path}: {e}"))?;
    let spec = entity_spec::parse_entity_spec(&text);
    for d in &spec.defeats {
        eprintln!("  spec [{:?}] {}: {}", d.kind, d.subject, d.reason);
    }
    let model = spec.value;
    if model.entities.is_empty() {
        return Err("the spec declares no entities".to_owned());
    }

    let db = Db::from_env(&dbname);
    if reset {
        db.run("postgres", &format!("drop database if exists {dbname};"))?;
        db.run("postgres", &format!("create database {dbname};"))?;
    }
    let ddl = sql_ddl_lowering::lower_to_postgres_ddl(&model);
    for l in &ddl.lossy {
        eprintln!("  lossy {}: {}", l.subject, l.detail);
    }
    db.query(&ddl.ddl)
        .map_err(|e| format!("schema could not be applied:\n{e}"))?;

    let openapi =
        serde_json::to_string_pretty(&openapi_lowering::lower_to_openapi(&model).document)
            .unwrap_or_else(|_| "{}".to_owned());

    let listener = TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| format!("could not bind port {port}: {e}"))?;

    eprintln!(
        "\n{} on http://127.0.0.1:{port}  (database {dbname})",
        spec_path
    );
    for e in &model.entities {
        eprintln!(
            "  /{:<12} {} field(s){}",
            e.name,
            e.fields.len(),
            if identity_of(e).is_some() {
                ""
            } else {
                "   [no pk: collection only]"
            }
        );
    }
    eprintln!("  /openapi.json\n");

    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let Some(req) = http::read_request(&mut stream) else {
            continue;
        };
        let (status, body) = handle(&model, &db, &openapi, &req);
        http::respond(&mut stream, status, &body);
    }
    Ok(())
}

fn identity_of(e: &EntityShape) -> Option<&semantics_data_model_v1::FieldShape> {
    let ids: Vec<_> = e.fields.iter().filter(|f| f.identity.is_yes()).collect();
    if ids.len() == 1 { Some(ids[0]) } else { None }
}

fn handle(model: &DataModel, db: &Db, openapi: &str, req: &http::Request) -> (u16, String) {
    let path = req.path.split('?').next().unwrap_or("");
    if path == "/openapi.json" {
        return (200, openapi.to_owned());
    }
    if path == "/" {
        let names: Vec<String> = model
            .entities
            .iter()
            .map(|e| format!("\"{}\"", e.name))
            .collect();
        return (200, format!("{{\"entities\":[{}]}}", names.join(",")));
    }

    let mut segments = path.trim_start_matches('/').splitn(2, '/');
    let Some(name) = segments.next().filter(|s| !s.is_empty()) else {
        return (404, http::error_body(&["no route".to_owned()]));
    };
    let Some(entity) = model.entities.iter().find(|e| e.name == name) else {
        return (404, http::error_body(&[format!("no entity `{name}`")]));
    };
    let id = segments.next().filter(|s| !s.is_empty());

    match (req.method.as_str(), id) {
        ("GET", None) => list(db, entity),
        ("POST", None) => create(db, entity, &req.body),
        ("GET", Some(id)) => get_one(db, entity, id),
        ("PATCH", Some(id)) => update(db, entity, id, &req.body),
        ("DELETE", Some(id)) => delete(db, entity, id),
        _ => (405, http::error_body(&["method not allowed".to_owned()])),
    }
}

fn parse_body(body: &str) -> Result<Value, (u16, String)> {
    serde_json::from_str(body).map_err(|e| (400, http::error_body(&[format!("invalid JSON: {e}")])))
}

fn id_predicate(entity: &EntityShape, id: &str) -> Result<String, (u16, String)> {
    let Some(key) = identity_of(entity) else {
        return Err((
            404,
            http::error_body(&[format!("{} has no single identity field", entity.name)]),
        ));
    };
    let v = Value::String(id.to_owned());
    if let Err(why) = validate::field_value(key, &v) {
        return Err((400, http::error_body(&[format!("`{}`: {why}", key.name)])));
    }
    // A value of the right shape can still be outside the domain -- a uuid
    // column will not accept arbitrary text -- so the store is asked to decide
    // rather than this runtime reimplementing every format.
    Ok(format!(
        "{} = {}",
        quote_ident(&key.name),
        value_to_sql(key, &v)
    ))
}

fn list(db: &Db, entity: &EntityShape) -> (u16, String) {
    let sql = format!(
        "select coalesce(json_agg(t), '[]'::json) from {} t;",
        quote_ident(&entity.name)
    );
    match db.query(&sql) {
        Ok(rows) => (
            200,
            format!(
                "{{\"data\":{}}}",
                if rows.is_empty() { "[]".into() } else { rows }
            ),
        ),
        Err(e) => (status_for(&e), http::error_body(&[first_line(&e)])),
    }
}

fn get_one(db: &Db, entity: &EntityShape, id: &str) -> (u16, String) {
    let pred = match id_predicate(entity, id) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let sql = format!(
        "select coalesce(json_agg(t), '[]'::json) from {} t where {pred};",
        quote_ident(&entity.name)
    );
    match db.query(&sql) {
        Ok(rows) => {
            let parsed: Value = serde_json::from_str(&rows).unwrap_or(Value::Array(vec![]));
            match parsed.as_array().and_then(|a| a.first()) {
                Some(row) => (200, row.to_string()),
                None => (404, http::error_body(&["not found".to_owned()])),
            }
        }
        Err(e) => (status_for(&e), http::error_body(&[first_line(&e)])),
    }
}

fn create(db: &Db, entity: &EntityShape, body: &str) -> (u16, String) {
    let value = match parse_body(body) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let problems = validate::check(entity, &value, Mode::Create);
    if !problems.is_empty() {
        return (400, http::error_body(&problems));
    }
    let obj = value.as_object().cloned().unwrap_or_default();

    let mut cols: Vec<String> = Vec::new();
    let mut vals: Vec<String> = Vec::new();
    for f in &entity.fields {
        match obj.get(&f.name) {
            Some(v) => {
                cols.push(quote_ident(&f.name));
                vals.push(value_to_sql(f, v));
            }
            None => {
                // The runtime fills application-origin defaults; the store fills its own.
                if let Some(expr) = application_default(f) {
                    cols.push(quote_ident(&f.name));
                    vals.push(expr);
                }
            }
        }
    }
    if cols.is_empty() {
        return (400, http::error_body(&["nothing to insert".to_owned()]));
    }
    let sql = format!(
        "with ins as (insert into {} ({}) values ({}) returning *) \
         select coalesce(json_agg(ins), '[]'::json) from ins;",
        quote_ident(&entity.name),
        cols.join(", "),
        vals.join(", ")
    );
    match db.query(&sql) {
        Ok(rows) => {
            let parsed: Value = serde_json::from_str(&rows).unwrap_or(Value::Array(vec![]));
            match parsed.as_array().and_then(|a| a.first()) {
                Some(row) => (201, row.to_string()),
                None => (
                    500,
                    http::error_body(&["insert returned no row".to_owned()]),
                ),
            }
        }
        Err(e) => (status_for(&e), http::error_body(&[first_line(&e)])),
    }
}

fn update(db: &Db, entity: &EntityShape, id: &str, body: &str) -> (u16, String) {
    let value = match parse_body(body) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let problems = validate::check(entity, &value, Mode::Update);
    if !problems.is_empty() {
        return (400, http::error_body(&problems));
    }
    let pred = match id_predicate(entity, id) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let obj = value.as_object().cloned().unwrap_or_default();
    if obj.is_empty() {
        return (400, http::error_body(&["no fields to update".to_owned()]));
    }
    let sets: Vec<String> = entity
        .fields
        .iter()
        .filter_map(|f| {
            obj.get(&f.name)
                .map(|v| format!("{} = {}", quote_ident(&f.name), value_to_sql(f, v)))
        })
        .collect();
    let sql = format!(
        "with upd as (update {} set {} where {pred} returning *) \
         select coalesce(json_agg(upd), '[]'::json) from upd;",
        quote_ident(&entity.name),
        sets.join(", ")
    );
    match db.query(&sql) {
        Ok(rows) => {
            let parsed: Value = serde_json::from_str(&rows).unwrap_or(Value::Array(vec![]));
            match parsed.as_array().and_then(|a| a.first()) {
                Some(row) => (200, row.to_string()),
                None => (404, http::error_body(&["not found".to_owned()])),
            }
        }
        Err(e) => (status_for(&e), http::error_body(&[first_line(&e)])),
    }
}

fn delete(db: &Db, entity: &EntityShape, id: &str) -> (u16, String) {
    let pred = match id_predicate(entity, id) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let sql = format!(
        "with del as (delete from {} where {pred} returning 1 as x) select count(*) from del;",
        quote_ident(&entity.name)
    );
    match db.query(&sql) {
        Ok(n) if n.trim() == "0" => (404, http::error_body(&["not found".to_owned()])),
        Ok(_) => (204, String::new()),
        Err(e) => (status_for(&e), http::error_body(&[first_line(&e)])),
    }
}

/// Maps a store error onto a client- or server-side status. A malformed value
/// is the caller's problem, not an internal failure.
fn status_for(e: &str) -> u16 {
    if e.contains("duplicate key") || e.contains("violates foreign key") {
        409
    } else if e.contains("invalid input syntax") || e.contains("invalid input value") {
        400
    } else {
        500
    }
}

fn first_line(e: &str) -> String {
    e.lines()
        .find(|l| l.contains("ERROR") || !l.trim().is_empty())
        .unwrap_or(e)
        .trim()
        .to_owned()
}
