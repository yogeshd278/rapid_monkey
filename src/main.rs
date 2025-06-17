use actix_web::{web, App, HttpServer};
use actix_cors::Cors;
use sqlx::sqlite::SqlitePool;
mod routes;
mod scanner;
mod models;

// Synchronous function for configuring routes
fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(routes::start_scan)
       .service(routes::get_scan_results);
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let pool = SqlitePool::connect("sqlite://scans.db")
        .await
        .expect("Failed to connect to SQLite");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .wrap(
                Cors::default()
                    .allowed_origin("http://localhost:3000") // Allow frontend origin
                    .allowed_methods(vec!["GET", "POST", "OPTIONS"]) // Allow GET and POST
                    .allowed_headers(vec!["Content-Type"]) // Allow Content-Type header
                    .max_age(3600), // Cache preflight for 1 hour
            )
            .configure(configure_routes)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}