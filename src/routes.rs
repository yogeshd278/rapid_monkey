use actix_web::{web, HttpResponse, Responder};
use sqlx::SqlitePool;
use crate::scanner;
use crate::models::{ScanRequest, ScanResult};

#[actix_web::post("/scan")]
pub async fn start_scan(
    pool: web::Data<SqlitePool>,
    req: web::Json<ScanRequest>,
) -> impl Responder {
    let results = scanner::scan_api(&req.api_url).await;

    // Save results to SQLite
    for result in &results {
        sqlx::query(
            "INSERT INTO scans (api_url, vulnerability, severity, details) VALUES (?, ?, ?, ?)"
        )
        .bind(&result.api_url)
        .bind(&result.vulnerability)
        .bind(&result.severity)
        .bind(&result.details)
        .execute(pool.get_ref())
        .await
        .expect("Failed to save scan result");
    }

    HttpResponse::Ok().json(results)
}

#[actix_web::get("/results")]
pub async fn get_scan_results(pool: web::Data<SqlitePool>) -> impl Responder {
    let results = sqlx::query_as::<_, ScanResult>("SELECT * FROM scans")
        .fetch_all(pool.get_ref())
        .await
        .expect("Failed to fetch scan results");

    HttpResponse::Ok().json(results)
}