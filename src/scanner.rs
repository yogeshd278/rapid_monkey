use reqwest::Client;
use serde_json::Value;

pub async fn scan_api(api_url: &str) -> Vec<super::models::ScanResult> {
    let client = Client::new();
    let mut results = Vec::new();

    // Main API request
    let response = client
        .get(api_url)
        .send()
        .await
        .unwrap_or_else(|_| panic!("Failed to reach {}", api_url));

    if response.status().is_success() {
        let headers = response.headers().clone();
        let body: Value = response.json().await.unwrap_or(Value::Null);

        // Check for sensitive data exposure
        if body.to_string().contains("password") || body.to_string().contains("token") {
            results.push(super::models::ScanResult {
                id: 0, // Will be set by DB
                api_url: api_url.to_string(),
                vulnerability: "Sensitive Data Exposure".to_string(),
                severity: "High".to_string(),
                details: "API endpoint returned sensitive data without authentication.".to_string(),
            });
        }

        // Check for missing CSP header
        if !headers.contains_key("content-security-policy") {
            results.push(super::models::ScanResult {
                id: 0,
                api_url: api_url.to_string(),
                vulnerability: "Missing Content-Security-Policy Header".to_string(),
                severity: "Medium".to_string(),
                details: "API response lacks CSP header, increasing risk of XSS attacks.".to_string(),
            });
        }

        // Check for missing X-Frame-Options header
        if !headers.contains_key("x-frame-options") {
            results.push(super::models::ScanResult {
                id: 0,
                api_url: api_url.to_string(),
                vulnerability: "Missing X-Frame-Options Header".to_string(),
                severity: "Medium".to_string(),
                details: "API response lacks X-Frame-Options header, increasing risk of clickjacking.".to_string(),
            });
        }
    }

    // Injection test
    let injection_url = format!("{}?input=' OR 1=1 --", api_url);
    let injection_response = client
        .get(&injection_url)
        .send()
        .await
        .unwrap_or_else(|_| panic!("Failed to test injection at {}", injection_url));

    if injection_response.status().is_success() {
        let body: Value = injection_response.json().await.unwrap_or(Value::Null);
        if body.to_string().contains("' OR 1=1 --") {
            results.push(super::models::ScanResult {
                id: 0,
                api_url: api_url.to_string(),
                vulnerability: "Potential Injection Vulnerability".to_string(),
                severity: "Critical".to_string(),
                details: "API reflected malicious input, indicating potential SQL or XSS vulnerability.".to_string(),
            });
        }
    }

    results
}