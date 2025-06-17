CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_url TEXT NOT NULL,
    vulnerability TEXT NOT NULL,
    severity TEXT NOT NULL,
    details TEXT NOT NULL
);