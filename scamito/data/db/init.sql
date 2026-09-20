CREATE TABLE IF NOT EXISTS nmap_hostnames (
    id SERIAL PRIMARY KEY,
    ip inet NOT NULL,
    hostname varchar(1024) NOT NULL,
    UNIQUE (ip, hostname)
);

CREATE TABLE IF NOT EXISTS e_ip_services (
    id SERIAL PRIMARY KEY,
    ip inet NOT NULL,
    port INTEGER NOT NULL,
    product TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    confidence INTEGER NOT NULL DEFAULT 0,
    UNIQUE (ip, port)
);

CREATE TABLE IF NOT EXISTS e_service_cve (
    id SERIAL PRIMARY KEY,
    product TEXT NOT NULL,
    version TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT '',
    score DOUBLE PRECISION,
    published TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    matched_cpes TEXT[] NOT NULL DEFAULT '{}',
    UNIQUE (product, version, cve_id)
);
