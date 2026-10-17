CREATE DATABASE IF NOT EXISTS saklolo CHARACTER SET utf8mb4;
USE saklolo;
CREATE TABLE users(
    id INT AUTO_INCREMENT PRIMARY KEY,
    phone_hash CHAR(64) UNIQUE NOT NULL,
    role ENUM('household', 'merchant', 'admin') NOT NULL,
    pw_hash VARCHAR(100) NOT NULL,
    name VARCHAR(120),
    brgy VARCHAR(80),
    wallet VARCHAR(20)
);
CREATE TABLE households(
    id INT AUTO_INCREMENT PRIMARY KEY,
    phone_hash CHAR(64) UNIQUE NOT NULL,
    phone_enc TEXT NOT NULL,
    name_enc TEXT NOT NULL,
    brgy VARCHAR(80),
    members INT DEFAULT 1
);
CREATE TABLE vouchers(
    id CHAR(5) PRIMARY KEY,
    code VARCHAR(32) NOT NULL,
    val INT NOT NULL,
    hh_hash CHAR(64) NOT NULL,
    brgy VARCHAR(80),
    status ENUM('issued', 'redeemed', 'confirmed', 'disputed') DEFAULT 'issued',
    issued_at BIGINT,
    INDEX(hh_hash),
    INDEX(status)
);
CREATE TABLE tx(
    n INT AUTO_INCREMENT PRIMARY KEY,
    voucher_id CHAR(5) UNIQUE NOT NULL,
    val INT,
    merchant_id INT,
    brgy VARCHAR(80),
    t BIGINT,
    paid TINYINT DEFAULT 0,
    FOREIGN KEY(voucher_id) REFERENCES vouchers(id),
    FOREIGN KEY(merchant_id) REFERENCES users(id)
);
CREATE TABLE ledger(
    n INT PRIMARY KEY,
    t BIGINT,
    ev VARCHAR(20),
    d TEXT,
    prev CHAR(64),
    hash CHAR(64)
);
CREATE TABLE sms_log(
    id INT AUTO_INCREMENT PRIMARY KEY,
    to_hash CHAR(64),
    to_enc TEXT,
    text VARCHAR(400),
    confirm_id CHAR(5),
    t BIGINT,
    sent TINYINT DEFAULT 0,
    tries TINYINT DEFAULT 0,
    INDEX(to_hash)
);
CREATE TABLE prices(item VARCHAR(80) PRIMARY KEY, cap DECIMAL(8, 2));
CREATE TABLE payouts(
    id INT AUTO_INCREMENT PRIMARY KEY,
    merchant_id INT,
    amt INT,
    ch VARCHAR(20),
    eta BIGINT,
    status VARCHAR(12) DEFAULT 'queued'
);
CREATE TABLE settings(k VARCHAR(20) PRIMARY KEY, v VARCHAR(100));
INSERT IGNORE INTO settings
VALUES('cap', '3000');
INSERT IGNORE INTO prices
VALUES('Rice (1 kg)', 55),
('Sardines (can)', 25),
('Instant noodles', 12),
('Bottled water 1L', 20);