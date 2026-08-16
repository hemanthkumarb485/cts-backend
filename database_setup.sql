-- ============================================================
-- VULNERABILITY RISK PRIORITIZATION & TICKETING SYSTEM
-- MySQL Database Setup — Run this when DB is ready
-- All tables are for GitHub Integration persistence only.
-- The pipeline itself is stateless (in-memory JSON).
-- ============================================================

CREATE DATABASE IF NOT EXISTS vulnrisk_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE vulnrisk_db;

-- ─── GitHub Connections ────────────────────────────────────────────────────────
-- Stores OAuth tokens (encrypted) for each connected GitHub account

CREATE TABLE IF NOT EXISTS github_connections (
    id                      INT AUTO_INCREMENT PRIMARY KEY,
    github_user_id          BIGINT NOT NULL UNIQUE,
    github_username         VARCHAR(255) NOT NULL,
    github_email            VARCHAR(255),
    access_token_encrypted  TEXT NOT NULL COMMENT 'Fernet-encrypted access token',
    token_scope             VARCHAR(500),
    connected_at            DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- ─── GitHub Repositories ───────────────────────────────────────────────────────
-- Tracks which repos a user has selected for issue creation

CREATE TABLE IF NOT EXISTS github_repositories (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    connection_id   INT NOT NULL,
    repo_id         BIGINT NOT NULL,
    repo_name       VARCHAR(255) NOT NULL,
    repo_full_name  VARCHAR(512) NOT NULL COMMENT 'owner/repo format',
    is_private      TINYINT(1) DEFAULT 0,
    repo_url        VARCHAR(1024),
    selected_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (connection_id) REFERENCES github_connections(id) ON DELETE CASCADE,
    UNIQUE KEY uq_connection_repo (connection_id, repo_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- ─── GitHub Issues ─────────────────────────────────────────────────────────────
-- Tracks all GitHub issues created from vulnerability findings

CREATE TABLE IF NOT EXISTS github_issues (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    connection_id   INT NOT NULL,
    repository_id   INT NOT NULL,
    finding_id      VARCHAR(36) NOT NULL COMMENT 'UUID from CanonicalFinding.finding_id',
    issue_number    INT NOT NULL,
    issue_url       VARCHAR(1024) NOT NULL,
    issue_title     TEXT NOT NULL,
    status          ENUM('open', 'closed') DEFAULT 'open',
    assignee        VARCHAR(255),
    labels          TEXT COMMENT 'JSON array of label strings',
    milestone       VARCHAR(255),
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    closed_at       DATETIME,
    FOREIGN KEY (connection_id) REFERENCES github_connections(id) ON DELETE CASCADE,
    FOREIGN KEY (repository_id) REFERENCES github_repositories(id) ON DELETE CASCADE,
    INDEX idx_finding_id (finding_id),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- ─── Verify ────────────────────────────────────────────────────────────────────
-- Run after setup to confirm tables were created

SHOW TABLES;
