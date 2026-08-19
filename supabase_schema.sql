-- ============================================================
-- VULNERABILITY RISK PRIORITIZATION & TICKETING SYSTEM
-- Supabase (Postgres) schema — run in the Supabase SQL editor.
-- Replaces database_setup.sql (MySQL). Auth is handled by
-- Supabase Auth (auth.users) — no custom users table needed.
-- ============================================================

create extension if not exists pgcrypto;

-- ─── Scan sessions ──────────────────────────────────────────────────────────
-- One row per completed pipeline run (SSE /scan/upload or sync /scan/process).

create table if not exists scan_sessions (
    id                        uuid primary key default gen_random_uuid(),
    user_id                   uuid not null references auth.users(id) on delete cascade,
    scan_date                 timestamptz,
    uploaded_files            jsonb not null default '[]',
    tools_detected            jsonb not null default '[]',
    total_raw_findings        integer default 0,
    total_after_dedup         integer default 0,
    total_after_fp_filter     integer default 0,
    total_scored              integer default 0,
    total_unscored            integer default 0,
    processing_time_seconds   numeric,
    created_at                timestamptz not null default now()
);

create index if not exists idx_scan_sessions_user_id on scan_sessions(user_id);

-- ─── Findings ───────────────────────────────────────────────────────────────
-- One row per CanonicalFinding. `data` holds the full pipeline object for
-- fidelity; the other columns are pulled out for cheap filtering/grouping
-- (Targets tab, Findings accordion).

create table if not exists findings (
    id                uuid primary key default gen_random_uuid(),
    finding_id        text not null,
    session_id        uuid not null references scan_sessions(id) on delete cascade,
    user_id           uuid not null references auth.users(id) on delete cascade,
    source_tool       text,
    vulnerability_name text,
    cve_id            text,
    cwe_id            text,
    severity          text,
    finding_type      text,
    asset_host        text,
    asset_path        text,
    data              jsonb not null,
    created_at        timestamptz not null default now()
);

create index if not exists idx_findings_session_id on findings(session_id);
create index if not exists idx_findings_user_id on findings(user_id);
create index if not exists idx_findings_asset_host on findings(asset_host);
create index if not exists idx_findings_cve_id on findings(cve_id);

-- ─── Risk scores ────────────────────────────────────────────────────────────

create table if not exists risk_scores (
    id                      uuid primary key default gen_random_uuid(),
    session_id              uuid not null references scan_sessions(id) on delete cascade,
    finding_id              uuid not null references findings(id) on delete cascade,
    cvss_component          numeric,
    kev_component           numeric,
    epss_component          numeric,
    exploitdb_component     numeric,
    github_poc_component    numeric,
    cwe_component           numeric,
    base_score              numeric,
    criticality_multiplier  numeric default 1.0,
    final_score             numeric,
    priority_tier           text,
    scoring_method          text,
    created_at              timestamptz not null default now()
);

create index if not exists idx_risk_scores_session_id on risk_scores(session_id);
create index if not exists idx_risk_scores_finding_id on risk_scores(finding_id);

-- ─── GitHub connections ─────────────────────────────────────────────────────
-- Migrated from database_setup.sql (MySQL) + app_user_id linking a GitHub
-- connection to the logged-in Supabase user.

create table if not exists github_connections (
    id                      uuid primary key default gen_random_uuid(),
    app_user_id             uuid references auth.users(id) on delete cascade,
    github_user_id          bigint not null unique,
    github_username         text not null,
    github_email            text,
    access_token_encrypted  text not null,
    token_scope             text,
    connected_at            timestamptz not null default now(),
    updated_at              timestamptz not null default now()
);

create index if not exists idx_github_connections_app_user_id on github_connections(app_user_id);

-- ─── GitHub repositories ────────────────────────────────────────────────────

create table if not exists github_repositories (
    id              uuid primary key default gen_random_uuid(),
    connection_id   uuid not null references github_connections(id) on delete cascade,
    repo_id         bigint not null,
    repo_name       text not null,
    repo_full_name  text not null,
    is_private      boolean default false,
    repo_url        text,
    selected_at     timestamptz not null default now(),
    unique (connection_id, repo_id)
);

-- ─── GitHub issues ──────────────────────────────────────────────────────────

create table if not exists github_issues (
    id              uuid primary key default gen_random_uuid(),
    connection_id   uuid not null references github_connections(id) on delete cascade,
    repository_id   uuid not null references github_repositories(id) on delete cascade,
    finding_id      text not null,
    issue_number    integer not null,
    issue_url       text not null,
    issue_title     text not null,
    status          text default 'open' check (status in ('open', 'closed')),
    assignee        text,
    labels          jsonb default '[]',
    milestone       text,
    created_at      timestamptz not null default now(),
    closed_at       timestamptz
);

create index if not exists idx_github_issues_finding_id on github_issues(finding_id);
create index if not exists idx_github_issues_status on github_issues(status);

-- ─── Row Level Security ─────────────────────────────────────────────────────
-- Backend writes over a direct Postgres connection (service credentials),
-- which bypasses RLS. These policies are a defense-in-depth backstop in
-- case anything ever queries Supabase directly with a user's own JWT.

alter table scan_sessions enable row level security;
alter table findings enable row level security;
alter table risk_scores enable row level security;
alter table github_connections enable row level security;
alter table github_repositories enable row level security;
alter table github_issues enable row level security;

create policy "own scan_sessions" on scan_sessions
    for all using (auth.uid() = user_id);

create policy "own findings" on findings
    for all using (auth.uid() = user_id);

create policy "own risk_scores" on risk_scores
    for all using (
        exists (
            select 1 from scan_sessions s
            where s.id = risk_scores.session_id and s.user_id = auth.uid()
        )
    );

create policy "own github_connections" on github_connections
    for all using (auth.uid() = app_user_id);

create policy "own github_repositories" on github_repositories
    for all using (
        exists (
            select 1 from github_connections c
            where c.id = github_repositories.connection_id and c.app_user_id = auth.uid()
        )
    );

create policy "own github_issues" on github_issues
    for all using (
        exists (
            select 1 from github_connections c
            where c.id = github_issues.connection_id and c.app_user_id = auth.uid()
        )
    );
