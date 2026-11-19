
CREATE TABLE managers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(20) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    mfa_secret_encrypted TEXT NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'owner',
    account_status VARCHAR(20) NOT NULL DEFAULT 'active',
    email_verified BOOLEAN NOT NULL DEFAULT TRUE,
    mfa_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE manager_setup (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(20) NOT NULL,
    email VARCHAR(255) NOT NULL,
    verification_hash TEXT NOT NULL,
    verification_expires TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ,
    password_hash TEXT,
    mfa_secret_encrypted TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX manager_setup_expiry_idx
ON manager_setup (verification_expires);

