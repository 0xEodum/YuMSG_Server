-- Migration: 001_initial_schema
-- Description: Create initial database schema for YuMSG server
-- Author: YuMSG Development Team
-- Date: 2024-01-15

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Organizations table
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) UNIQUE,
    supported_algorithms JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255),
    password_hash VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    status VARCHAR(30) DEFAULT 'offline_disconnected',
    last_seen TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_blocked BOOLEAN DEFAULT FALSE,
    
    CONSTRAINT valid_status CHECK (status IN ('online', 'offline_connected', 'offline_disconnected')),
    CONSTRAINT valid_username_format CHECK (username ~ '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
);

-- Active WebSocket connections table
CREATE TABLE IF NOT EXISTS active_connections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    connection_id VARCHAR(255) UNIQUE NOT NULL,
    connected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_heartbeat TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT
);

-- Chat metadata table (only relationships between users)
CREATE TABLE IF NOT EXISTS chat_metadata (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user1_id UUID REFERENCES users(id) ON DELETE CASCADE,
    user2_id UUID REFERENCES users(id) ON DELETE CASCADE,
    chat_uuid VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Ensure unique pair of users (order-independent)
    CONSTRAINT unique_user_pair UNIQUE(LEAST(user1_id, user2_id), GREATEST(user1_id, user2_id)),
    -- Ensure users are different
    CONSTRAINT different_users CHECK (user1_id != user2_id)
);

-- Pending messages table (temporary storage for offline users)
CREATE TABLE IF NOT EXISTS pending_messages (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    recipient_id UUID REFERENCES users(id) ON DELETE CASCADE,
    sender_id UUID REFERENCES users(id) ON DELETE CASCADE,
    message_type VARCHAR(50) NOT NULL,
    message_data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() + INTERVAL '7 days'),
    delivered BOOLEAN DEFAULT FALSE
);

-- Audit log table
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    details JSONB,
    ip_address INET,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Blocked users table
CREATE TABLE IF NOT EXISTS blocked_users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    blocked_by UUID REFERENCES users(id) ON DELETE SET NULL,
    reason VARCHAR(100),
    description TEXT,
    blocked_until TIMESTAMP WITH TIME ZONE,
    blocked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_organization ON users(organization_id);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_username_lower ON users(LOWER(username));
CREATE INDEX IF NOT EXISTS idx_users_display_name_gin ON users USING gin(to_tsvector('english', display_name));

CREATE INDEX IF NOT EXISTS idx_active_connections_user ON active_connections(user_id);
CREATE INDEX IF NOT EXISTS idx_active_connections_last_heartbeat ON active_connections(last_heartbeat);

CREATE INDEX IF NOT EXISTS idx_chat_metadata_users ON chat_metadata(user1_id, user2_id);
CREATE INDEX IF NOT EXISTS idx_chat_metadata_chat_uuid ON chat_metadata(chat_uuid);

CREATE INDEX IF NOT EXISTS idx_pending_messages_recipient ON pending_messages(recipient_id);
CREATE INDEX IF NOT EXISTS idx_pending_messages_expires ON pending_messages(expires_at);
CREATE INDEX IF NOT EXISTS idx_pending_messages_delivered ON pending_messages(delivered);

CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at);

CREATE INDEX IF NOT EXISTS idx_blocked_users_user_id ON blocked_users(user_id);
CREATE INDEX IF NOT EXISTS idx_blocked_users_blocked_until ON blocked_users(blocked_until);

-- Function to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for users table
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Function to clean up expired pending messages
CREATE OR REPLACE FUNCTION cleanup_expired_messages()
RETURNS void AS $$
BEGIN
    DELETE FROM pending_messages 
    WHERE expires_at < NOW();
END;
$$ language 'plpgsql';

-- Function to clean up inactive connections
CREATE OR REPLACE FUNCTION cleanup_inactive_connections()
RETURNS void AS $$
BEGIN
    DELETE FROM active_connections 
    WHERE last_heartbeat < (NOW() - INTERVAL '5 minutes');
END;
$$ language 'plpgsql';

-- Insert default organization
INSERT INTO organizations (id, name, domain, supported_algorithms) 
VALUES (
    '00000000-0000-0000-0000-000000000000',
    'Default Organization',
    'localhost',
    '{
        "asymmetric": [
            {
                "name": "NTRU",
                "description": "Решетчатый алгоритм",
                "key_size": 1024,
                "recommended": true
            },
            {
                "name": "BIKE",
                "description": "Код-основанный алгоритм",
                "key_size": 2048,
                "recommended": false
            }
        ],
        "symmetric": [
            {
                "name": "AES-256",
                "description": "Стандарт шифрования",
                "key_size": 256,
                "recommended": true
            },
            {
                "name": "ChaCha20",
                "description": "Потоковый шифр",
                "key_size": 256,
                "recommended": false
            }
        ],
        "signature": [
            {
                "name": "Falcon",
                "description": "Решетчатая подпись",
                "key_size": 1024,
                "recommended": true
            },
            {
                "name": "Dilithium",
                "description": "Модульная решетчатая подпись",
                "key_size": 2048,
                "recommended": false
            }
        ]
    }'::jsonb
) ON CONFLICT (id) DO NOTHING;