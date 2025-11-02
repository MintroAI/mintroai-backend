-- MintroAI User Database Schema
-- This script creates the users table for persistent user storage

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_address VARCHAR(255) NOT NULL,
    protocol VARCHAR(20) NOT NULL,
    first_login_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_login_at TIMESTAMP WITH TIME ZONE NOT NULL,
    login_count INTEGER DEFAULT 0,
    challenge_count INTEGER DEFAULT 0,
    user_tier VARCHAR(20) DEFAULT 'free',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT unique_wallet_protocol UNIQUE (wallet_address, protocol)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_wallet_protocol ON users(wallet_address, protocol);
CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login_at);
CREATE INDEX IF NOT EXISTS idx_users_tier ON users(user_tier);

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger to automatically update updated_at
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Add comments for documentation
COMMENT ON TABLE users IS 'Persistent user storage for authentication system';
COMMENT ON COLUMN users.wallet_address IS 'Blockchain wallet address (EVM or NEAR)';
COMMENT ON COLUMN users.protocol IS 'Blockchain protocol: evm or near';
COMMENT ON COLUMN users.first_login_at IS 'Timestamp of first successful login';
COMMENT ON COLUMN users.last_login_at IS 'Timestamp of most recent successful login';
COMMENT ON COLUMN users.login_count IS 'Total number of successful logins';
COMMENT ON COLUMN users.challenge_count IS 'Total number of authentication challenges created';
COMMENT ON COLUMN users.user_tier IS 'User tier: free, premium, or enterprise';

-- =====================================================
-- Contract Activities Table
-- =====================================================

CREATE TABLE IF NOT EXISTS contract_activities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_address VARCHAR(255) NOT NULL,
    activity_type VARCHAR(50) NOT NULL,
    contract_type VARCHAR(50),
    chat_id VARCHAR(255),
    chain_id VARCHAR(50),
    success BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for contract_activities
CREATE INDEX IF NOT EXISTS idx_contract_activities_wallet ON contract_activities(wallet_address);
CREATE INDEX IF NOT EXISTS idx_contract_activities_type ON contract_activities(activity_type);
CREATE INDEX IF NOT EXISTS idx_contract_activities_created ON contract_activities(created_at);
CREATE INDEX IF NOT EXISTS idx_contract_activities_wallet_type ON contract_activities(wallet_address, activity_type);

-- Add comments
COMMENT ON TABLE contract_activities IS 'Log of all contract-related activities';
COMMENT ON COLUMN contract_activities.wallet_address IS 'User wallet address performing the activity';
COMMENT ON COLUMN contract_activities.activity_type IS 'Type of activity: generate, compile, get_price';
COMMENT ON COLUMN contract_activities.contract_type IS 'Contract type: token or vesting';
COMMENT ON COLUMN contract_activities.chat_id IS 'Associated chat ID if available';
COMMENT ON COLUMN contract_activities.chain_id IS 'Target blockchain chain ID';
COMMENT ON COLUMN contract_activities.success IS 'Whether the operation was successful';

-- =====================================================
-- Funding Activities Table
-- =====================================================

CREATE TABLE IF NOT EXISTS funding_activities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_address VARCHAR(255) NOT NULL,
    funded_address VARCHAR(255) NOT NULL,
    chain_id VARCHAR(50) NOT NULL,
    amount VARCHAR(100),
    tx_hash VARCHAR(255),
    success BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for funding_activities
CREATE INDEX IF NOT EXISTS idx_funding_activities_wallet ON funding_activities(wallet_address);
CREATE INDEX IF NOT EXISTS idx_funding_activities_funded_addr ON funding_activities(funded_address);
CREATE INDEX IF NOT EXISTS idx_funding_activities_chain ON funding_activities(chain_id);
CREATE INDEX IF NOT EXISTS idx_funding_activities_created ON funding_activities(created_at);
CREATE INDEX IF NOT EXISTS idx_funding_activities_wallet_chain ON funding_activities(wallet_address, chain_id);

-- Add comments
COMMENT ON TABLE funding_activities IS 'Log of all funding activities';
COMMENT ON COLUMN funding_activities.wallet_address IS 'User wallet address requesting funding';
COMMENT ON COLUMN funding_activities.funded_address IS 'Address that received the funds';
COMMENT ON COLUMN funding_activities.chain_id IS 'Target blockchain chain ID';
COMMENT ON COLUMN funding_activities.amount IS 'Amount funded (as string)';
COMMENT ON COLUMN funding_activities.tx_hash IS 'Transaction hash from blockchain';
COMMENT ON COLUMN funding_activities.success IS 'Whether the funding was successful';

