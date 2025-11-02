"""
SQLAlchemy ORM models for database tables
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, Boolean, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
import uuid

Base = declarative_base()


class UserModel(Base):
    """SQLAlchemy ORM model for users table"""
    
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    wallet_address = Column(String(255), nullable=False)
    protocol = Column(String(20), nullable=False)
    first_login_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_login_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    login_count = Column(Integer, default=0, nullable=False)
    challenge_count = Column(Integer, default=0, nullable=False)
    user_tier = Column(String(20), default='free', nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    __table_args__ = (
        Index('idx_users_wallet_protocol', 'wallet_address', 'protocol', unique=True),
        Index('idx_users_last_login', 'last_login_at'),
        Index('idx_users_tier', 'user_tier'),
    )
    
    def __repr__(self):
        return f"<User(wallet_address='{self.wallet_address}', protocol='{self.protocol}', tier='{self.user_tier}')>"


class ContractActivityModel(Base):
    """SQLAlchemy ORM model for contract_activities table"""
    
    __tablename__ = "contract_activities"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    wallet_address = Column(String(255), nullable=False)
    activity_type = Column(String(50), nullable=False)
    contract_type = Column(String(50), nullable=True)
    chat_id = Column(String(255), nullable=True)
    chain_id = Column(String(50), nullable=True)
    success = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    __table_args__ = (
        Index('idx_contract_activities_wallet', 'wallet_address'),
        Index('idx_contract_activities_type', 'activity_type'),
        Index('idx_contract_activities_created', 'created_at'),
        Index('idx_contract_activities_wallet_type', 'wallet_address', 'activity_type'),
    )
    
    def __repr__(self):
        return f"<ContractActivity(wallet='{self.wallet_address}', type='{self.activity_type}', success={self.success})>"


class FundingActivityModel(Base):
    """SQLAlchemy ORM model for funding_activities table"""
    
    __tablename__ = "funding_activities"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    wallet_address = Column(String(255), nullable=False)
    funded_address = Column(String(255), nullable=False)
    chain_id = Column(String(50), nullable=False)
    amount = Column(String(100), nullable=True)
    tx_hash = Column(String(255), nullable=True)
    success = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    __table_args__ = (
        Index('idx_funding_activities_wallet', 'wallet_address'),
        Index('idx_funding_activities_funded_addr', 'funded_address'),
        Index('idx_funding_activities_chain', 'chain_id'),
        Index('idx_funding_activities_created', 'created_at'),
        Index('idx_funding_activities_wallet_chain', 'wallet_address', 'chain_id'),
    )
    
    def __repr__(self):
        return f"<FundingActivity(wallet='{self.wallet_address}', chain='{self.chain_id}', success={self.success})>"

