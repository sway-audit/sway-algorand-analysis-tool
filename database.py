"""
Database models and configuration for Algorand Smart Contract Audit Tool
Enterprise-grade PostgreSQL database with SQLAlchemy ORM
"""

import os
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from sqlalchemy import create_engine, Column, String, DateTime, Text, JSON, Integer, Float, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.types import TypeDecorator, CHAR
import logging

logger = logging.getLogger(__name__)

# Database Configuration - Use SQLite for development, PostgreSQL for production
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./algorand_audit.db"  # SQLite for development
    # "postgresql://postgres:password@localhost:5432/algorand_audit"  # PostgreSQL for production
)

# Create engine with connection pooling
engine = create_engine(
    DATABASE_URL,
    pool_size=20,
    max_overflow=30,
    pool_pre_ping=True,
    pool_recycle=3600,
    echo=False  # Set to True for SQL debugging
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# SQLite-compatible UUID type
class GUID(TypeDecorator):
    """Platform-independent GUID type.
    Uses PostgreSQL's UUID type, otherwise uses CHAR(36), storing as stringified hex values.
    """
    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(UUID())
        else:
            return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'postgresql':
            return str(value)
        else:
            if not isinstance(value, uuid.UUID):
                return str(uuid.UUID(value))
            else:
                return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        else:
            if not isinstance(value, uuid.UUID):
                return uuid.UUID(value)
            return value

# Database Models
class User(Base):
    """User model for authentication and audit history"""
    __tablename__ = "users"
    
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    full_name = Column(String(255), nullable=True)
    wallet_address = Column(String(100), nullable=True, index=True)
    is_active = Column(Boolean, default=True)
    is_premium = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    audit_reports = relationship("AuditReport", back_populates="user", cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")

class AuditReport(Base):
    """Audit report model storing complete analysis results"""
    __tablename__ = "audit_reports"
    
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id"), nullable=True, index=True)
    
    # Contract Information
    contract_name = Column(String(255), nullable=False)
    contract_type = Column(String(50), nullable=False)  # teal, pyteal, reach
    contract_source = Column(String(50), nullable=False)  # file, github, address, text
    contract_code = Column(Text, nullable=False)
    contract_hash = Column(String(64), nullable=False, index=True)  # SHA-256 hash
    
    # Source Details
    github_url = Column(String(500), nullable=True)
    blockchain_address = Column(String(100), nullable=True)
    file_name = Column(String(255), nullable=False)
    file_size = Column(Integer, nullable=True)
    
    # Analysis Results
    overall_risk_score = Column(String(20), nullable=False)
    security_score = Column(Float, nullable=False)  # 0-100
    complexity_score = Column(Float, nullable=False)  # 0-100
    gas_efficiency_score = Column(Float, nullable=False)  # 0-100
    
    # Findings
    total_findings = Column(Integer, default=0)
    critical_findings = Column(Integer, default=0)
    high_findings = Column(Integer, default=0)
    medium_findings = Column(Integer, default=0)
    low_findings = Column(Integer, default=0)
    informational_findings = Column(Integer, default=0)
    
    # Complete Analysis Data
    findings_data = Column(JSON, nullable=False)  # Complete findings array
    analysis_metadata = Column(JSON, nullable=False)  # Analysis configuration and metadata
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Analysis Performance
    analysis_duration_ms = Column(Integer, nullable=True)
    lines_of_code = Column(Integer, nullable=True)
    
    # Sharing and Export
    is_public = Column(Boolean, default=False)
    share_token = Column(String(64), nullable=True, unique=True, index=True)
    export_count = Column(Integer, default=0)
    
    # Relationships
    user = relationship("User", back_populates="audit_reports")
    vulnerability_findings = relationship("VulnerabilityFinding", back_populates="audit_report", cascade="all, delete-orphan")

class VulnerabilityFinding(Base):
    """Individual vulnerability finding details"""
    __tablename__ = "vulnerability_findings"
    
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    audit_report_id = Column(GUID(), ForeignKey("audit_reports.id"), nullable=False, index=True)
    
    # Vulnerability Details
    vulnerability_name = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    category = Column(String(100), nullable=False, index=True)
    cwe_id = Column(String(20), nullable=True)
    owasp_category = Column(String(100), nullable=True)
    
    # Location Information
    line_number = Column(Integer, nullable=False)
    column_number = Column(Integer, nullable=True)
    function_name = Column(String(255), nullable=True)
    code_snippet = Column(Text, nullable=False)
    
    # Description and Remediation
    description = Column(Text, nullable=False)
    impact = Column(Text, nullable=True)
    recommended_fix = Column(Text, nullable=True)
    remediation_effort = Column(String(20), nullable=True)  # Low, Medium, High
    
    # Risk Assessment
    likelihood = Column(String(20), nullable=True)  # Low, Medium, High
    impact_score = Column(Float, nullable=True)  # 0-10
    exploitability = Column(String(20), nullable=True)
    
    # Additional Data
    references = Column(JSON, nullable=True)  # External references
    tags = Column(JSON, nullable=True)  # Custom tags
    
    # Status Tracking
    status = Column(String(20), default="open")  # open, acknowledged, fixed, false_positive
    resolution_notes = Column(Text, nullable=True)
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    audit_report = relationship("AuditReport", back_populates="vulnerability_findings")

class APIKey(Base):
    """API keys for programmatic access"""
    __tablename__ = "api_keys"
    
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id"), nullable=False, index=True)
    
    name = Column(String(255), nullable=False)
    key_hash = Column(String(64), nullable=False, unique=True, index=True)
    key_prefix = Column(String(10), nullable=False)  # First 8 chars for display
    
    is_active = Column(Boolean, default=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    usage_count = Column(Integer, default=0)
    rate_limit_per_hour = Column(Integer, default=100)
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="api_keys")

class AuditSession(Base):
    """Track analysis sessions for performance monitoring"""
    __tablename__ = "audit_sessions"
    
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id"), nullable=True, index=True)
    
    session_type = Column(String(50), nullable=False)  # web, api, batch
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    
    # Performance Metrics
    total_duration_ms = Column(Integer, nullable=True)
    parsing_duration_ms = Column(Integer, nullable=True)
    analysis_duration_ms = Column(Integer, nullable=True)
    
    # Request Details
    contract_size_bytes = Column(Integer, nullable=True)
    contract_lines = Column(Integer, nullable=True)
    analysis_type = Column(String(50), nullable=True)
    
    # Results
    success = Column(Boolean, nullable=False)
    error_message = Column(Text, nullable=True)
    findings_count = Column(Integer, nullable=True)
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

# Database Utility Functions
def get_db() -> Session:
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_tables():
    """Create all database tables"""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {str(e)}")
        raise

def drop_tables():
    """Drop all database tables (use with caution)"""
    try:
        Base.metadata.drop_all(bind=engine)
        logger.info("Database tables dropped successfully")
    except Exception as e:
        logger.error(f"Failed to drop database tables: {str(e)}")
        raise

def get_database_session() -> Session:
    """Get a new database session"""
    return SessionLocal()

# Database Health Check
def check_database_health() -> bool:
    """Check if database is accessible"""
    try:
        from sqlalchemy import text
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        return True
    except Exception as e:
        logger.error(f"Database health check failed: {str(e)}")
        return False
