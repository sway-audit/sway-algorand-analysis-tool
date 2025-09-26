# SWAY | Algorand Smart Contract Security Audit Tool



## Overview

Static analysis platform for comprehensive security assessment of Algorand smart contracts. This tool provides automated vulnerability detection, code quality analysis, and detailed security reporting for TEAL and PyTeal smart contracts deployed on the Algorand blockchain.

## Architecture

### Core Components

- **FastAPI Backend**: High-performance asynchronous web framework with automatic API documentation
- **SQLAlchemy ORM**: Enterprise database abstraction layer supporting PostgreSQL and SQLite
- **Real-time Analysis Engine**: Advanced static analysis with 15+ vulnerability detection patterns
- **Blockchain Integration**: Direct integration with Algorand mainnet/testnet for contract retrieval
- **GitHub Integration**: Automated contract fetching from public and private repositories
- **Report Generation**: Professional PDF, Excel, and JSON export capabilities

### Security Analysis Features

- **Vulnerability Detection**: Comprehensive pattern matching for common smart contract vulnerabilities
- **Access Control Analysis**: Detection of missing or inadequate permission checks
- **Reentrancy Protection**: Analysis of potential reentrancy attack vectors
- **Integer Overflow Detection**: Identification of arithmetic operation vulnerabilities
- **Gas Optimization**: Performance analysis and efficiency recommendations
- **Compliance Checking**: Regulatory and best practice adherence validation

## Technical Specifications

### Backend Stack

- **Framework**: FastAPI 0.104.1 with Uvicorn ASGI server
- **Database**: SQLAlchemy 2.0.23 with PostgreSQL/SQLite support
- **Authentication**: JWT-based authentication with bcrypt password hashing
- **HTTP Client**: aiohttp 3.9.1 for external API integrations
- **Blockchain SDK**: py-algorand-sdk 2.6.1 for Algorand network interaction

### Frontend Stack

- **Framework**: React 18 with TypeScript
- **Build Tool**: Vite for optimized development and production builds
- **Styling**: Tailwind CSS for responsive design
- **Icons**: Lucide React for consistent iconography
- **HTTP Client**: Axios for API communication

### Database Schema

- **Users**: Authentication and authorization management
- **AuditReports**: Comprehensive analysis results storage
- **VulnerabilityFindings**: Detailed security issue documentation
- **AuditSessions**: Performance monitoring and session tracking
- **APIKeys**: Programmatic access management

### API Endpoints

#### Core Analysis
- `POST /audit/text` - Direct contract code analysis with database storage
- `POST /audit` - File upload analysis with metadata tracking
- `POST /audit/github` - GitHub repository contract analysis with real API integration
- `POST /audit/address` - Blockchain address contract retrieval and analysis

#### Data Management
- `GET /reports/history` - Audit history with pagination and filtering
- `POST /export/report` - Multi-format report generation (PDF, Excel, JSON)
- `GET /health` - System health monitoring and diagnostics

## Installation

### Prerequisites

- Python 3.9+
- Node.js 18+ and npm
- PostgreSQL 12+ (production) or SQLite (development)
- Git

### Environment Setup

```bash
# Clone repository
git clone <repository-url>
cd algorand-smart-contract-audit-tool

# Backend setup
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate  # Windows

# Install backend dependencies
pip install -r requirements.txt

# Frontend setup
npm install

# Initialize database
python3 -c "from database import create_tables; create_tables()"
```

### Configuration

Create `.env` file with required environment variables:

```env
# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/algorand_audit
# DATABASE_URL=sqlite:///./algorand_audit.db  # Development alternative

# GitHub Integration
GITHUB_API_TOKEN=your_github_token_here

# Algorand Network
ALGORAND_ALGOD_ADDRESS=https://mainnet-api.algonode.cloud
ALGORAND_INDEXER_ADDRESS=https://mainnet-idx.algonode.cloud

# Security
SECRET_KEY=your-secret-key-here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Monitoring (Optional)
SENTRY_DSN=your_sentry_dsn_here
```

## Usage

### Development Environment

```bash
# Start backend server
python3 main.py

# Start frontend development server (separate terminal)
npm run dev

# Alternative backend startup with uvicorn
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Production Deployment

```bash
# Production backend with multiple workers
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4

# Build frontend for production
npm run build

# Serve frontend with nginx or similar web server
```

### API Documentation

Access interactive API documentation:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### Application Access

- Frontend: `http://localhost:5173` (development)
- Backend API: `http://localhost:8000`
- Health Check: `http://localhost:8000/health`

## Testing

### Comprehensive Test Suite

```bash
# Run enterprise backend test suite
python3 test_enterprise_backend.py

# Individual component testing
python3 -c "from database import check_database_health; print(check_database_health())"
python3 -c "from integrations import integration_manager; print('Integrations loaded')"
```

### Test Coverage

The test suite validates:
- Health endpoint functionality and system diagnostics
- Text-based contract analysis for TEAL and PyTeal
- File upload processing with database storage and metadata
- GitHub integration with real API calls and fallback mechanisms
- Algorand blockchain integration with contract retrieval
- Audit history retrieval with pagination and filtering
- Report export functionality in PDF, Excel, and JSON formats
- Advanced security analysis with 15+ vulnerability patterns

## Security Considerations

### Input Validation

- Comprehensive sanitization of all user inputs
- File type validation and size limitations
- SQL injection prevention through parameterized queries
- XSS protection with proper output encoding

### Authentication & Authorization

- JWT-based stateless authentication
- Role-based access control (RBAC)
- API key management for programmatic access
- Session management with configurable expiration

### Data Protection

- Encryption at rest for sensitive data
- TLS encryption for data in transit
- Secure password hashing with bcrypt
- Environment-based configuration management

## Performance Optimization

### Database Performance

- Connection pooling with configurable limits
- Query optimization with proper indexing
- Pagination for large dataset handling
- Transaction management for data consistency

### Application Performance

- Asynchronous request processing
- Efficient memory management
- Background task processing
- Response caching for static content

## Monitoring & Logging

### Health Monitoring

- Database connectivity checks
- External API availability monitoring
- System resource utilization tracking
- Error rate and response time metrics

### Structured Logging

- Comprehensive audit trails
- Error tracking with stack traces
- Performance metrics collection
- Security event logging

## Contributing

### Development Guidelines

- Follow PEP 8 style guidelines for Python code
- Implement comprehensive unit tests for all features
- Document all public APIs with detailed specifications
- Use type hints throughout the codebase

### Code Quality Tools

```bash
# Code formatting
black main.py database.py integrations.py

# Import sorting
isort main.py database.py integrations.py

# Type checking
mypy main.py database.py integrations.py

# Linting
flake8 main.py database.py integrations.py
```

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Support

For technical support and enterprise inquiries, please contact the development team or create an issue in the project repository.

## Changelog

### Version 2.0.0
- Complete enterprise architecture implementation
- Real GitHub and Algorand blockchain integrations
- Advanced security analysis with 15+ vulnerability patterns
- Professional report generation capabilities
- Comprehensive database integration with audit history
- Production-ready deployment configuration