# Algorand Smart Contract Security Audit Tool - Backend

## Overview

This is a production-ready FastAPI backend for analyzing Algorand smart contracts. The system performs comprehensive static analysis (SAST) on TEAL and PyTeal contracts to identify security vulnerabilities.

## Features

- **Comprehensive Security Analysis**: Detects rekeying vulnerabilities, access control issues, atomic group safety problems, integer overflows, and reentrancy vulnerabilities
- **Multi-Language Support**: Handles both TEAL and PyTeal contracts
- **AST-Based Analysis**: Uses Abstract Syntax Tree parsing for accurate code analysis
- **Production-Ready**: Includes proper error handling, logging, and security measures
- **API Compatibility**: Maintains compatibility with existing frontend

## Quick Start

### Prerequisites

- Python 3.9 or higher
- pip package manager

### Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Start the server:
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The server will be available at `http://localhost:8000`

### API Documentation

Once running, visit:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## API Endpoints

### Health Check
```
GET /health
```
Returns server health status.

### Text Analysis
```
POST /audit/text
Content-Type: application/json

{
  "contract_code": "TEAL or PyTeal code",
  "filename": "contract.teal",
  "language": "teal" // optional
}
```

### File Upload Analysis
```
POST /audit
Content-Type: multipart/form-data

file: contract file (.teal, .py, .reach)
```

### GitHub Repository Analysis
```
POST /audit/github
Content-Type: application/json

{
  "github_url": "https://github.com/owner/repo/blob/main/contract.py"
}
```

### Blockchain Address Analysis
```
POST /audit/address
Content-Type: application/json

{
  "contract_address": "ALGORAND_CONTRACT_ADDRESS"
}
```

## Security Analysis Features

### Vulnerability Detection

1. **Rekeying Vulnerabilities** (Critical)
   - Detects unprotected RekeyTo field access
   - Prevents account takeover attacks

2. **Access Control Issues** (High)
   - Identifies unprotected state modifications
   - Ensures proper authorization checks

3. **Atomic Group Safety** (Medium)
   - Validates group transaction handling
   - Checks for group size validation

4. **Integer Overflow** (Medium)
   - Detects arithmetic operations without overflow protection
   - Prevents unexpected calculation results

5. **Reentrancy Protection** (High)
   - Identifies potential reentrancy vulnerabilities
   - Ensures safe inner transaction handling

### Response Format

```json
{
  "analysisReport": {
    "fileName": "contract.teal",
    "timestamp": "2024-01-01T00:00:00Z",
    "overallRiskScore": "High",
    "summary": "Found 2 security issues (1 Critical, 1 High). Overall risk level: Critical.",
    "findings": [
      {
        "vulnerabilityName": "Potential Rekeying Vulnerability",
        "severity": "Critical",
        "description": "Detailed vulnerability description...",
        "lineNumber": 15,
        "vulnerableCodeSnippet": "txn RekeyTo",
        "recommendedFix": "Add validation: txn RekeyTo; global ZeroAddress; ==; assert",
        "cwe": "CWE-284"
      }
    ]
  }
}
```

## Testing

Run the test suite:
```bash
python test_backend.py
```

This will test all endpoints and verify the analysis functionality.

## Development

### Project Structure

```
main.py              # Main FastAPI application
requirements.txt     # Python dependencies
test_backend.py      # Test suite
README_BACKEND.md    # This file
```

### Key Components

- **AST Parser**: Converts TEAL code to structured representation
- **Security Engine**: Runs multiple vulnerability checks
- **Report Generator**: Creates structured analysis reports
- **API Layer**: FastAPI endpoints with proper error handling

### Adding New Vulnerability Checks

1. Create a new check function in `main.py`:
```python
def check_new_vulnerability(ast: List[ASTNode]) -> List[VulnerabilityFinding]:
    # Implementation here
    pass
```

2. Add the check to `run_sast_engine()`:
```python
all_findings.extend(check_new_vulnerability(ast))
```

## Production Deployment

### Environment Variables

- `LOG_LEVEL`: Logging level (default: INFO)
- `PORT`: Server port (default: 8000)
- `HOST`: Server host (default: 0.0.0.0)

### Security Considerations

- CORS is configured for development (`allow_origins=["*"]`)
- In production, restrict CORS to your frontend domain
- PyTeal compilation uses safe simulation mode
- All user inputs are validated and sanitized

### Docker Deployment

Create a `Dockerfile`:
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY main.py .
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

## Troubleshooting

### Common Issues

1. **Port already in use**: Change the port in the uvicorn command
2. **Module not found**: Ensure all dependencies are installed
3. **CORS errors**: Check CORS configuration in production

### Logs

The application logs all important events including:
- Analysis requests and results
- Error conditions and stack traces
- Performance metrics

Check logs for debugging information.

## License

This project is part of the Algorand Smart Contract Security Audit Tool.
