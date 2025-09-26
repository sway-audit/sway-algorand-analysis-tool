const http = require('http');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

// Smart Contract Analysis Engine
class SmartContractAnalyzer {
  constructor() {
    this.vulnerabilityPatterns = {
      // TEAL Security Patterns
      'insufficient_access_control': {
        patterns: [
          /global\s+ZeroAddress/i,
          /txn\s+Sender/i,
          /txn\s+ApplicationID/i
        ],
        severity: 'HIGH',
        description: 'Insufficient access control checks'
      },
      'reentrancy_vulnerability': {
        patterns: [
          /itxn_submit/i,
          /inner_txn/i,
          /app_local_put.*app_local_get/i
        ],
        severity: 'CRITICAL',
        description: 'Potential reentrancy vulnerability'
      },
      'integer_overflow': {
        patterns: [
          /\+(?!\s*int)/,
          /\-(?!\s*int)/,
          /\*(?!\s*int)/,
          /\/(?!\s*int)/
        ],
        severity: 'HIGH',
        description: 'Potential integer overflow/underflow'
      },
      'unchecked_external_calls': {
        patterns: [
          /itxn_field\s+TypeEnum/i,
          /itxn_field\s+Receiver/i,
          /itxn_submit/i
        ],
        severity: 'MEDIUM',
        description: 'Unchecked external calls'
      },
      'hardcoded_values': {
        patterns: [
          /int\s+\d{10,}/,
          /"[A-Za-z0-9+/]{20,}"/,
          /addr\s+[A-Z2-7]{58}/
        ],
        severity: 'LOW',
        description: 'Hardcoded sensitive values'
      },
      'missing_validation': {
        patterns: [
          /txn\s+ApplicationArgs/i,
          /btoi/i,
          /extract/i
        ],
        severity: 'MEDIUM',
        description: 'Missing input validation'
      }
    };

    this.gasOptimizationPatterns = [
      {
        pattern: /int\s+0\s*==\s*/i,
        suggestion: 'Use !',
        savings: 2
      },
      {
        pattern: /dup\s*dup/i,
        suggestion: 'Combine duplicate operations',
        savings: 1
      },
      {
        pattern: /global\s+LatestTimestamp.*global\s+LatestTimestamp/i,
        suggestion: 'Cache global values',
        savings: 3
      }
    ];
  }

  analyzeContract(code, language = 'teal') {
    const analysis = {
      security_score: 100,
      vulnerabilities: [],
      gas_optimizations: [],
      code_quality: {
        complexity: 'LOW',
        maintainability: 'HIGH',
        readability: 'HIGH'
      },
      recommendations: []
    };

    // Security Analysis
    for (const [vulnType, config] of Object.entries(this.vulnerabilityPatterns)) {
      for (const pattern of config.patterns) {
        const matches = [...code.matchAll(new RegExp(pattern.source, 'gi'))];
        
        if (matches.length > 0) {
          const vulnerability = {
            type: vulnType,
            severity: config.severity,
            description: config.description,
            line_numbers: [],
            count: matches.length,
            recommendation: this.getRecommendation(vulnType)
          };

          // Find line numbers for matches
          const lines = code.split('\n');
          lines.forEach((line, index) => {
            if (pattern.test(line)) {
              vulnerability.line_numbers.push(index + 1);
            }
          });

          analysis.vulnerabilities.push(vulnerability);

          // Reduce security score based on severity
          const scoreReduction = {
            'CRITICAL': 30,
            'HIGH': 20,
            'MEDIUM': 10,
            'LOW': 5
          };
          analysis.security_score -= scoreReduction[config.severity] || 5;
        }
      }
    }

    // Gas Optimization Analysis
    for (const optimization of this.gasOptimizationPatterns) {
      const matches = [...code.matchAll(new RegExp(optimization.pattern.source, 'gi'))];
      
      if (matches.length > 0) {
        analysis.gas_optimizations.push({
          type: 'optimization',
          description: optimization.suggestion,
          potential_savings: optimization.savings * matches.length,
          occurrences: matches.length
        });
      }
    }

    // Code Quality Analysis
    const lines = code.split('\n').filter(line => line.trim());
    const complexity = this.calculateComplexity(code);
    
    analysis.code_quality = {
      complexity: complexity > 20 ? 'HIGH' : complexity > 10 ? 'MEDIUM' : 'LOW',
      maintainability: lines.length > 200 ? 'LOW' : lines.length > 100 ? 'MEDIUM' : 'HIGH',
      readability: this.calculateReadability(code),
      lines_of_code: lines.length
    };

    // Generate recommendations
    analysis.recommendations = this.generateRecommendations(analysis);

    // Ensure security score doesn't go below 0
    analysis.security_score = Math.max(0, analysis.security_score);

    return analysis;
  }

  calculateComplexity(code) {
    const complexityFactors = [
      /bnz|bz/gi,  // Branches
      /loop|while/gi,  // Loops
      /callsub/gi,  // Function calls
      /switch/gi   // Switch statements
    ];

    let complexity = 1; // Base complexity
    
    for (const factor of complexityFactors) {
      const matches = code.match(factor) || [];
      complexity += matches.length;
    }

    return complexity;
  }

  calculateReadability(code) {
    const lines = code.split('\n');
    let commentLines = 0;
    let codeLines = 0;

    lines.forEach(line => {
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('#')) {
        commentLines++;
      } else if (trimmed.length > 0) {
        codeLines++;
      }
    });

    const commentRatio = codeLines > 0 ? commentLines / codeLines : 0;
    
    if (commentRatio > 0.3) return 'HIGH';
    if (commentRatio > 0.1) return 'MEDIUM';
    return 'LOW';
  }

  getRecommendation(vulnType) {
    const recommendations = {
      'insufficient_access_control': 'Implement proper access control checks using sender verification',
      'reentrancy_vulnerability': 'Use checks-effects-interactions pattern and state locks',
      'integer_overflow': 'Add bounds checking and use safe arithmetic operations',
      'unchecked_external_calls': 'Validate all external call parameters and return values',
      'hardcoded_values': 'Use configuration parameters or constants instead of hardcoded values',
      'missing_validation': 'Add input validation for all user-provided data'
    };

    return recommendations[vulnType] || 'Review and improve code security';
  }

  generateRecommendations(analysis) {
    const recommendations = [];

    if (analysis.security_score < 70) {
      recommendations.push('Address critical security vulnerabilities before deployment');
    }

    if (analysis.vulnerabilities.length > 5) {
      recommendations.push('Consider refactoring to reduce complexity and vulnerability surface');
    }

    if (analysis.code_quality.complexity === 'HIGH') {
      recommendations.push('Break down complex functions into smaller, manageable pieces');
    }

    if (analysis.gas_optimizations.length > 0) {
      recommendations.push('Implement suggested gas optimizations to reduce transaction costs');
    }

    if (analysis.code_quality.readability === 'LOW') {
      recommendations.push('Add more comments and documentation for better maintainability');
    }

    return recommendations;
  }

  detectLanguage(code) {
    // Simple heuristics to detect TEAL vs PyTeal
    const pytealPatterns = [
      /from pyteal import/i,
      /import pyteal/i,
      /def\s+\w+\(/,
      /class\s+\w+/,
      /Seq\(/,
      /If\(/,
      /App\./
    ];

    const tealPatterns = [
      /^int\s+\d+$/m,
      /^txn\s+/m,
      /^global\s+/m,
      /^bnz\s+/m,
      /^bz\s+/m,
      /^\w+:$/m  // Labels
    ];

    const pytealMatches = pytealPatterns.reduce((count, pattern) => {
      return count + (code.match(pattern) || []).length;
    }, 0);

    const tealMatches = tealPatterns.reduce((count, pattern) => {
      return count + (code.match(pattern) || []).length;
    }, 0);

    return pytealMatches > tealMatches ? 'pyteal' : 'teal';
  }
}

// HTTP Server
class ContractAuditServer {
  constructor() {
    this.analyzer = new SmartContractAnalyzer();
    this.server = http.createServer(this.handleRequest.bind(this));
  }

  async handleRequest(req, res) {
    // Enable CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
      res.writeHead(200);
      res.end();
      return;
    }

    const url = new URL(req.url, `http://${req.headers.host}`);
    const method = req.method;
    const pathname = url.pathname;

    console.log(`${method} ${pathname}`);

    try {
      if (method === 'GET' && pathname === '/health') {
        await this.handleHealth(req, res);
      } else if (method === 'POST' && pathname === '/audit') {
        await this.handleFileUpload(req, res);
      } else if (method === 'POST' && pathname === '/audit/text') {
        await this.handleTextAudit(req, res);
      } else {
        this.sendError(res, 404, 'Endpoint not found');
      }
    } catch (error) {
      console.error('Server error:', error);
      this.sendError(res, 500, 'Internal server error');
    }
  }

  async handleHealth(req, res) {
    const health = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
      analyzer: 'ready'
    };

    this.sendJson(res, 200, health);
  }

  async handleTextAudit(req, res) {
    const body = await this.getRequestBody(req);
    
    if (!body.contract_code || typeof body.contract_code !== 'string') {
      this.sendError(res, 400, 'Code is required');
      return;
    }

    const language = body.language || this.analyzer.detectLanguage(body.code);
    const analysis = this.analyzer.analyzeContract(body.code, language);

    // Format response to match frontend expectations
    const result = {
      analysisReport: {
        fileName: body.filename || 'contract.teal',
        timestamp: new Date().toISOString(),
        overallRiskScore: this.getRiskLevel(analysis.security_score),
        summary: this.generateSummary(analysis),
        findings: this.formatFindings(analysis.vulnerabilities, body.contract_code)
      }
    };

    this.sendJson(res, 200, result);
  }

  async handleFileUpload(req, res) {
    // Handle multipart form data
    const body = await this.getRequestBody(req);
    
    if (!body.contract_code) {
      this.sendError(res, 400, 'No contract code provided');
      return;
    }

    const language = this.analyzer.detectLanguage(body.contract_code);
    const analysis = this.analyzer.analyzeContract(body.contract_code, language);

    const result = {
      analysisReport: {
        fileName: body.filename || 'contract.teal',
        timestamp: new Date().toISOString(),
        overallRiskScore: this.getRiskLevel(analysis.security_score),
        summary: this.generateSummary(analysis),
        findings: this.formatFindings(analysis.vulnerabilities, body.contract_code)
      }
    };

    this.sendJson(res, 200, result);
  }

  getRiskLevel(securityScore) {
    if (securityScore >= 90) return 'Passed';
    if (securityScore >= 70) return 'Low';
    if (securityScore >= 50) return 'Medium';
    if (securityScore >= 30) return 'High';
    return 'Critical';
  }

  generateSummary(analysis) {
    const vulnCount = analysis.vulnerabilities.length;
    const score = analysis.security_score;
    
    if (vulnCount === 0) {
      return 'No security vulnerabilities detected. The contract follows good security practices.';
    } else {
      return `Found ${vulnCount} security issue${vulnCount > 1 ? 's' : ''} with an overall security score of ${score}/100. Review and address the identified vulnerabilities before deployment.`;
    }
  }

  formatFindings(vulnerabilities, contractCode) {
    const lines = contractCode.split('\n');
    
    return vulnerabilities.map(vuln => ({
      vulnerabilityName: this.formatVulnName(vuln.type),
      severity: this.capitalizeSeverity(vuln.severity),
      description: vuln.description,
      lineNumber: vuln.line_numbers[0] || 1,
      vulnerableCodeSnippet: this.getCodeSnippet(lines, vuln.line_numbers[0] || 1),
      recommendedFix: vuln.recommendation,
      cwe: this.getCweMapping(vuln.type)
    }));
  }

  formatVulnName(type) {
    return type.split('_').map(word => 
      word.charAt(0).toUpperCase() + word.slice(1)
    ).join(' ');
  }

  capitalizeSeverity(severity) {
    return severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase();
  }

  getCodeSnippet(lines, lineNumber) {
    const index = lineNumber - 1;
    if (index >= 0 && index < lines.length) {
      return lines[index].trim();
    }
    return 'Code snippet not available';
  }

  getCweMapping(vulnType) {
    const cweMap = {
      'insufficient_access_control': 'CWE-285',
      'reentrancy_vulnerability': 'CWE-362', 
      'integer_overflow': 'CWE-190',
      'unchecked_external_calls': 'CWE-252',
      'hardcoded_values': 'CWE-798',
      'missing_validation': 'CWE-20'
    };
    return cweMap[vulnType] || 'CWE-Other';
  }

  async getRequestBody(req) {
    return new Promise((resolve, reject) => {
      let body = '';
      
      req.on('data', chunk => {
        body += chunk.toString();
      });
      
      req.on('end', () => {
        try {
          const parsed = body ? JSON.parse(body) : {};
          resolve(parsed);
        } catch (error) {
          reject(new Error('Invalid JSON'));
        }
      });
      
      req.on('error', reject);
    });
  }

  sendJson(res, statusCode, data) {
    res.writeHead(statusCode, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data, null, 2));
  }

  sendError(res, statusCode, message) {
    this.sendJson(res, statusCode, { error: message });
  }

  start(port = 8000) {
    this.server.listen(port, () => {
      console.log(`Smart Contract Audit Server running on http://localhost:${port}`);
      console.log('Available endpoints:');
      console.log('  GET  /health            - Health check');
      console.log('  POST /audit/text        - Analyze text input');
      console.log('  POST /audit             - Analyze uploaded file');
      console.log('  POST /audit/github      - Analyze GitHub repository');
      console.log('  POST /audit/address     - Analyze contract address');
    });
  }
}

// DEPRECATED: This Node.js server has been replaced by the Python FastAPI backend (main.py)
// To start the new backend, run: python3 main.py
// This file is kept for reference only

// Start the server
if (require.main === module) {
  console.log("⚠️  DEPRECATED: This Node.js server has been replaced!");
  console.log("🐍 Please use the new Python FastAPI backend instead:");
  console.log("   python3 main.py");
  console.log("");
  console.log("The new backend provides:");
  console.log("✅ Enhanced security analysis");
  console.log("✅ GitHub integration");
  console.log("✅ Blockchain address support");
  console.log("✅ Production-ready error handling");
  console.log("");
  process.exit(1);
}

module.exports = ContractAuditServer;