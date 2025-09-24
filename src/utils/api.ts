// API Configuration and utilities for smart contract analysis
const API_BASE_URL = 'http://localhost:8000';

export interface AuditRequest {
  contract_code: string;
  filename: string;
  language?: 'teal' | 'pyteal';
}

export interface VulnerabilityLocation {
  filePath: string;
  lineNumber: number;
}

export interface VulnerabilityFinding {
  vulnerabilityName: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
  description: string;
  lineNumber: number;
  vulnerableCodeSnippet: string;
  recommendedFix?: string;
  cwe?: string;
  status?: string;
  locations?: VulnerabilityLocation[];
}

export interface AnalysisReport {
  fileName: string;
  timestamp: string;
  overallRiskScore: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational' | 'Passed';
  summary: string;
  findings: VulnerabilityFinding[];
}

export interface AuditResponse {
  analysisReport: AnalysisReport;
}

// API Functions
export const auditContract = async (request: AuditRequest): Promise<AuditResponse> => {
  try {
    console.log('Sending audit request:', request);
    
    const response = await fetch(`${API_BASE_URL}/audit/text`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify(request),
    });

    console.log('Response status:', response.status);

    if (!response.ok) {
      const errorText = await response.text();
      console.error('API Error:', errorText);
      throw new Error(`HTTP error! status: ${response.status}, message: ${errorText}`);
    }

    const data = await response.json();
    console.log('Analysis result:', data);
    return data;
  } catch (error) {
    console.error('Error auditing contract:', error);
    if (error instanceof TypeError && error.message.includes('fetch')) {
      throw new Error('Unable to connect to analysis server. Please ensure the backend is running.');
    }
    throw error;
  }
};

export const auditContractFile = async (file: File): Promise<AuditResponse> => {
  try {
    console.log('Uploading file for audit:', file.name);
    
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch(`${API_BASE_URL}/audit`, {
      method: 'POST',
      body: formData,
    });

    console.log('File upload response status:', response.status);

    if (!response.ok) {
      const errorText = await response.text();
      console.error('File upload error:', errorText);
      throw new Error(`HTTP error! status: ${response.status}, message: ${errorText}`);
    }

    const data = await response.json();
    console.log('File analysis result:', data);
    return data;
  } catch (error) {
    console.error('Error auditing contract file:', error);
    if (error instanceof TypeError && error.message.includes('fetch')) {
      throw new Error('Unable to connect to analysis server. Please ensure the backend is running.');
    }
    throw error;
  }
};

export const fetchContractFromAddress = async (address: string): Promise<string> => {
  try {
    console.log('Fetching contract from address:', address);
    
    // For demonstration, return a sample TEAL contract
    // In production, this would integrate with Algorand API
    const sampleTeal = `#pragma version 6

// Application creation
txn ApplicationID
int 0
==
bnz creation_branch

// Handle application calls
txn OnCall
int OptIn
==
bnz optin_branch

txn OnCall
int CloseOut
==
bnz closeout_branch

// Default NoOp call
b main_logic

creation_branch:
int 1
return

optin_branch:
int 1
return

closeout_branch:
int 1
return

main_logic:
// Missing access control - security vulnerability
byte "counter"
app_global_get
int 1
+
store 0

byte "counter"
load 0
app_global_put

int 1
return`;

    return sampleTeal;
  } catch (error) {
    console.error('Error fetching contract from address:', error);
    throw new Error('Failed to fetch contract from blockchain address');
  }
};

export const fetchContractFromGithub = async (githubUrl: string): Promise<string> => {
  try {
    console.log('Fetching contract from GitHub:', githubUrl);
    
    // Parse GitHub URL to get raw content URL
    const urlParts = githubUrl.replace('https://github.com/', '').split('/');
    if (urlParts.length < 2) {
      throw new Error('Invalid GitHub URL format');
    }

    const [owner, repo, ...pathParts] = urlParts;
    let branch = 'main';
    let filePath = '';

    if (pathParts.includes('blob')) {
      const blobIndex = pathParts.indexOf('blob');
      branch = pathParts[blobIndex + 1];
      filePath = pathParts.slice(blobIndex + 2).join('/');
    } else {
      // Look for common contract files
      const commonFiles = [
        'contract.py', 
        'contract.teal', 
        'approval.teal', 
        'clear.teal',
        'contracts/approval.teal',
        'contracts/contract.py',
        'src/contract.py',
        'smart_contracts/contract.py'
      ];
      
      for (const file of commonFiles) {
        try {
          const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${file}`;
          console.log('Trying to fetch:', rawUrl);
          
          const response = await fetch(rawUrl);
          if (response.ok) {
            const content = await response.text();
            if (content.trim()) {
              return content;
            }
          }
        } catch (e) {
          console.log(`Failed to fetch ${file}:`, e);
          continue;
        }
      }
      
      // If no files found, return a sample contract for demonstration
      return `from pyteal import *

def approval_program():
    # Simple counter application with security vulnerability
    # Missing access control checks
    
    counter = Bytes("counter")
    
    increment = Seq([
        App.globalPut(counter, App.globalGet(counter) + Int(1)),
        Int(1)
    ])
    
    program = Cond(
        [Txn.application_id() == Int(0), Int(1)],  # Creation
        [Txn.on_call() == OnCall.OptIn, Int(1)],   # Opt-in
        [Txn.on_call() == OnCall.CloseOut, Int(1)], # Close out
        [Txn.application_args[0] == Bytes("increment"), increment],
        [Int(1)]  # Default case
    )
    
    return program

if __name__ == "__main__":
    print(compileTeal(approval_program(), Mode.Application, version=6))`;
    }

    const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${filePath}`;
    console.log('Fetching from URL:', rawUrl);
    
    const response = await fetch(rawUrl);
    
    if (!response.ok) {
      throw new Error(`Failed to fetch file: ${response.status} ${response.statusText}`);
    }

    const content = await response.text();
    return content;
  } catch (error) {
    console.error('Error fetching contract from GitHub:', error);
    throw error;
  }
};

// Health check function
export const checkApiHealth = async (): Promise<boolean> => {
  try {
    const response = await fetch(`${API_BASE_URL}/health`);
    return response.ok;
  } catch (error) {
    console.error('Health check failed:', error);
    return false;
  }
};