#!/usr/bin/env python3
"""
Comprehensive test suite for Enterprise Algorand Smart Contract Audit Tool
Tests all new features: database, real integrations, advanced security, and report export
"""

import os
import sys
import json
import asyncio
import requests
import time
from typing import Dict, Any

# Test configuration
BASE_URL = "http://localhost:8000"
TEST_TIMEOUT = 30

# Test data
SAMPLE_TEAL_CONTRACT = """
#pragma version 6
txn ApplicationID
int 0
==
bnz main_l2
txn OnCompletion
int DeleteApplication
==
bnz main_l2
txn OnCompletion
int UpdateApplication
==
bnz main_l2
int 0
return
main_l2:
int 1
return
"""

SAMPLE_PYTEAL_CONTRACT = """
from pyteal import *

def approval_program():
    return Seq([
        If(Txn.application_id() == Int(0)).Then(
            Return(Int(1))
        ),
        If(Txn.on_completion() == OnCall.DeleteApplication).Then(
            Return(Int(1))
        ),
        Return(Int(0))
    ])

if __name__ == "__main__":
    print(compileTeal(approval_program(), Mode.Application, version=6))
"""

class EnterpriseBackendTester:
    """Comprehensive test suite for enterprise backend features"""
    
    def __init__(self):
        self.base_url = BASE_URL
        self.session = requests.Session()
        self.test_results = []
        self.report_id = None
        
    def log_test(self, test_name: str, success: bool, details: str = ""):
        """Log test result"""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status}: {test_name}")
        if details:
            print(f"   Details: {details}")
        
        self.test_results.append({
            "test": test_name,
            "success": success,
            "details": details
        })
    
    def test_health_endpoint(self) -> bool:
        """Test basic health endpoint"""
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=TEST_TIMEOUT)
            success = response.status_code == 200
            
            if success:
                data = response.json()
                details = f"Status: {data.get('status', 'unknown')}"
            else:
                details = f"HTTP {response.status_code}"
            
            self.log_test("Health Endpoint", success, details)
            return success
            
        except Exception as e:
            self.log_test("Health Endpoint", False, str(e))
            return False
    
    def test_text_analysis_basic(self) -> bool:
        """Test basic text analysis with TEAL contract"""
        try:
            payload = {
                "contract_code": SAMPLE_TEAL_CONTRACT,
                "filename": "test_contract.teal",
                "language": "teal"
            }
            
            response = self.session.post(
                f"{self.base_url}/audit/text",
                json=payload,
                timeout=TEST_TIMEOUT
            )
            
            success = response.status_code == 200
            
            if success:
                data = response.json()
                analysis_report = data.get("analysisReport", {})
                findings = analysis_report.get("findings", [])
                
                # Store report ID for later tests
                self.report_id = analysis_report.get("report_id")
                
                details = f"Found {len(findings)} security findings"
                if "metrics" in analysis_report:
                    metrics = analysis_report["metrics"]
                    details += f", Security Score: {metrics.get('security_score', 'N/A')}"
            else:
                details = f"HTTP {response.status_code}: {response.text[:100]}"
            
            self.log_test("Text Analysis (TEAL)", success, details)
            return success
            
        except Exception as e:
            self.log_test("Text Analysis (TEAL)", False, str(e))
            return False
    
    def test_text_analysis_pyteal(self) -> bool:
        """Test text analysis with PyTeal contract"""
        try:
            payload = {
                "contract_code": SAMPLE_PYTEAL_CONTRACT,
                "filename": "test_contract.py",
                "language": "pyteal"
            }
            
            response = self.session.post(
                f"{self.base_url}/audit/text",
                json=payload,
                timeout=TEST_TIMEOUT
            )
            
            success = response.status_code == 200
            
            if success:
                data = response.json()
                analysis_report = data.get("analysisReport", {})
                findings = analysis_report.get("findings", [])
                details = f"Found {len(findings)} security findings in PyTeal contract"
            else:
                details = f"HTTP {response.status_code}: {response.text[:100]}"
            
            self.log_test("Text Analysis (PyTeal)", success, details)
            return success
            
        except Exception as e:
            self.log_test("Text Analysis (PyTeal)", False, str(e))
            return False
    
    def test_file_upload_analysis(self) -> bool:
        """Test file upload analysis"""
        try:
            # Create temporary test file
            test_file_path = "temp_test_contract.teal"
            with open(test_file_path, "w") as f:
                f.write(SAMPLE_TEAL_CONTRACT)
            
            with open(test_file_path, "rb") as f:
                files = {"file": ("test_contract.teal", f, "text/plain")}
                response = self.session.post(
                    f"{self.base_url}/audit",
                    files=files,
                    timeout=TEST_TIMEOUT
                )
            
            # Clean up
            os.remove(test_file_path)
            
            success = response.status_code == 200
            
            if success:
                data = response.json()
                analysis_report = data.get("analysisReport", {})
                findings = analysis_report.get("findings", [])
                details = f"File upload analysis found {len(findings)} findings"
            else:
                details = f"HTTP {response.status_code}: {response.text[:100]}"
            
            self.log_test("File Upload Analysis", success, details)
            return success
            
        except Exception as e:
            self.log_test("File Upload Analysis", False, str(e))
            return False
    
    def test_github_integration_mock(self) -> bool:
        """Test GitHub integration (mock endpoint)"""
        try:
            payload = {
                "github_url": "https://github.com/algorand/smart-contracts/blob/main/approval.teal"
            }
            
            response = self.session.post(
                f"{self.base_url}/audit/github",
                json=payload,
                timeout=TEST_TIMEOUT
            )
            
            success = response.status_code == 200
            
            if success:
                data = response.json()
                analysis_report = data.get("analysisReport", {})
                findings = analysis_report.get("findings", [])
                details = f"GitHub mock analysis found {len(findings)} findings"
            else:
                details = f"HTTP {response.status_code}: {response.text[:100]}"
            
            self.log_test("GitHub Integration (Mock)", success, details)
            return success
            
        except Exception as e:
            self.log_test("GitHub Integration (Mock)", False, str(e))
            return False
    
    def test_address_integration_mock(self) -> bool:
        """Test Algorand address integration (mock endpoint)"""
        try:
            payload = {
                "contract_address": "123456789"
            }
            
            response = self.session.post(
                f"{self.base_url}/audit/address",
                json=payload,
                timeout=TEST_TIMEOUT
            )
            
            success = response.status_code == 200
            
            if success:
                data = response.json()
                analysis_report = data.get("analysisReport", {})
                findings = analysis_report.get("findings", [])
                details = f"Address mock analysis found {len(findings)} findings"
            else:
                details = f"HTTP {response.status_code}: {response.text[:100]}"
            
            self.log_test("Address Integration (Mock)", success, details)
            return success
            
        except Exception as e:
            self.log_test("Address Integration (Mock)", False, str(e))
            return False
    
    def test_audit_history(self) -> bool:
        """Test audit history endpoint"""
        try:
            response = self.session.get(
                f"{self.base_url}/reports/history",
                timeout=TEST_TIMEOUT
            )
            
            success = response.status_code == 200
            
            if success:
                data = response.json()
                reports = data.get("reports", [])
                total = data.get("total", 0)
                details = f"Found {len(reports)} reports in history (total: {total})"
            else:
                details = f"HTTP {response.status_code}: {response.text[:100]}"
            
            self.log_test("Audit History", success, details)
            return success
            
        except Exception as e:
            self.log_test("Audit History", False, str(e))
            return False
    
    def test_report_export(self) -> bool:
        """Test report export functionality"""
        if not self.report_id:
            self.log_test("Report Export", False, "No report ID available for export test")
            return False
        
        try:
            # Test JSON export
            payload = {
                "report_id": self.report_id,
                "format": "json"
            }
            
            response = self.session.post(
                f"{self.base_url}/export/report",
                json=payload,
                timeout=TEST_TIMEOUT
            )
            
            success = response.status_code == 200
            
            if success:
                content_type = response.headers.get("content-type", "")
                details = f"Export successful, content-type: {content_type}"
            else:
                details = f"HTTP {response.status_code}: {response.text[:100]}"
            
            self.log_test("Report Export (JSON)", success, details)
            return success
            
        except Exception as e:
            self.log_test("Report Export (JSON)", False, str(e))
            return False
    
    def test_advanced_security_features(self) -> bool:
        """Test advanced security analysis features"""
        try:
            # Use a more complex contract to trigger advanced analysis
            complex_contract = """
            #pragma version 6
            txn ApplicationID
            int 0
            ==
            bnz create_app
            
            txn OnCompletion
            int DeleteApplication
            ==
            bnz delete_app
            
            txn OnCompletion
            int UpdateApplication
            ==
            bnz update_app
            
            // Main application logic
            txn ApplicationArgs 0
            byte "transfer"
            ==
            bnz transfer
            
            int 0
            return
            
            create_app:
            int 1
            return
            
            delete_app:
            global CreatorAddress
            txn Sender
            ==
            return
            
            update_app:
            global CreatorAddress
            txn Sender
            ==
            return
            
            transfer:
            // Potential vulnerability: no balance check
            int 1
            return
            """
            
            payload = {
                "contract_code": complex_contract,
                "filename": "complex_contract.teal",
                "language": "teal"
            }
            
            response = self.session.post(
                f"{self.base_url}/audit/text",
                json=payload,
                timeout=TEST_TIMEOUT
            )
            
            success = response.status_code == 200
            
            if success:
                data = response.json()
                analysis_report = data.get("analysisReport", {})
                findings = analysis_report.get("findings", [])
                metrics = analysis_report.get("metrics", {})
                
                # Check for advanced analysis features
                has_complexity = "complexity" in metrics
                has_gas_analysis = "gas_analysis" in metrics
                has_security_score = "security_score" in metrics
                
                advanced_features = sum([has_complexity, has_gas_analysis, has_security_score])
                details = f"Found {len(findings)} findings, {advanced_features}/3 advanced features detected"
            else:
                details = f"HTTP {response.status_code}: {response.text[:100]}"
            
            self.log_test("Advanced Security Analysis", success, details)
            return success
            
        except Exception as e:
            self.log_test("Advanced Security Analysis", False, str(e))
            return False
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all enterprise backend tests"""
        print("🚀 Starting Enterprise Algorand Smart Contract Audit Tool Backend Tests")
        print("=" * 80)
        
        # Core functionality tests
        self.test_health_endpoint()
        self.test_text_analysis_basic()
        self.test_text_analysis_pyteal()
        self.test_file_upload_analysis()
        
        # Integration tests
        self.test_github_integration_mock()
        self.test_address_integration_mock()
        
        # Enterprise features tests
        self.test_audit_history()
        self.test_report_export()
        self.test_advanced_security_features()
        
        # Summary
        print("\n" + "=" * 80)
        print("📊 TEST SUMMARY")
        print("=" * 80)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result["success"])
        failed_tests = total_tests - passed_tests
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests} ✅")
        print(f"Failed: {failed_tests} ❌")
        print(f"Success Rate: {(passed_tests/total_tests*100):.1f}%")
        
        if failed_tests > 0:
            print("\n❌ Failed Tests:")
            for result in self.test_results:
                if not result["success"]:
                    print(f"   - {result['test']}: {result['details']}")
        
        return {
            "total": total_tests,
            "passed": passed_tests,
            "failed": failed_tests,
            "success_rate": passed_tests/total_tests*100,
            "results": self.test_results
        }

def main():
    """Main test execution"""
    print("Waiting for backend to start...")
    time.sleep(2)
    
    tester = EnterpriseBackendTester()
    results = tester.run_all_tests()
    
    # Exit with appropriate code
    sys.exit(0 if results["failed"] == 0 else 1)

if __name__ == "__main__":
    main()
