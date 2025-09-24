import React, { useState, useEffect } from 'react';
import { ArrowLeft, Shield, AlertTriangle, CheckCircle, Clock, FileText, Download } from 'lucide-react';
import swayLogo from '../assets/sway-logo.png';
import swayCoin from '../assets/sway-coin.png';
import { useContractAnalysis } from '../hooks/useContractAnalysis';
import { VulnerabilityFinding } from '../utils/api';

interface AnalysisProps {
  contractData: any;
  onBack: () => void;
}

const Analysis = ({ contractData, onBack }: AnalysisProps) => {
  const { isAnalyzing, result, error, progress, stage, analyzeContract, resetAnalysis } = useContractAnalysis();
  const [showResults, setShowResults] = useState(false);

  useEffect(() => {
    // Start analysis when component mounts
    if (contractData && !result && !isAnalyzing && !error) {
      console.log('Starting analysis with contract data:', contractData);
      
      const analysisData = {
        method: contractData.method,
        filename: contractData.filename || 'contract',
        file: contractData.method === 'file' ? contractData.file : undefined,
        githubUrl: contractData.method === 'github' ? contractData.githubUrl : undefined,
        contractAddress: contractData.method === 'address' ? contractData.contractAddress : undefined,
      };
      
      analyzeContract(analysisData)
        .then(() => {
          console.log('Analysis completed successfully');
          setShowResults(true);
        })
        .catch((err) => {
          console.error('Analysis failed:', err);
          setShowResults(true); // Show results even on error to display error state
        });
    }
  }, [contractData, result, isAnalyzing, error, analyzeContract]);

  // Show results if analysis is complete or if there's an error
  if ((result || error) && !isAnalyzing) {
    setShowResults(true);
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'border-red-600 text-red-600';
      case 'high': return 'border-red-500 text-red-500';
      case 'medium': return 'border-yellow-600 text-yellow-600';
      case 'low': return 'border-blue-600 text-blue-600';
      case 'informational': return 'border-gray-600 text-gray-600';
      default: return 'border-black text-black';
    }
  };

  const getSeverityCounts = (findings: VulnerabilityFinding[]) => {
    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0
    };

    findings.forEach(finding => {
      const severity = finding.severity.toLowerCase() as keyof typeof counts;
      if (counts[severity] !== undefined) {
        counts[severity]++;
      }
    });

    return counts;
  };

  if (isAnalyzing || (!showResults && !error)) {
    return (
      <div className="min-h-screen bg-[#fff982] p-4">
        <div className="max-w-4xl mx-auto">
          <div className="flex items-center space-x-4 mb-8 pt-8">
            <button
              onClick={onBack}
              className="flex items-center space-x-2 px-4 py-2 bg-[#fff982] border border-black rounded text-sm font-medium text-black hover:bg-black hover:text-[#fff982] transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>back to home</span>
            </button>
            <div className="flex items-center space-x-3">
              <img src={swayLogo} alt="Sway Logo" className="w-8 h-8" />
              <span className="text-xl font-medium text-black">sway analysis</span>
            </div>
          </div>

          <div className="bg-[#fff982] border border-black rounded p-12 text-center">
            <div className="space-y-8">
              <div className="animate-pulse">
                <img src={swayCoin} alt="Analyzing" className="w-24 h-24 mx-auto" />
              </div>
              
              <div className="space-y-4">
                <h2 className="text-2xl font-bold text-black">analyzing your contract</h2>
                <p className="text-sm text-black opacity-80">
                  our ai is performing comprehensive security analysis on your smart contract
                </p>
              </div>

              <div className="space-y-4">
                <div className="w-full bg-black bg-opacity-20 rounded-full h-2">
                  <div 
                    className="bg-black h-2 rounded-full transition-all duration-300"
                    style={{ width: `${progress}%` }}
                  ></div>
                </div>
                
                <div className="flex items-center justify-center space-x-2">
                  <Clock className="w-4 h-4 text-black animate-spin" />
                  <span className="text-sm text-black capitalize">{stage}...</span>
                </div>
              </div>

              <div className="text-xs text-black opacity-70">
                this usually takes 1-2 minutes depending on contract complexity
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Show error state
  if (error && !result) {
    return (
      <div className="min-h-screen bg-[#fff982] p-4">
        <div className="max-w-6xl mx-auto">
          <div className="flex items-center space-x-4 mb-8 pt-8">
            <button
              onClick={onBack}
              className="flex items-center space-x-2 px-4 py-2 bg-[#fff982] border border-black rounded text-sm font-medium text-black hover:bg-black hover:text-[#fff982] transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>back to home</span>
            </button>
            <div className="flex items-center space-x-3">
              <img src={swayLogo} alt="Sway Logo" className="w-8 h-8" />
              <span className="text-xl font-medium text-black">analysis error</span>
            </div>
          </div>

          <div className="bg-red-50 border border-red-600 rounded p-8 text-center">
            <AlertTriangle className="w-16 h-16 text-red-600 mx-auto mb-4" />
            <h2 className="text-2xl font-bold text-red-800 mb-4">Analysis Failed</h2>
            <p className="text-red-700 mb-6">{error}</p>
            <button
              onClick={onBack}
              className="px-6 py-3 bg-red-600 text-white rounded border border-red-600 font-medium text-sm hover:bg-red-700 transition-colors"
            >
              Try Again
            </button>
          </div>
        </div>
      </div>
    );
  }

  const analysisReport = result?.analysisReport;
  const findings = analysisReport?.findings || [];
  const severityCounts = getSeverityCounts(findings);

  return (
    <div className="min-h-screen bg-[#fff982] p-4">
      <div className="max-w-6xl mx-auto">
        <div className="flex items-center space-x-4 mb-8 pt-8">
          <button
            onClick={onBack}
            className="flex items-center space-x-2 px-4 py-2 bg-[#fff982] border border-black rounded text-sm font-medium text-black hover:bg-black hover:text-[#fff982] transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>back to home</span>
          </button>
          <div className="flex items-center space-x-3">
            <img src={swayLogo} alt="Sway Logo" className="w-8 h-8" />
            <span className="text-xl font-medium text-black">audit report</span>
          </div>
        </div>

        <div className="grid lg:grid-cols-3 gap-8">
          <div className="lg:col-span-2 space-y-6">
            <div className="bg-[#fff982] border border-black rounded p-6">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-xl font-bold text-black">security overview</h2>
                <button className="flex items-center space-x-2 px-4 py-2 bg-black text-[#fff982] rounded text-sm font-medium hover:bg-[#fff982] hover:text-black border border-black transition-colors">
                  <Download className="w-4 h-4" />
                  <span>export report</span>
                </button>
              </div>

              <div className="grid grid-cols-3 gap-4 mb-8">
                <div className="text-center p-4 bg-[#fff982] border border-red-600 rounded">
                  <div className="text-2xl font-bold text-red-600">{severityCounts.critical + severityCounts.high}</div>
                  <div className="text-xs text-black">critical issues</div>
                </div>
                <div className="text-center p-4 bg-[#fff982] border border-yellow-600 rounded">
                  <div className="text-2xl font-bold text-yellow-600">{severityCounts.medium}</div>
                  <div className="text-xs text-black">warnings</div>
                </div>
                <div className="text-center p-4 bg-[#fff982] border border-blue-600 rounded">
                  <div className="text-2xl font-bold text-blue-600">{severityCounts.low + severityCounts.informational}</div>
                  <div className="text-xs text-black">info & low</div>
                </div>
              </div>

              <div className="space-y-4">
                {findings.length === 0 ? (
                  <div className="p-8 bg-green-50 border border-green-600 rounded text-center">
                    <CheckCircle className="w-12 h-12 text-green-600 mx-auto mb-4" />
                    <h3 className="text-lg font-bold text-green-800 mb-2">No Issues Found</h3>
                    <p className="text-green-700">Your smart contract passed all security checks!</p>
                  </div>
                ) : (
                  findings.map((finding, index) => (
                    <div key={index} className={`p-4 bg-[#fff982] border rounded ${getSeverityColor(finding.severity)}`}>
                    <div className="flex items-start justify-between">
                      <div className="space-y-2">
                        <div className="flex items-center space-x-2">
                          <AlertTriangle className="w-4 h-4" />
                          <h3 className="text-sm font-semibold">{finding.vulnerabilityName}</h3>
                          <span className="text-xs px-2 py-1 bg-black bg-opacity-10 rounded">
                            line {finding.lineNumber}
                          </span>
                        </div>
                        <p className="text-xs opacity-80">{finding.description}</p>
                        {finding.recommendedFix && (
                          <div className="text-xs p-2 bg-white bg-opacity-50 rounded">
                            <strong>Fix:</strong> {finding.recommendedFix}
                          </div>
                        )}
                      </div>
                      <span className={`text-xs px-2 py-1 border rounded ${getSeverityColor(finding.severity)}`}>
                        {finding.severity}
                      </span>
                    </div>
                  </div>
                  ))
                )}
              </div>
            </div>

            <div className="bg-[#fff982] border border-black rounded p-6">
              <h3 className="text-lg font-bold text-black mb-4">gas optimization suggestions</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 bg-black text-[#fff982] rounded">
                  <span className="text-sm">optimize storage layout</span>
                  <span className="text-xs">save ~12% gas</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-black text-[#fff982] rounded">
                  <span className="text-sm">batch operations</span>
                  <span className="text-xs">save ~8% gas</span>
                </div>
              </div>
            </div>
          </div>

          <div className="space-y-6">
            <div className="bg-[#fff982] border border-black rounded p-6">
              <h3 className="text-lg font-bold text-black mb-4">contract info</h3>
              <div className="space-y-3 text-sm">
                <div className="flex justify-between">
                  <span className="text-black opacity-70">method:</span>
                  <span className="text-black capitalize">
                    {contractData.method === 'write' ? 'written code' : contractData.method}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-black opacity-70">analyzed:</span>
                  <span className="text-black">{analysisReport ? new Date(analysisReport.timestamp).toLocaleDateString() : new Date().toLocaleDateString()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-black opacity-70">lines of code:</span>
                  <span className="text-black">{analysisReport?.fileName ? 'analyzed' : 'calculating...'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-black opacity-70">complexity:</span>
                  <span className="text-black">
                    {findings.length === 0 ? 'simple' : 
                     findings.length <= 3 ? 'medium' : 'complex'}
                  </span>
                </div>
              </div>
            </div>

            <div className="bg-[#fff982] border border-black rounded p-6">
              <h3 className="text-lg font-bold text-black mb-4">security score</h3>
              <div className="text-center space-y-4">
                <div className="text-4xl font-bold text-black">
                  {analysisReport?.overallRiskScore === 'Passed' ? '10/10' :
                   analysisReport?.overallRiskScore === 'Low' ? '8.5/10' :
                   analysisReport?.overallRiskScore === 'Medium' ? '6.5/10' :
                   analysisReport?.overallRiskScore === 'High' ? '4.0/10' :
                   analysisReport?.overallRiskScore === 'Critical' ? '2.0/10' : '7.2/10'}
                </div>
                <div className="text-sm text-black opacity-80">
                  {analysisReport?.overallRiskScore === 'Passed' ? 'excellent security' :
                   analysisReport?.overallRiskScore === 'Low' ? 'good security' :
                   analysisReport?.overallRiskScore === 'Medium' ? 'moderate security' :
                   analysisReport?.overallRiskScore === 'High' ? 'poor security' :
                   analysisReport?.overallRiskScore === 'Critical' ? 'critical issues' : 'good security rating'}
                </div>
                <div className="w-full bg-black bg-opacity-20 rounded-full h-2">
                  <div className="bg-black h-2 rounded-full" style={{ 
                    width: analysisReport?.overallRiskScore === 'Passed' ? '100%' :
                            analysisReport?.overallRiskScore === 'Low' ? '85%' :
                            analysisReport?.overallRiskScore === 'Medium' ? '65%' :
                            analysisReport?.overallRiskScore === 'High' ? '40%' :
                            analysisReport?.overallRiskScore === 'Critical' ? '20%' : '72%'
                  }}></div>
                </div>
              </div>
            </div>

            <div className="bg-[#fff982] border border-black rounded p-6">
              <h3 className="text-lg font-bold text-black mb-4">next steps</h3>
              <div className="space-y-3">
                <div className="flex items-center space-x-3">
                  <CheckCircle className="w-4 h-4 text-black" />
                  <span className="text-xs text-black">fix critical vulnerabilities</span>
                </div>
                <div className="flex items-center space-x-3">
                  <FileText className="w-4 h-4 text-black" />
                  <span className="text-xs text-black">review detailed recommendations</span>
                </div>
                <div className="flex items-center space-x-3">
                  <Shield className="w-4 h-4 text-black" />
                  <span className="text-xs text-black">re-run audit after fixes</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Analysis;