import { useState, useCallback } from 'react';
import { 
  auditContract, 
  auditContractFile, 
  fetchContractFromGithub, 
  fetchContractFromAddress, 
  checkApiHealth,
  AuditResponse, 
  AuditRequest 
} from '../utils/api';

export interface AnalysisState {
  isAnalyzing: boolean;
  result: AuditResponse | null;
  error: string | null;
  progress: number;
  stage: string;
}

export interface ContractData {
  method: 'file' | 'github' | 'address' | 'write';
  content?: string;
  contractCode?: string;
  file?: File;
  githubUrl?: string;
  contractAddress?: string;
  filename: string;
}

export const useContractAnalysis = () => {
  const [state, setState] = useState<AnalysisState>({
    isAnalyzing: false,
    result: null,
    error: null,
    progress: 0,
    stage: 'idle'
  });

  const updateProgress = useCallback((progress: number, stage: string) => {
    setState(prev => ({ ...prev, progress, stage }));
  }, []);

  const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

  const analyzeContract = useCallback(async (contractData: ContractData): Promise<AuditResponse> => {
    setState({
      isAnalyzing: true,
      result: null,
      error: null,
      progress: 0,
      stage: 'initializing'
    });

    try {
      // Check if backend is available
      updateProgress(10, 'connecting to analysis server');
      const isHealthy = await checkApiHealth();
      if (!isHealthy) {
        throw new Error('Analysis server is not available. Please try again later.');
      }

      let contractCode: string;
      let filename = contractData.filename;
      
      updateProgress(20, 'preparing analysis');
      await delay(500);

      // Fetch contract code based on method
      switch (contractData.method) {
        case 'write':
          if (!contractData.contractCode) {
            throw new Error('No contract code provided');
          }
          contractCode = contractData.contractCode;
          filename = contractData.filename || 'written_contract.teal';
          break;

        case 'file':
          if (!contractData.file) {
            throw new Error('No file provided');
          }
          filename = contractData.file.name;
          updateProgress(30, 'reading file');
          contractCode = await new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target?.result as string);
            reader.onerror = (e) => reject(new Error('Failed to read file'));
            reader.readAsText(contractData.file as File);
          });
          break;

        case 'github':
          if (!contractData.githubUrl) {
            throw new Error('No GitHub URL provided');
          }
          updateProgress(30, 'fetching from github');
          contractCode = await fetchContractFromGithub(contractData.githubUrl);
          filename = contractData.githubUrl.split('/').pop() || 'github_contract';
          break;

        case 'address':
          if (!contractData.contractAddress) {
            throw new Error('No contract address provided');
          }
          updateProgress(30, 'fetching from blockchain');
          contractCode = await fetchContractFromAddress(contractData.contractAddress);
          filename = `contract_${contractData.contractAddress}`;
          break;

        default:
          throw new Error('Invalid analysis method');
      }

      if (!contractCode || contractCode.trim().length === 0) {
        throw new Error('Contract code is empty or could not be loaded');
      }

      updateProgress(50, 'analyzing contract structure');
      await delay(800);

      // Determine language based on file extension or content
      let language: 'teal' | 'pyteal' = 'teal';
      if (filename.endsWith('.py') || contractCode.includes('from pyteal') || contractCode.includes('import pyteal')) {
        language = 'pyteal';
      }

      updateProgress(70, 'performing security analysis');
      await delay(1000);

      // Perform the audit
      let result: AuditResponse;
      
      if (contractData.method === 'file' && contractData.file) {
        result = await auditContractFile(contractData.file);
      } else {
        const auditRequest: AuditRequest = {
          contract_code: contractCode,
          filename: filename,
          language
        };
        result = await auditContract(auditRequest);
      }

      updateProgress(90, 'generating report');
      await delay(500);

      updateProgress(100, 'analysis complete');
      await delay(200);

      setState(prev => ({
        ...prev,
        isAnalyzing: false,
        result,
        error: null
      }));

      return result;

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      console.error('Analysis failed:', error);
      
      setState(prev => ({
        ...prev,
        isAnalyzing: false,
        error: errorMessage,
        result: null,
        stage: 'error'
      }));
      
      throw error;
    }
  }, [updateProgress]);

  const resetAnalysis = useCallback(() => {
    setState({
      isAnalyzing: false,
      result: null,
      error: null,
      progress: 0,
      stage: 'idle'
    });
  }, []);

  return {
    ...state,
    analyzeContract,
    resetAnalysis
  };
};