import React, { useState } from 'react';
import { ArrowLeft, Upload, FileCode, Link, AlertCircle } from 'lucide-react';
import swayLogo from '../assets/1.png';
import dalgaBg from '../assets/dalga.png';
import githubLogo from '../assets/logos/pngimg.com - github_PNG40.png';
import algorandLogo from '../assets/logos/algorand-logo.png';
import { checkApiHealth } from '../utils/api';

interface UploadContractProps {
  onUpload: (data: any) => void;
  onBack: () => void;
}

const UploadContract = ({ onUpload, onBack }: UploadContractProps) => {
  const [uploadMethod, setUploadMethod] = useState('file');
  const [contractAddress, setContractAddress] = useState('');
  const [githubUrl, setGithubUrl] = useState('');
  const [contractCode, setContractCode] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleUpload = async () => {
    setError(null);
    setIsUploading(true);

    try {
      // Validate inputs
      if (uploadMethod === 'file' && !file) {
        throw new Error('Please select a file to upload');
      }
      if (uploadMethod === 'github' && !githubUrl.trim()) {
        throw new Error('Please enter a GitHub URL');
      }
      if (uploadMethod === 'address' && !contractAddress.trim()) {
        throw new Error('Please enter a contract address');
      }
      if (uploadMethod === 'write' && !contractCode.trim()) {
        throw new Error('Please write or paste contract code');
      }

      // Validate GitHub URL format
      if (uploadMethod === 'github') {
        const githubPattern = /^https:\/\/github\.com\/[\w\-\.]+\/[\w\-\.]+/;
        if (!githubPattern.test(githubUrl.trim())) {
          throw new Error('Please enter a valid GitHub URL (e.g., https://github.com/user/repo)');
        }
      }

      // Validate contract address format (basic validation)
      if (uploadMethod === 'address') {
        const addressPattern = /^[A-Z0-9]{52,58}$|^\d{1,10}$/;
        if (!addressPattern.test(contractAddress.trim())) {
          throw new Error('Please enter a valid Algorand contract address or application ID');
        }
      }

      // Check if backend is available
      const isHealthy = await checkApiHealth();
      if (!isHealthy) {
        throw new Error('Analysis server is currently unavailable. Please try again later.');
      }

      // Prepare contract data
      const data = {
        method: uploadMethod,
        contractAddress: contractAddress.trim(),
        githubUrl: githubUrl.trim(),
        contractCode: contractCode.trim(),
        file: file,
        filename: file ? file.name : (
          uploadMethod === 'github' ? githubUrl.split('/').pop() || 'github_contract' :
          uploadMethod === 'address' ? `contract_${contractAddress}` : 
          uploadMethod === 'write' ? 'written_contract.teal' : 'contract'
        ),
        timestamp: Date.now()
      };

      onUpload(data);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'An unexpected error occurred';
      setError(errorMessage);
    } finally {
      setIsUploading(false);
    }
  };

  const isValidInput = () => {
    switch (uploadMethod) {
      case 'file':
        return file !== null;
      case 'github':
        return githubUrl.trim().length > 0;
      case 'address':
        return contractAddress.trim().length > 0;
      case 'write':
        return contractCode.trim().length > 0;
      default:
        return false;
    }
  };

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files[0]) {
      setFile(event.target.files[0]);
    }
  };

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
            <span className="text-xl font-medium text-black">Swayyy Me Now</span>
          </div>
        </div>

        <div className="bg-white border border-black rounded p-8 bg-cover bg-center bg-no-repeat" style={{ backgroundImage: `url(${dalgaBg})` }}>
          <div className="text-center space-y-4 mb-12">
            <h1 className="text-3xl font-bold text-black">Upload Smart Contract</h1>
            <p className="text-sm text-black opacity-80 max-w-2xl mx-auto">
              Choose your preferred method to upload your Algorand smart contract for comprehensive security analysis
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <button
              onClick={() => setUploadMethod('write')}
              className={`p-6 border border-black rounded transition-colors ${
                uploadMethod === 'write' ? 'bg-black text-[#fff982]' : 'bg-white text-black hover:bg-black hover:text-[#fff982]'
              }`}
            >
              <FileCode className="w-8 h-8 mx-auto mb-3" />
              <h3 className="text-sm font-semibold mb-2">write contract</h3>
              <p className="text-xs opacity-80">write or paste teal/pyteal code directly</p>
            </button>

            <button
              onClick={() => setUploadMethod('file')}
              className={`p-6 border border-black rounded transition-colors ${
                uploadMethod === 'file' ? 'bg-black text-[#fff982]' : 'bg-white text-black hover:bg-black hover:text-[#fff982]'
              }`}
            >
              <Upload className="w-8 h-8 mx-auto mb-3" />
              <h3 className="text-sm font-semibold mb-2">upload file</h3>
              <p className="text-xs opacity-80">upload .teal, .py, or .reach files directly</p>
            </button>

            <button
              onClick={() => setUploadMethod('github')}
              className={`p-6 border border-black rounded transition-colors ${
                uploadMethod === 'github' ? 'bg-black text-[#fff982]' : 'bg-white text-black hover:bg-black hover:text-[#fff982]'
              }`}
            >
              <img 
                src={githubLogo} 
                alt="GitHub" 
                className="w-8 h-8 mx-auto mb-3" 
              />
              <h3 className="text-sm font-semibold mb-2">github repository</h3>
              <p className="text-xs opacity-80">connect your github repository</p>
            </button>

            <button
              onClick={() => setUploadMethod('address')}
              className={`p-6 border border-black rounded transition-colors ${
                uploadMethod === 'address' ? 'bg-black text-[#fff982]' : 'bg-white text-black hover:bg-black hover:text-[#fff982]'
              }`}
            >
              <img 
                src={algorandLogo} 
                alt="Algorand" 
                className="w-12 h-12 mx-auto mb-3" 
              />
              <h3 className="text-sm font-semibold mb-2">contract address</h3>
              <p className="text-xs opacity-80">analyze deployed contract by address</p>
            </button>
          </div>

          <div className="space-y-6">
            {uploadMethod === 'write' && (
              <div className="space-y-4">
                <label className="block text-sm font-medium text-black">write or paste contract code</label>
                <div className="space-y-2">
                  <textarea
                    value={contractCode}
                    onChange={(e) => setContractCode(e.target.value)}
                    placeholder="// Paste your TEAL or PyTeal contract code here
#pragma version 6

// Your contract logic here
txn ApplicationID
int 0
==
bnz creation_branch

// Add your contract logic..."
                    className="w-full h-80 px-4 py-3 bg-[#fff982] border border-black rounded text-sm text-black placeholder-black placeholder-opacity-50 focus:outline-none focus:ring-2 focus:ring-black font-mono resize-y"
                    style={{ minHeight: '320px' }}
                  />
                  <div className="flex items-center justify-between text-xs text-black opacity-70">
                    <span>supports both TEAL assembly and PyTeal python code</span>
                    <span>{contractCode.length} characters</span>
                  </div>
                </div>
              </div>
            )}

            {uploadMethod === 'file' && (
              <div className="space-y-4">
                <label className="block text-sm font-medium text-black">select contract file</label>
                <div className="border border-black border-dashed rounded p-8 text-center">
                  <FileCode className="w-12 h-12 mx-auto mb-4 text-black" />
                  <input
                    type="file"
                    onChange={handleFileChange}
                    accept=".teal,.py,.reach"
                    className="hidden"
                    id="file-upload"
                  />
                  <label
                    htmlFor="file-upload"
                   className="cursor-pointer px-4 py-2 bg-white text-black rounded border border-black text-sm font-medium hover:bg-black hover:text-[#fff982] transition-colors"
                  >
                    choose file
                  </label>
                  <p className="text-xs text-black opacity-70 mt-2">
                    {file ? file.name : 'supports .teal, .py, and .reach files'}
                  </p>
                </div>
              </div>
            )}

            {uploadMethod === 'github' && (
              <div className="space-y-4">
                <label className="block text-sm font-medium text-black">github repository url</label>
                <input
                  type="url"
                  value={githubUrl}
                  onChange={(e) => setGithubUrl(e.target.value)}
                  placeholder="https://github.com/username/repository/blob/main/contract.py"
                  className="w-full px-4 py-3 bg-[#fff982] border border-black rounded text-sm text-black placeholder-black placeholder-opacity-50 focus:outline-none focus:ring-2 focus:ring-black"
                />
                <p className="text-xs text-black opacity-70">
                  Paste the full GitHub URL to your contract file or repository
                </p>
              </div>
            )}

            {uploadMethod === 'address' && (
              <div className="space-y-4">
                <label className="block text-sm font-medium text-black">algorand contract address</label>
                <input
                  type="text"
                  value={contractAddress}
                  onChange={(e) => setContractAddress(e.target.value)}
                  placeholder="Enter contract address or application ID"
                  className="w-full px-4 py-3 bg-[#fff982] border border-black rounded text-sm text-black placeholder-black placeholder-opacity-50 focus:outline-none focus:ring-2 focus:ring-black"
                />
                <p className="text-xs text-black opacity-70">
                  Enter a 58-character address or numeric application ID
                </p>
              </div>
            )}

            {error && (
              <div className="flex items-center space-x-2 p-4 bg-red-50 border border-red-300 rounded">
                <AlertCircle className="w-4 h-4 text-red-600 flex-shrink-0" />
                <p className="text-sm text-red-700">{error}</p>
              </div>
            )}

            <div className="flex justify-end pt-6">
              <button
                onClick={handleUpload}
                disabled={!isValidInput() || isUploading}
                className="px-6 py-3 bg-black text-[#fff982] rounded border border-black font-medium text-sm hover:bg-[#fff982] hover:text-black transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
              >
                {isUploading && (
                  <div className="w-4 h-4 border-2 border-[#fff982] border-t-transparent rounded-full animate-spin"></div>
                )}
                <span>
                  {isUploading ? 'Starting Analysis...' : 'Start Analysis'}
                </span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default UploadContract;