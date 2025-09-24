import React, { useState } from 'react';
import Header from './components/Header';
import HeroSection from './components/HeroSection';
import SocialProof from './components/SocialProof';
import ProblemSolution from './components/ProblemSolution';
import HowItWorks from './components/HowItWorks';
import Features from './components/Features';
import Footer from './components/Footer';
import UploadContract from './pages/UploadContract';
import Analysis from './pages/Analysis';

function App() {
  const [currentPage, setCurrentPage] = useState('home');
  const [contractData, setContractData] = useState(null);

  const handleStartAudit = () => {
    setCurrentPage('upload');
  };

  const handleContractUpload = (data) => {
    setContractData(data);
    setCurrentPage('analysis');
  };

  const handleBackToHome = () => {
    setCurrentPage('home');
    setContractData(null);
  };

  if (currentPage === 'upload') {
    return <UploadContract onUpload={handleContractUpload} onBack={handleBackToHome} />;
  }

  if (currentPage === 'analysis') {
    return <Analysis contractData={contractData} onBack={handleBackToHome} />;
  }

  return (
    <div className="min-h-screen bg-[#fff982]">
      <Header />
      <HeroSection onStartAudit={handleStartAudit} />
      <SocialProof />
      <ProblemSolution />
      <HowItWorks />
      <Features />
      <Footer />
    </div>
  );
}

export default App;