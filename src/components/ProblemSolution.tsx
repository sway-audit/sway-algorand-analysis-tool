import React from 'react';
import { AlertTriangle, CheckCircle } from 'lucide-react';
import gradientBg from '../assets/Gradient.png';

const ProblemSolution = () => {
  return (
    <section 
      className="py-20 px-4 sm:px-6 lg:px-8 bg-white bg-cover bg-center bg-no-repeat"
      style={{
        backgroundImage: `url(${gradientBg})`,
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        backgroundRepeat: 'no-repeat'
      }}
    >
      <div className="max-w-7xl mx-auto">
        <div className="grid lg:grid-cols-2 gap-16">
          <div className="space-y-8">
            <div className="flex items-center space-x-3">
              <AlertTriangle className="w-6 h-6 text-black" />
              <h2 className="text-2xl font-bold text-black">The Problem</h2>
            </div>
            
            <div className="space-y-6 flex flex-col">
              <div className="p-6 bg-[#fff982] border border-black rounded flex-1 min-h-[120px] flex flex-col justify-between">
                <h3 className="text-sm font-medium text-black mb-2">Smart Contract Vulnerabilities Cost Millions</h3>
                <p className="text-sm text-black opacity-80">
                  Over $3.8 billion lost in 2022 due to smart contract exploits. Traditional audit processes take weeks and cost thousands.
                </p>
              </div>
              
              <div className="p-6 bg-[#fff982] border border-black rounded flex-1 min-h-[120px] flex flex-col justify-between">
                <h3 className="text-sm font-medium text-black mb-2">Manual Auditing is Slow and Expensive</h3>
                <p className="text-sm text-black opacity-80">
                  Security firms charge $50k+ and take 4-6 weeks for comprehensive audits, making it inaccessible for smaller projects.
                </p>
              </div>
              
              <div className="p-6 bg-[#fff982] border border-black rounded flex-1 min-h-[120px] flex flex-col justify-between">
                <h3 className="text-sm font-medium text-black mb-2">No Real-Time Feedback During Development</h3>
                <p className="text-sm text-black opacity-80">
                  Developers discover security issues only after completing their contracts, leading to costly rewrites and delays.
                </p>
              </div>
            </div>
          </div>
          
          <div className="space-y-8">
            <div className="flex items-center space-x-3">
              <CheckCircle className="w-6 h-6 text-black" />
              <h2 className="text-2xl font-bold text-black">Our Solution</h2>
            </div>
            
            <div className="space-y-6 flex flex-col">
              <div className="p-6 bg-white text-black border border-black rounded flex-1 min-h-[120px] flex flex-col justify-between">
                <h3 className="text-sm font-medium mb-2 text-black">AI-Powered Instant Auditing</h3>
                <p className="text-sm opacity-80 text-black">
                  Our advanced AI engine analyzes your contracts in under 2 minutes, identifying vulnerabilities with 99.9% accuracy.
                </p>
              </div>
              
              <div className="p-6 bg-white text-black border border-black rounded flex-1 min-h-[120px] flex flex-col justify-between">
                <h3 className="text-sm font-medium mb-2 text-black">Affordable for Everyone</h3>
                <p className="text-sm opacity-80 text-black">
                  Starting at $99 per audit, making professional security analysis accessible to projects of all sizes.
                </p>
              </div>
              
              <div className="p-6 bg-white text-black border border-black rounded flex-1 min-h-[120px] flex flex-col justify-between">
                <h3 className="text-sm font-medium mb-2 text-black">Continuous Integration Support</h3>
                <p className="text-sm opacity-80 text-black">
                  Integrate directly into your development workflow with GitHub Actions, Jenkins, and other CI/CD tools.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default ProblemSolution;