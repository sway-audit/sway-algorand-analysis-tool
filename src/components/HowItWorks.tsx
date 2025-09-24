import React from 'react';
import { Upload, Search, FileText } from 'lucide-react';

const HowItWorks = () => {
  const steps = [
    {
      icon: Upload,
      title: 'Connect & Upload',
      description: 'Connect your GitHub repository or paste your contract address. Supports all Algorand smart contract formats.'
    },
    {
      icon: Search,
      title: 'AI Analysis',
      description: 'Our AI engine performs static, dynamic, and formal verification tests to identify potential vulnerabilities.'
    },
    {
      icon: FileText,
      title: 'Detailed Report',
      description: 'Receive a comprehensive report with criticality rankings, specific recommendations, and actionable fixes.'
    }
  ];

  return (
    <section id="how-it-works" className="py-24 px-4 sm:px-6 lg:px-8 border-t border-black bg-white">
      <div className="max-w-7xl mx-auto">
        <div className="text-center space-y-4 mb-16">
          <h2 className="text-4xl font-bold text-black">How It Works</h2>
          <p className="text-sm text-black opacity-80 max-w-2xl mx-auto">
            Get comprehensive security analysis for your Algorand smart contracts in three simple steps
          </p>
          <div className="w-24 h-1 bg-black mx-auto mt-6"></div>
        </div>
        
        <div className="grid md:grid-cols-3 gap-12">
          {steps.map((step, index) => (
            <div key={index} className="text-center space-y-6 group hover:transform hover:scale-105 transition-all duration-300">
              <div className="relative">
                <div className="w-20 h-20 mx-auto bg-black rounded-full flex items-center justify-center shadow-lg group-hover:shadow-xl transition-shadow duration-300">
                  <step.icon className="w-10 h-10 text-[#fff982] group-hover:scale-110 transition-transform duration-300" />
                </div>
                <div className="absolute -top-3 -right-3 w-8 h-8 bg-[#fff982] border-2 border-black rounded-full flex items-center justify-center shadow-md">
                  <span className="text-sm font-bold text-black">{index + 1}</span>
                </div>
              </div>
              
              <div className="space-y-4">
                <h3 className="text-xl font-bold text-black group-hover:text-gray-800 transition-colors duration-300 capitalize">{step.title}</h3>
                <p className="text-base text-black opacity-80 leading-relaxed">{step.description}</p>
              </div>
              
              {index < steps.length - 1 && (
                <div className="hidden md:block absolute top-10 left-1/2 w-16 h-0.5 bg-gradient-to-r from-black to-gray-400 transform translate-x-12 opacity-40"></div>
              )}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default HowItWorks;