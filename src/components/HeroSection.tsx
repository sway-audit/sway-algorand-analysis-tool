import React from 'react';
import { Shield, ArrowRight } from 'lucide-react';
import swayFan from '../assets/sway-fan.png';
import gradientBg from '../assets/Gradient.png';

interface HeroSectionProps {
  onStartAudit: () => void;
}

const HeroSection = ({ onStartAudit }: HeroSectionProps) => {
  return (
    <section className="pt-24 pb-16 px-4 sm:px-6 lg:px-8 bg-white">
      <div className="max-w-7xl mx-auto">
        <div className="grid lg:grid-cols-2 gap-12 items-center">
          <div className="space-y-8">
            <div className="space-y-4">
              <h1 className="text-4xl lg:text-5xl font-bold text-black leading-tight">
                Secure Your Algorand Smart Contracts
              </h1>
              <p className="text-base text-black opacity-80 max-w-lg">
                Comprehensive AI-Powered Audit Platform That Identifies Vulnerabilities, Optimizes Gas Usage, And Ensures Your Contracts Meet Industry Standards Before Deployment.
              </p>
            </div>
            
            <div className="flex flex-col sm:flex-row gap-4">
              <button
                onClick={onStartAudit}
                className="flex items-center justify-center space-x-2 px-6 py-3 bg-white text-black rounded border border-black font-medium text-sm hover:bg-black hover:text-white transition-colors group"
                style={{
                  backgroundImage: `url(${gradientBg})`,
                  backgroundSize: 'cover',
                  backgroundPosition: 'center',
                  backgroundRepeat: 'no-repeat'
                }}
              >
                <span>Start Free Audit</span>
                <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
              </button>
              
              <button className="px-6 py-3 bg-[#fff982] text-black rounded border border-black font-medium text-sm hover:bg-black hover:text-[#fff982] transition-colors">
                View Documentation
              </button>
            </div>
            
            <div className="flex items-center space-x-8 pt-4">
              <div className="text-center group">
                <div className="text-lg font-bold text-black transition-all duration-500 hover:scale-110 animate-pulse">10k+</div>
                <div className="text-xs text-black opacity-70 transition-opacity duration-300 group-hover:opacity-100">Contracts Audited</div>
              </div>
              <div className="text-center group">
                <div className="text-lg font-bold text-black transition-all duration-500 hover:scale-110 animate-pulse">99.9%</div>
                <div className="text-xs text-black opacity-70 transition-opacity duration-300 group-hover:opacity-100">Vulnerability Detection</div>
              </div>
              <div className="text-center group">
                <div className="text-lg font-bold text-black transition-all duration-500 hover:scale-110 animate-pulse">{"< 2min"}</div>
                <div className="text-xs text-black opacity-70 transition-opacity duration-300 group-hover:opacity-100">Average Scan Time</div>
              </div>
            </div>
          </div>
          
          <div className="flex justify-center lg:justify-end">
            <div className="relative">
              <img 
                src={swayFan} 
                alt="Sway Fan" 
                className="w-full h-auto max-w-lg border border-black rounded-sm"
              />
            </div>
          </div>
        </div>
      </div>
    </section>
  )
};

export default HeroSection;