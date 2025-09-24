import React from 'react';
import { Github, Twitter, MessageCircle } from 'lucide-react';
import swayLogo from '../assets/1.png';

const Footer = () => {
  return (
    <footer className="border-t border-black bg-[#fff982] py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto">
        <div className="grid md:grid-cols-4 gap-8 mb-8">
          <div className="space-y-4">
            <div className="flex items-center space-x-3">
              <img src={swayLogo} alt="Sway Logo" className="w-8 h-8" />
              <span className="text-lg font-medium text-black">Sway</span>
            </div>
            <p className="text-xs text-black opacity-80">
              Securing the Algorand ecosystem, one smart contract at a time.
            </p>
          </div>
          
          <div className="space-y-3">
            <h3 className="text-sm font-semibold text-black">Product</h3>
            <div className="space-y-2">
              <a href="#features" className="block text-xs text-black hover:opacity-70 transition-opacity">Features</a>
              <a href="#pricing" className="block text-xs text-black hover:opacity-70 transition-opacity">Pricing</a>
              <a href="#integrations" className="block text-xs text-black hover:opacity-70 transition-opacity">Integrations</a>
            </div>
          </div>
          
          <div className="space-y-3">
            <h3 className="text-sm font-semibold text-black">Resources</h3>
            <div className="space-y-2">
              <a href="#docs" className="block text-xs text-black hover:opacity-70 transition-opacity">Documentation</a>
              <a href="#blog" className="block text-xs text-black hover:opacity-70 transition-opacity">Blog</a>
              <a href="#api" className="block text-xs text-black hover:opacity-70 transition-opacity">API Reference</a>
            </div>
          </div>
          
          <div className="space-y-3">
            <h3 className="text-sm font-semibold text-black">Company</h3>
            <div className="space-y-2">
              <a href="#about" className="block text-xs text-black hover:opacity-70 transition-opacity">About Us</a>
              <a href="#careers" className="block text-xs text-black hover:opacity-70 transition-opacity">Careers</a>
              <a href="#contact" className="block text-xs text-black hover:opacity-70 transition-opacity">Contact</a>
            </div>
          </div>
        </div>
        
        <div className="text-center pt-6">
          <p className="text-xs text-black opacity-70">© 2025 Sway. All rights reserved.</p>
        </div>
      </div>
    </footer>
  );
};

export default Footer;