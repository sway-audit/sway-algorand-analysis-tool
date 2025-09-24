import React from 'react';
import { Shield, Zap, GitBranch, Globe, Clock, BarChart } from 'lucide-react';

const Features = () => {
  const features = [
    {
      icon: Shield,
      title: 'Comprehensive Vulnerability Detection',
      description: 'Detects reentrancy, integer overflow, access control issues, and 50+ other common vulnerabilities'
    },
    {
      icon: Zap,
      title: 'Gas Optimization Recommendations',
      description: 'Reduce transaction costs with AI-powered optimization suggestions and efficiency improvements'
    },
    {
      icon: GitBranch,
      title: 'CI/CD Integration',
      description: 'Seamlessly integrate into your development workflow with GitHub Actions, Jenkins, and more'
    },
    {
      icon: Globe,
      title: 'Multi-Language Support',
      description: 'Supports PyTeal, TEAL, and Reach smart contracts on the Algorand ecosystem'
    },
    {
      icon: Clock,
      title: 'Real-Time Analysis',
      description: 'Get instant feedback while coding with our VS Code extension and real-time vulnerability scanning'
    },
    {
      icon: BarChart,
      title: 'Security Dashboard',
      description: 'Track all your projects security scores, audit history, and improvement metrics in one place'
    }
  ];

  return (
    <section id="features" className="py-24 px-4 sm:px-6 lg:px-8 bg-white border-t border-black">
      <div className="max-w-7xl mx-auto">
        <div className="text-center space-y-6 mb-20">
          <div className="inline-block">
            <h2 className="text-4xl lg:text-5xl font-bold text-black mb-4">Powerful Features</h2>
            <div className="w-24 h-1 bg-black mx-auto"></div>
          </div>
          <p className="text-lg text-black opacity-80 max-w-3xl mx-auto leading-relaxed">
            Enterprise-grade security tools designed specifically for Algorand smart contract developers
          </p>
        </div>
        
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-10">
          {features.map((feature, index) => (
            <div 
              key={index}
              className="group cursor-pointer"
            >
              <div className="bg-[#fff982] border-2 border-black rounded-lg p-8 h-full transition-all duration-300 hover:transform hover:-translate-y-2 hover:shadow-xl hover:bg-black hover:text-[#fff982] hover:border-[#fff982]">
                <div className="space-y-6">
                  <div className="flex items-center justify-center w-16 h-16 bg-black rounded-full group-hover:bg-[#fff982] transition-colors duration-300">
                    <feature.icon className="w-8 h-8 text-[#fff982] group-hover:text-black transition-colors duration-300" />
                  </div>
                  <h3 className="text-lg font-bold text-black group-hover:text-[#fff982] transition-colors duration-300">
                    {feature.title}
                  </h3>
                  <p className="text-sm text-black opacity-80 group-hover:text-[#fff982] group-hover:opacity-90 leading-relaxed transition-all duration-300">
                  {feature.description}
                </p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default Features;