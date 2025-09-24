import React from 'react';
import algorandLogo from '../assets/logos/algorand-logo.png';
import peraLogo from '../assets/logos/pera-logo-black.png';
import tinymanLogo from '../assets/logos/tinyman-logo-png_seeklogo-444564.png';

const SocialProof = () => {
  const logos = [
    {
      src: algorandLogo,
      alt: 'Algorand Foundation',
      className: 'h-8 w-auto'
    },
    {
      src: peraLogo, 
      alt: 'Pera Wallet',
      className: 'h-8 w-auto'
    },
    {
      src: tinymanLogo,
      alt: 'Tinyman',
      className: 'h-8 w-auto'
    }
  ];

  return (
    <section className="py-16 px-4 sm:px-6 lg:px-8 border-t border-b border-black bg-white">
      <div className="max-w-7xl mx-auto">
        <div className="text-center space-y-8">
          <h2 className="text-2xl font-medium text-black">Trusted By Leading Algorand Projects</h2>
          
          <div className="flex flex-wrap items-center justify-center gap-16">
            {logos.map((logo, index) => (
              <div key={index} className="flex items-center justify-center p-4">
                <img 
                  src={logo.src}
                  alt={logo.alt}
                  className="h-32 w-auto opacity-70 hover:opacity-100 transition-opacity"
                />
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
};

export default SocialProof;