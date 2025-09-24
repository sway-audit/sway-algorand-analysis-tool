import React, { useState, useEffect } from 'react';
import { PeraWalletConnect } from '@perawallet/connect';
import swayLogo from '../assets/1.png';

const peraWallet = new PeraWalletConnect({
  shouldShowSignTxnToast: false,
});

const Header = () => {
  const [accountAddress, setAccountAddress] = useState<string>('');
  const [isConnected, setIsConnected] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);

  useEffect(() => {
    // Reconnect to the session when the component is mounted
    peraWallet.reconnectSession().then((accounts) => {
      // Setup the disconnect event listener
      peraWallet.connector?.on('disconnect', handleDisconnectWalletClick);

      if (accounts.length) {
        setAccountAddress(accounts[0]);
        setIsConnected(true);
      }
    }).catch((error) => {
      console.error('Failed to reconnect session:', error);
    });

    return () => {
      peraWallet.connector?.off('disconnect', handleDisconnectWalletClick);
    };
  }, []);

  const handleConnectWalletClick = async () => {
    if (isConnected) {
      handleDisconnectWalletClick();
      return;
    }

    setIsConnecting(true);

    try {
      const newAccounts = await peraWallet.connect();
      
      // Setup the disconnect event listener
      peraWallet.connector?.on('disconnect', handleDisconnectWalletClick);
      
      if (newAccounts.length > 0) {
        setAccountAddress(newAccounts[0]);
        setIsConnected(true);
      }
    } catch (error) {
      if (error instanceof Error && error.message.includes('Connect modal is closed by user')) {
        console.info('User cancelled wallet connection');
      } else {
        console.error('Failed to connect to Pera Wallet:', error);
      }
      
      // Handle specific error cases
      if (error instanceof Error) {
        if (error.message.includes('Session currently connected')) {
          // Already connected, try to get accounts
          try {
            const accounts = await peraWallet.reconnectSession();
            if (accounts.length > 0) {
              setAccountAddress(accounts[0]);
              setIsConnected(true);
            }
          } catch (reconnectError) {
            console.error('Failed to reconnect:', reconnectError);
          }
        }
      }
    } finally {
      setIsConnecting(false);
    }
  };

  const handleDisconnectWalletClick = () => {
    peraWallet.disconnect();
    setAccountAddress('');
    setIsConnected(false);
  };

  const formatAddress = (address: string): string => {
    if (address.length <= 8) return address;
    return `${address.slice(0, 4)}...${address.slice(-4)}`;
  };

  const getButtonText = (): string => {
    if (isConnecting) return 'connecting...';
    if (isConnected) return formatAddress(accountAddress);
    return '';
  };

  const getButtonColor = (): string => {
    if (isConnected) {
      return 'bg-green-50 border-green-500 text-green-700 hover:bg-green-100';
    }
    return 'bg-white border-black text-black hover:bg-black hover:text-white';
  };

  return (
    <header className="fixed top-0 left-0 right-0 z-50 bg-[#fff982] border-b border-black">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center py-3">
          <div className="flex items-center space-x-3">
            <img src={swayLogo} alt="Sway Logo" className="w-16 h-16 transition-opacity hover:opacity-80" />
            <span className="text-xl font-semibold text-black tracking-wide">Sway Audit</span>
          </div>
          
          <nav className="hidden md:flex items-center space-x-10">
            <a href="#features" className="text-sm font-medium text-black hover:opacity-70 transition-all duration-200 hover:transform hover:scale-105">
              Features
            </a>
            <a href="#how-it-works" className="text-sm font-medium text-black hover:opacity-70 transition-all duration-200 hover:transform hover:scale-105">
              How It Works
            </a>
            <a href="#docs" className="text-sm font-medium text-black hover:opacity-70 transition-all duration-200 hover:transform hover:scale-105">
              Docs
            </a>
          </nav>

          <button
            onClick={handleConnectWalletClick}
            disabled={isConnecting}
            className={`px-6 py-3 border-2 rounded-lg text-sm font-semibold transition-all duration-200 hover:transform hover:scale-105 shadow-sm disabled:opacity-50 disabled:cursor-not-allowed ${getButtonColor()}`}
          >
            {isConnected ? (
              <span className="tracking-wide">{getButtonText()}</span>
            ) : (
              <span className="tracking-wide">
                {isConnecting ? 'Connecting...' : 'Connect Pera'}
              </span>
            )}
          </button>
        </div>
      </div>
    </header>
  );
};

export default Header;