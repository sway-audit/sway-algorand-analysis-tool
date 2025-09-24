import React, { createContext, useContext, ReactNode } from 'react';
import { useWallet } from '../hooks/useWallet';
import { WalletContextType } from '../types/wallet';

const WalletContext = createContext<WalletContextType | undefined>(undefined);

interface WalletProviderProps {
  children: ReactNode;
}

export const WalletProvider: React.FC<WalletProviderProps> = ({ children }) => {
  const wallet = useWallet();

  const contextValue: WalletContextType = {
    walletState: wallet.walletState,
    connectWallet: wallet.connectWallet,
    disconnectWallet: wallet.disconnectWallet,
    signTransaction: wallet.signTransaction,
  };

  return (
    <WalletContext.Provider value={contextValue}>
      {children}
    </WalletContext.Provider>
  );
};

export const useWalletContext = (): WalletContextType => {
  const context = useContext(WalletContext);
  if (context === undefined) {
    throw new Error('useWalletContext must be used within a WalletProvider');
  }
  return context;
};