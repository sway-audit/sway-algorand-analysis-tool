import { useState, useEffect, useCallback } from 'react';
import { PeraWalletConnect } from '@perawallet/connect';
import { WalletState, PeraWalletError } from '../types/wallet';

const peraWallet = new PeraWalletConnect({
  shouldShowSignTxnToast: false,
  chainId: 416001, // MainNet
});

export const useWallet = () => {
  const [walletState, setWalletState] = useState<WalletState>({
    isConnected: false,
    accountAddress: '',
  });
  const [isConnecting, setIsConnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Initialize wallet connection on mount
  useEffect(() => {
    initializeWallet();
    
    return () => {
      peraWallet.connector?.off('disconnect', handleDisconnect);
    };
  }, []);

  const initializeWallet = useCallback(async () => {
    try {
      const accounts = await peraWallet.reconnectSession();
      
      if (accounts.length > 0) {
        setWalletState({
          isConnected: true,
          accountAddress: accounts[0],
        });
        
        // Setup disconnect listener
        peraWallet.connector?.on('disconnect', handleDisconnect);
      }
    } catch (error) {
      console.error('Failed to initialize wallet:', error);
    }
  }, []);

  const handleDisconnect = useCallback(() => {
    setWalletState({
      isConnected: false,
      accountAddress: '',
    });
    setError(null);
  }, []);

  const connectWallet = useCallback(async (): Promise<void> => {
    if (walletState.isConnected) return;

    setIsConnecting(true);
    setError(null);

    try {
      const accounts = await peraWallet.connect();
      
      if (accounts.length > 0) {
        setWalletState({
          isConnected: true,
          accountAddress: accounts[0],
        });
        
        // Setup disconnect listener
        peraWallet.connector?.on('disconnect', handleDisconnect);
      } else {
        throw new Error('No accounts returned from wallet');
      }
    } catch (error) {
      const walletError = error as PeraWalletError;
      
      if (walletError.message?.includes('Session currently connected')) {
        // Handle already connected case
        await initializeWallet();
      } else {
        setError(walletError.message || 'Failed to connect wallet');
        throw error;
      }
    } finally {
      setIsConnecting(false);
    }
  }, [walletState.isConnected, initializeWallet, handleDisconnect]);

  const disconnectWallet = useCallback((): void => {
    peraWallet.disconnect();
    handleDisconnect();
  }, [handleDisconnect]);

  const signTransaction = useCallback(async (txnGroup: any[]): Promise<any> => {
    if (!walletState.isConnected) {
      throw new Error('Wallet not connected');
    }

    try {
      const signedTxn = await peraWallet.signTransaction([txnGroup]);
      return signedTxn;
    } catch (error) {
      const walletError = error as PeraWalletError;
      setError(walletError.message || 'Failed to sign transaction');
      throw error;
    }
  }, [walletState.isConnected]);

  return {
    walletState,
    isConnecting,
    error,
    connectWallet,
    disconnectWallet,
    signTransaction,
    peraWallet, // Export for advanced usage
  };
};