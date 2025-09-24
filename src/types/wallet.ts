export interface WalletState {
  isConnected: boolean;
  accountAddress: string;
  balance?: number;
}

export interface WalletContextType {
  walletState: WalletState;
  connectWallet: () => Promise<void>;
  disconnectWallet: () => void;
  signTransaction: (txn: any) => Promise<any>;
}

export interface PeraWalletError extends Error {
  type?: string;
  code?: number;
}