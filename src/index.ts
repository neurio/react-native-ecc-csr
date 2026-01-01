import { NativeModules } from 'react-native';

const { CSRModule } = NativeModules;

export type ECCurve = 'secp256r1' | 'secp384r1' | 'secp521r1';

export interface CSRParams {
  country?: string;
  state?: string;
  locality?: string;
  organization?: string;
  organizationalUnit?: string;
  commonName: string;
  serialNumber?: string;
  ipAddress?: string;
  dnsName: string;
  curve?: ECCurve; // P-256, P-384 (default), or P-521
  privateKeyAlias: string;
  phoneInfo?: string;
}

export interface CSRResult {
  csr: string;
  privateKeyAlias: string; // Alias to the key in Android Keystore (NOT the key itself!)
  publicKey: string;
  isHardwareBacked: boolean; // Whether the key is stored in hardware
}

export interface CSRModuleInterface {
  /**
   * Generates a Certificate Signing Request (CSR) with hardware-backed ECC key pair
   * The private key is stored securely in Android Keystore and NEVER exposed.
   * 
   * @param params - CSR parameters including privateKeyAlias for secure storage
   * @returns Promise resolving to CSR, key alias (not the key!), and public key
   */
  generateCSR(params: CSRParams): Promise<CSRResult>;

  /**
   * Deletes a key from Android Keystore
   * @param privateKeyAlias - The alias of the key to delete
   * @returns Promise resolving to true if successful
   */
  deleteKey(privateKeyAlias: string): Promise<boolean>;

  /**
   * Checks if a key exists in Android Keystore
   * @param privateKeyAlias - The alias of the key to check
   * @returns Promise resolving to true if key exists
   */
  keyExists(privateKeyAlias: string): Promise<boolean>;

  /**
   * Retrieves the public key for a given alias
   * @param privateKeyAlias - The alias of the key pair
   * @returns Promise resolving to base64-encoded public key
   */
  getPublicKey(privateKeyAlias: string): Promise<string>;
}

export default CSRModule as CSRModuleInterface;
