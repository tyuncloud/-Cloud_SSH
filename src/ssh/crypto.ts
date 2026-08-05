import { writeUint32 } from './utils';

function buildMacData(seqNum: number, packet: Uint8Array): Uint8Array {
  const data = new Uint8Array(4 + packet.length);
  writeUint32(data, 0, seqNum);
  data.set(packet, 4);
  return data;
}

export class SSHAESGCMCipher {

  private key: CryptoKey | null = null;
  private iv: Uint8Array;
  private rawKey: Uint8Array;


  constructor(
    rawKey: Uint8Array,
    iv: Uint8Array
  ) {

    this.iv = new Uint8Array(iv);
    this.rawKey = rawKey;

  }


  async init(): Promise<void> {

    this.key = await crypto.subtle.importKey(
      'raw',
      this.rawKey,
      {
        name:'AES-GCM',
        length:this.rawKey.length * 8
      },
      false,
      [
        'encrypt',
        'decrypt'
      ]
    );

  }



  private buildNonce(seqNum:number):Uint8Array {


    const nonce = new Uint8Array(this.iv);


    // SSH GCM:
    // first 4 bytes fixed
    // last 8 bytes = packet sequence number


    nonce[4] =
      (seqNum >>> 24) & 0xff;

    nonce[5] =
      (seqNum >>> 16) & 0xff;

    nonce[6] =
      (seqNum >>> 8) & 0xff;

    nonce[7] =
      seqNum & 0xff;


    return nonce;

  }



  async encrypt(
    plaintext:Uint8Array,
    seqNum:number,
    aad?:Uint8Array
  ):Promise<Uint8Array>{


    if(!this.key)
      throw new Error('Cipher not initialized');


    const encrypted =
      await crypto.subtle.encrypt(
        {
          name:'AES-GCM',
          iv:this.buildNonce(seqNum),
          additionalData:aad,
          tagLength:128
        },
        this.key,
        plaintext
      );


    return new Uint8Array(encrypted);

  }



  async decrypt(
    ciphertext:Uint8Array,
    seqNum:number,
    aad?:Uint8Array
  ):Promise<Uint8Array|null>{


    if(!this.key)
      throw new Error('Cipher not initialized');


    try{


      const decrypted =
        await crypto.subtle.decrypt(
          {
            name:'AES-GCM',
            iv:this.buildNonce(seqNum),
            additionalData:aad,
            tagLength:128
          },
          this.key,
          ciphertext
        );


      return new Uint8Array(decrypted);


    }catch(e){

      console.error(
        '[CRYPTO] GCM decrypt failed',
        e
      );

      return null;

    }

  }

}

export class SSHAESCTRCipher {
  private key: CryptoKey | null = null;
  private counter: Uint8Array;
  private rawKey: Uint8Array;

  constructor(rawKey: Uint8Array, iv: Uint8Array) {
    if (iv.length !== 16) {
      throw new Error(`AES-CTR requires a 16-byte IV, got ${iv.length}`);
    }
    this.counter = new Uint8Array(iv);
    this.rawKey = rawKey;
  }

  async init(): Promise<void> {
    this.key = await crypto.subtle.importKey(
      'raw',
      this.rawKey,
      { name: 'AES-CTR', length: this.rawKey.length * 8 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  private incCounter(blocks: number): void {
    let carry = blocks;
    for (let i = 15; i >= 0 && carry > 0; i--) {
      const add = carry % 256;
      const sum = this.counter[i] + add;
      this.counter[i] = sum & 0xff;
      carry = Math.floor(carry / 256) + (sum >>> 8);
    }
  }

  async encrypt(plaintext: Uint8Array, _seqNum?: number, _aad?: Uint8Array, commit: boolean = true): Promise<Uint8Array> {
    if (!this.key) throw new Error('Cipher not initialized');
    const counter = new Uint8Array(this.counter);
    const encrypted = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-CTR', counter, length: 128 } as SubtleCryptoEncryptAlgorithm,
        this.key,
        plaintext
      )
    );
    if (commit) {
      this.incCounter(Math.ceil(plaintext.length / 16));
    }
    return encrypted;
  }

  async decrypt(ciphertext: Uint8Array, _seqNum?: number, _aad?: Uint8Array, commit: boolean = true): Promise<Uint8Array | null> {
    if (!this.key) throw new Error('Cipher not initialized');
    const counter = new Uint8Array(this.counter);
    try {
      const decrypted = new Uint8Array(
        await crypto.subtle.decrypt(
          { name: 'AES-CTR', counter, length: 128 } as SubtleCryptoEncryptAlgorithm,
          this.key,
          ciphertext
        )
      );
      if (commit) {
        this.incCounter(Math.ceil(ciphertext.length / 16));
      }
      return decrypted;
    } catch (e) {
      console.error('[CRYPTO] AES-CTR decrypt failed, ciphertextLen:', ciphertext?.length, 'error:', e instanceof Error ? e.message : String(e));
      return null;
    }
  }
}

export class SSHHMAC {
  private key: CryptoKey | null = null;
  private rawKey: Uint8Array;
  private hash: 'SHA-1' | 'SHA-256' | 'SHA-512';
  readonly length: number;

  constructor(algorithm: string, rawKey: Uint8Array) {
    this.rawKey = rawKey;
    if (algorithm === 'hmac-sha1') {
      this.hash = 'SHA-1';
      this.length = 20;
    } else if (algorithm === 'hmac-sha2-256') {
      this.hash = 'SHA-256';
      this.length = 32;
    } else if (algorithm === 'hmac-sha2-512') {
      this.hash = 'SHA-512';
      this.length = 64;
    } else {
      throw new Error(`Unsupported MAC algorithm: ${algorithm}`);
    }
  }

  async init(): Promise<void> {
    this.key = await crypto.subtle.importKey(
      'raw',
      this.rawKey,
      { name: 'HMAC', hash: this.hash },
      false,
      ['sign', 'verify']
    );
  }

  async sign(packet: Uint8Array, seqNum: number): Promise<Uint8Array> {
    if (!this.key) throw new Error('MAC not initialized');
    return new Uint8Array(await crypto.subtle.sign('HMAC', this.key, buildMacData(seqNum, packet)));
  }

  async verify(packet: Uint8Array, seqNum: number, expected: Uint8Array): Promise<boolean> {
    if (!this.key) throw new Error('MAC not initialized');
    return crypto.subtle.verify('HMAC', this.key, expected, buildMacData(seqNum, packet));
  }
}

export const REKEY_THRESHOLD = 1 << 30;

export function shouldRekey(seqNum: number): boolean {
  return seqNum >= REKEY_THRESHOLD;
}
