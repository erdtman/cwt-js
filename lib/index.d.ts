/**
 * CBOR Web Token (RFC 8392).
 *
 * A CWT is a claims set carried inside a COSE structure: signed (COSE_Sign1),
 * MACed (COSE_Mac0) or encrypted (COSE_Encrypt0), and optionally nested.
 */
declare class CWT {
  /** The CBOR tag that marks a byte string as a CWT. RFC 8392 section 6. */
  static readonly CwtTag: 61;

  /**
   * Verify, or decrypt, a token and read its claims.
   *
   * The token's own COSE tag selects the operation, so one function covers
   * signed, MACed and encrypted tokens. For a nested token the outer layer is
   * removed here and `done` is false; call `continue` with the next key.
   *
   * @param token the encoded token
   * @param key the key for the outermost layer
   * @returns the token, rejected if it does not verify or decrypt
   */
  static parse (token: Buffer, key: CWT.Key): Promise<CWT>;

  /**
   * @param claims a claims set, or an already encoded token
   */
  constructor (claims: CWT.Claims | Buffer);

  /**
   * False while an inner layer of a nested token is still wrapped, which is
   * the only case where `continue` has anything to do.
   */
  done: boolean;

  /** The claims, with registered labels translated back to their names. */
  readonly claims: CWT.Claims;

  /** The encoded token, once one of `mac`, `sign` or `encrypt` has run. */
  readonly raw: Buffer | undefined;

  /**
   * Read one claim. A registered name is translated to its label, so `get`
   * and `set` accept either.
   */
  get (claim: string | number): unknown;

  /** Set one claim, by registered name or by label. */
  set (claim: string | number, value: unknown): void;

  /** Forget the encoded token, keeping the claims. */
  reset (): void;

  /** MAC the claims, producing a COSE_Mac0 token. */
  mac (key: CWT.SymmetricKey, alg: string, options?: CWT.Options): Promise<CWT>;

  /** Sign the claims, producing a COSE_Sign1 token. */
  sign (key: CWT.PrivateKey, alg: string, options?: CWT.Options): Promise<CWT>;

  /**
   * Encrypt, producing a COSE_Encrypt0 token. Encrypts the token already held
   * if there is one, which is how a nested token is built, and the claims
   * otherwise.
   */
  encrypt (key: CWT.SymmetricKey, alg: string, options?: CWT.EncryptOptions): Promise<CWT>;

  /** Unwrap the next layer of a nested token. */
  continue (key: CWT.Key): Promise<CWT>;
}

declare namespace CWT {
  /**
   * A claims set. The seven registered claims are translated to and from
   * their integer labels; any other name or label is carried through as it is.
   */
  interface Claims {
    /** Issuer, label 1. */
    iss?: string;
    /** Subject, label 2. */
    sub?: string;
    /** Audience, label 3. */
    aud?: string;
    /** Expiration time, label 4, as seconds since the epoch. */
    exp?: number;
    /** Not before, label 5, as seconds since the epoch. */
    nbf?: number;
    /** Issued at, label 6, as seconds since the epoch. */
    iat?: number;
    /** CWT ID, label 7, hex-encoded on the way in and out. */
    cti?: string;
    [claim: string]: unknown;
  }

  /** A symmetric key, for `mac` and `encrypt`. */
  interface SymmetricKey {
    k: Buffer;
    kid?: string | Buffer;
  }

  /** A private key, for `sign`. */
  interface PrivateKey {
    d: Buffer;
    kid?: string | Buffer;
  }

  /** A public key, for verifying a signature. */
  interface PublicKey {
    x: Buffer;
    y: Buffer;
    kid?: string | Buffer;
  }

  /** Any key `parse` accepts; which one depends on the token's COSE tag. */
  type Key = SymmetricKey | PublicKey;

  interface Options {
    /** Wrap the result in the CWT CBOR tag. */
    addTag?: boolean;
  }

  interface EncryptOptions extends Options {
    /**
     * Where the IV comes from. Only for reproducing a test vector; leave it
     * unset and the COSE layer uses a secure random source.
     */
    randomSource?: (bytes: number) => Buffer;
  }
}

export = CWT;
