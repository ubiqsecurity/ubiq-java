package com.ubiqsecurity.structured;

import java.math.BigInteger;

import java.util.Arrays;

import javax.crypto.Cipher;

import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CBCModeCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

abstract class FFX
{

    public static final String DEFAULT_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz";

    // protected CBCBlockCipher cipher;
    final protected int radix;
    final protected long txtmin, txtmax;
    final protected long twkmin, twkmax;
    final protected byte[] twk;
    final protected String alpha;
    final protected byte[] key;
    final protected int blksz;

    protected FFX(final byte[] key, final byte[] twk,
                  final long txtmax,
                  final long twkmin, final long twkmax,
                  final int radix, final String alpha) {
        long txtmin;

        /* all 3 key sizes of AES are supported */
        switch (key.length) {
        case 16:
        case 24:
        case 32:
            break;
        default:
            throw new IllegalArgumentException("key size error");
        }

        /*
         * FF1 and FF3-1 support a radix up to 65536, but the
         * implementation becomes increasingly difficult and
         * less useful in practice after the limits below.
         */
        if (radix < 2 || radix > alpha.length()) {
            throw new IllegalArgumentException("invalid radix");
        }

        /*
         * for both ff1 and ff3-1: radix**minlen >= 1000000
         *
         * therefore:
         *   minlen = ceil(log_radix(1000000))
         *          = ceil(log_10(1000000) / log_10(radix))
         *          = ceil(6 / log_10(radix))
         */
        txtmin = (int)Math.ceil(6.0 / Math.log10(radix));
        if (txtmin < 2 || txtmin > txtmax) {
            throw new RuntimeException("minimum text length out of range");
        }

        /* the default tweak must be specified */
        if (twk == null) {
            throw new NullPointerException("invalid tweak");
        }
        /* check tweak lengths */
        if (twkmin > twkmax ||
            twk.length < twkmin ||
            (twkmax > 0 && twk.length > twkmax)) {
            throw new IllegalArgumentException("invalid tweak length");
        }

        /*
         * the underlying cipher for FF1 and FF3-1 is AES in CBC mode.
         * by not specifying the IV, the IV is set to 0's which is
         * what is called for in these algorithms
         */

         // The Cipher needs to be local to the PRF function but we create once
         // to get block size which will not change between calls.  We could

        this.key = key;
        CBCModeCipher cipher = CBCBlockCipher.newInstance(AESEngine.newInstance());
        cipher.init(true, new KeyParameter(key));
        blksz = cipher.getBlockSize();
        cipher.reset();

        this.radix = radix;
        this.alpha = alpha;

        this.txtmin = txtmin;
        this.txtmax = txtmax;

        this.twkmin = twkmin;
        this.twkmax = twkmax;

        this.twk = Arrays.copyOf(twk, twk.length);
    }

    abstract protected String cipher(
        final String X, byte [] twk, final boolean encrypt);

    /*
     * perform an aes-cbc encryption (with an IV of 0) of @src, storing
     * the last block of output into @dst. The number of bytes in @src
     * must be a multiple of 16. @dst and @src may point to the same
     * location but may not overlap, otherwise. @dst must point to a
     * location at least 16 bytes long
     */
    protected void prf(byte[] dst, final int doff,
                       final byte[] src, final int soff, final int len) {
        
        // There were threadsafe issues by having a BlockCipher instance variable
        // Timing of creating and destroying this object is LESS in a large load
        // than using locking mechanisms.
        CBCModeCipher cipher = CBCBlockCipher.newInstance(AESEngine.newInstance());
        cipher.init(true, new KeyParameter(this.key));

        if ((src.length - soff) % blksz != 0) {
            throw new IllegalArgumentException("invalid source length");
        }

        // Some time, we want to run through process block for the entire src
        // sometimes just one block of the src, regardless of the length.
        // In cases where only one block needs to be processed, len would be
        // block size and will terminate the look.  In othercases, len will
        // be the size of the src but len - soff will terminate that.  however
        // cannot easily combine both checks into a single math equation.
        for (int i = 0; i < len && i < src.length - soff; i += this.blksz) {
            cipher.processBlock(src, soff + i, dst, doff);
        }
        cipher.reset();
    }

    /*
     * perform an aes-ecb encryption of @src. @src and @dst must each be
     * 16 bytes long, starting from the respective offsets. @src and @dst
     * may point to the same location or otherwise overlap
     */
    protected void ciph(byte[] dst, final int doff,
                        final byte[] src, final int soff) {
        this.prf(dst, doff, src, soff, 16);
    }

    /*
     * a convenience version of the ciph function that returns its
     * output as a separate byte array
     */
    protected byte[] ciph(final byte[] src) {
        byte[] dst = new byte[this.blksz];
        ciph(dst, 0, src, 0);
        return dst;
    }

    /*
     * reverse the bytes in a byte array. @dst and @src may point
     * to the same location but may not otherwise overlap
     */
    public static void rev(byte[] dst, final byte[] src) {
        int i;

        for (i = 0; i < src.length / 2; i++) {
            final byte t = src[i];
            dst[i] = src[src.length - i - 1];
            dst[src.length - i - 1] = t;
        }

        if (src.length % 2 == 1) {
            dst[i] = src[i];
        }
    }

    /*
     * convenience function that returns the reversed sequence
     * of bytes as a new byte array
     */
    public static byte[] rev(final byte[] src) {
        byte[] dst = new byte[src.length];
        rev(dst, src);
        return dst;
    }

    /*
     * reverse the characters in a string
     */
    public static String rev(final String str) {
        StringBuilder sb =  new StringBuilder(str);
        return sb.reverse().toString();
    }

    /*
     * Perform an exclusive-or of the corresponding bytes
     * in two byte arrays
     */
    public static void xor(byte[] d, final int doff,
                           final byte[] s1, final int s1off,
                           final byte[] s2, final int s2off,
                           final int len) {
        for (int i = 0; i < len; i++) {
            d[doff + i] = (byte)(s1[s1off + i] ^ s2[s2off + i]);
        }
    }

    /*
     * convert a big integer to a string under the radix @r with
     * length @m. If the string is longer than @m, the function fails.
     * if the string is shorter that @m, it is zero-padded to the left
     */
    public static String str(final int m, final int r, final BigInteger i) {
      return str(m, r, FFX.DEFAULT_ALPHABET, i);
    }

    public static String str(final int m, final String alpha, final BigInteger i) {
      // String s = i.toString(r);
      return str(m, alpha.length(), alpha, i);
  }

  public static String str(final int m, final int radix, final String alpha, final BigInteger i) {
    // String s = i.toString(r);
    StringBuilder sb = new StringBuilder();
    BigInteger bi_radix = BigInteger.valueOf(radix);
    BigInteger cvt = i;

    while (cvt.compareTo(BigInteger.ZERO) > 0) {
        sb.insert(0, alpha.charAt(cvt.mod(bi_radix).intValue()));
        cvt = cvt.divide(bi_radix);
    }
    if (sb.length() > m) 
    {
      throw new RuntimeException(String.format("Unable to convert biginteger into %d characters",m));
    }
    while (sb.length() < m)
    {
        sb.insert(0, alpha.charAt(0));
    }
    return sb.toString();
  }

  public static BigInteger number(final String num, final int radix) {
    return number(num, radix, FFX.DEFAULT_ALPHABET);
  }

  public static BigInteger number(final String num, final String alpha) {
    return number(num, alpha.length(), alpha);
  }

  public static BigInteger number(String num, int radix, String alpha) {
    BigInteger ret = BigInteger.valueOf(0);
    int idx = num.length() - 1;
    BigInteger digit = BigInteger.valueOf(1);
    BigInteger bi_radix = BigInteger.valueOf(radix);
    while (idx >= 0) {
      ret = ret.add(digit.multiply(BigInteger.valueOf(alpha.indexOf(num.charAt(idx)))));
      idx--;
      digit = digit.multiply(bi_radix);
    }
    return ret;
  }

    /**
     * Encrypt a string, returning a cipher text using the same alphabet.
     *
     * The key, tweak parameters, and radix were all already set
     * by the initialization of the FF1 object.
     *
     * @param X   the plain text to be encrypted
     * @param twk the tweak used to perturb the encryption
     *
     * @return    the encryption of the plain text, the cipher text
     */
    public String encrypt(String X, byte[] twk) {
        return this.cipher(X, twk, true);
    }

    /**
     * Encrypt a string, returning a cipher text using the same alphabet.
     *
     * The key, tweak parameters, and radix were all already set
     * by the initialization of the FF1 object.
     *
     * @param X   The plain text to be encrypted
     *
     * @return    the encryption of the plain text, the cipher text
     */
    public String encrypt(String X) {
        return this.encrypt(X, null);
    }

    /**
     * Decrypt a string, returning the plain text.
     *
     * The key, tweak parameters, and radix were all already set
     * by the initialization of the FF1 object.
     *
     * @param X   the cipher text to be decrypted
     * @param twk the tweak used to perturb the encryption
     *
     * @return    the decryption of the cipher text, the plain text
     */
    public String decrypt(String X, byte[] twk) {
        return this.cipher(X, twk, false);
    }

    /**
     * Decrypt a string, returning the plain text.
     *
     * The key, tweak parameters, and radix were all already set
     * by the initialization of the FF1 object.
     *
     * @param X   the cipher text to be decrypted
     *
     * @return    the decryption of the cipher text, the plain text
     */
    public String decrypt(String X) {
        return this.decrypt(X, null);
    }
}
