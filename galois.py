mod128 = 0x100000000000000000000000000000087L # x^128+x^7+x^2+x+1
mod8 = 0b100011011

# A detailed explanation of how this works can be found at
# http://en.wikipedia.org/wiki/Finite_field_arithmetic
# In short what we are doing is multiplying polynomials where each term is
# modulo 2. For this reason we can represent the polynomials as a binary
# string. For example, the polynomial x^3 + x + 1 = x^3 + x^1 + x^0 is the
# binary string 1011b. Here's a short example. Let us multiply
# (x + 1) with (x^3 + x^2): (x + 1)(x^3 + x^2) = x(x^3 + x^2) + x^3 + x^2 =
# x^4 + x^3 + x^3 + x^2 = x^4 + 2x^3 + x^2
# This is regular multiplication. However, as each term is modulo 2
# we're left with (1 % 2)x^4 + (2 % 2)x^3 + (1 % 2)x^2 = x^4 + x^2.
# There is however one step remaining: Depending of the field we're multiplying
# in there's modulo step left. For GF(2^8) the modulo is 100011011b
# and for GF(2^128) the modulo is x^128+x^7+x^2+x+1.
# This modulo step can be performed with simple long division but by
# binary OR:ing instead of subtracting.

def gf2n_mul(a, b, mod):
    """Multiplication in GF(2^n)."""

    def highest_bit_set(n):
        # XXX: naive
        cnt = 0
        while n:
            n >>= 1
            cnt += 1
        return cnt - 1  

    def xor_mod(n, mod):
        while True:
            x = highest_bit_set(n) - highest_bit_set(mod)
     
            if x == 0:
                n = n ^ mod
            if x <= 0:
                break
            lower = n & ((1 << x) - 1)
            n = (((n >> x) ^ mod) << x) | lower
        return n        

    # Naively mutiply two polynomials together. Lets say a is x^8+x^3+1
    # and b is x^4+x^2, then we can write this as the following pseudo code:
    res = 0
    a_cnt = 0
    # for each term in [x^8, x^3, 1]:
    while a:
        b2 = b
        b_cnt = 0
        if a & 1:
            # for each term in [x^4, x^2]:
            while b2:
                if b2 & 1:
                    # 1 << (a_cnt + b_cnt) constructs the new term
                    # and the xor adds it to the result modulo 2.
                    res ^= 1 << (a_cnt + b_cnt)
                b2 >>= 1
                b_cnt += 1
        a >>= 1
        a_cnt += 1
        
    return xor_mod(res, mod)

def gf2pow128mul(a, b):
    return gf2n_mul(a, b, mod128)

# Add and subtract polynomials modulo 2. See explanation above why this
# code is so simple.

def gf2n_add(a, b):
    """Addition in GF(2^n)."""
    return a ^ b

def gf2n_sub(a, b):
    """Subtraction in GF(2^n)."""
    return a ^ b
