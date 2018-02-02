#pragma once

#include <cstdlib>
#include <cstring>
#include <ctime>

namespace rsa
{
    typedef unsigned long long TInt;
    typedef unsigned char TByte;

    enum EKeyType {
        KEY_TYPE_PUBLIC,
        KEY_TYPE_PRIVATE
    };

    typedef struct CKey {
        TByte type;
        TInt n;
        TInt key;

        CKey(TInt _key = 0, TInt _n = 0, TByte _type = KEY_TYPE_PUBLIC) :
            type(_type), n(_n), key(_key) {}

        TByte getType() { return type; }
        TInt getN() { return n; }
        TInt getKey() { return key; }
    } TKey;

    #define RSA_KEY_SIZE sizeof(rsa::TKey)

    typedef struct SGeneratorOutput {
        TInt p;
        TInt q;
        TInt n;
        TInt phi;
        TInt e;
        TInt d;

        SGeneratorOutput() :
            p(0), q(0), n(0), phi(0), e(0), d(0) {}

        TKey * publicKey()
        {
            return new TKey(e, n, KEY_TYPE_PUBLIC);
        }

        TKey * privateKey()
        {
            return new TKey(d, n, KEY_TYPE_PRIVATE);
        }
    } TGeneratorOutput;

    template<typename _Type>
    _Type gcd(_Type a, _Type b)
    {
        return (b != 0 ? gcd(b, a % b) : a);
    }

    template<typename _Type>
    _Type rand(_Type min, _Type max)
    {
        return ::rand() % max + min;
    }

    template<typename _Type>
    bool is_prime(_Type n)
    {
        for (_Type i = 2; i < n; ++i)
        {
            if (n % i == 0)
                return false;
        }

        return true;
    }

    template<typename _Type>
    _Type rand_prime(_Type min, _Type max)
    {
        _Type out;

        do
            out = rand(min, max);
        while (! is_prime(out));

        return out;
    }

    template<typename _Type>
    _Type powm(_Type base, _Type exp, _Type mod)
    {
        base %= mod;
        _Type result = 1;

        while (exp > 0)
        {
            if (exp & 1) {
                result *= base;
                result %= mod;
            }

            base *= base;
            base %= mod;

            exp >>= 1;
        }

        return result;
    }

    template<typename _Type>
    _Type evaluate(TKey * pKey, _Type what)
    {
        return powm(what, pKey->getKey(), pKey->getN());
    }

    void encode(TKey * pKey, const TByte * in, TInt in_len, TByte * out, TInt & out_len);

    void decode(TKey * pKey, const TByte * in, TInt in_len, TByte * out, TInt & out_len);

    template<typename _Type>
    TGeneratorOutput generate(_Type max, _Type min = 2)
    {
        TGeneratorOutput go;
        go.p = rand_prime(min, max);

        do
            go.q = rand_prime(min, max);
        while (go.p == go.q);

        go.n = go.p * go.q;
        go.phi = (go.p - 1) * (go.q - 1);

        do
            go.e = rand_prime((_Type) 2, go.phi - 1);
        while (gcd(go.e, go.phi) != 1);

        TInt k = 5;
        for (; (1 + k * go.phi) % go.e != 0; ++k);
        go.d = (1 + k * go.phi) / go.e;

        return go;
    }
};
