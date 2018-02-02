#include "rsa.h"

namespace rsa
{
    void encode(TKey * pKey, const TByte * in, TInt in_len, TByte * out, TInt & out_len)
    {
        TInt * encoded = new TInt[in_len]();

        for (size_t i = 0; i < in_len; i++)
            encoded[i] = evaluate(pKey, (TInt) in[i]);

        out_len = sizeof(TInt) * in_len;
        std::memcpy(out, encoded, out_len);
    }

    void decode(TKey * pKey, const TByte * in, TInt in_len, TByte * out, TInt & out_len)
    {
        out_len = in_len / sizeof(TInt);
        TInt * decoded = new TInt[out_len]();
        std::memcpy(decoded, in, in_len);

        for (size_t i = 0; i < out_len; i++)
            out[i] = (TByte) evaluate(pKey, decoded[i]);
    }
};
