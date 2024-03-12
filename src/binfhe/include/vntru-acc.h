
#ifndef _VNTRU_FHE_H_
#define _VNTRU_FHE_H_

#include "ntru-ciphertext.h"
// #include "rgsw-acckey.h"
// #include "rgsw-cryptoparameters.h"

//wkx
#include "vntru-acckey.h"
#include "vntru-cryptoparameters.h"

#include <vector>
#include <memory>

namespace lbcrypto {

class VectorNTRUAccumulator {
public:
    VectorNTRUAccumulator() = default;

    virtual VectorNTRUACCKey KeyGenAcc(const std::shared_ptr<VectorNTRUCryptoParams>& params, const NativePoly& skNTT,
                                 const NativePoly& invskNTT,   ConstLWEPrivateKey& LWEsk) const 
    {
        OPENFHE_THROW(not_implemented_error, "KeyGenACC operation not supported");
    }

    virtual void EvalAcc(const std::shared_ptr<VectorNTRUCryptoParams>& params, ConstVectorNTRUACCKey& ek,
                        NTRUCiphertext& acc, const NativeVector& a,NativePoly f) const {
            std::cout<<"run EvalAcc in rgsw-acc.h"<<std::endl;
        OPENFHE_THROW(not_implemented_error, "ACC operation not supported");
    }

    void SignedDigitDecompose(const std::shared_ptr<VectorNTRUCryptoParams>& params, const std::vector<NativePoly>& input,
                              std::vector<NativePoly>& output) const;

    void SignedDigitDecompose(const std::shared_ptr<VectorNTRUCryptoParams>& params, const NativePoly& input,
                              std::vector<NativePoly>& output) const;
};
}  // namespace lbcrypto

#endif