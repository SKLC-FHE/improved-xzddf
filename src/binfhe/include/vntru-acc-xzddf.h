//wkx
#ifndef _VNTRU_ACC_XZDDF_H_
#define _VNTRU_ACC_XZDDF_H_

// #include "rgsw-acc.h"
#include "vntru-acc.h"

#include <memory>

using namespace std;
namespace lbcrypto {


class VectorNTRUAccumulatorXZDDF final : public VectorNTRUAccumulator {
public:
    VectorNTRUAccumulatorXZDDF() = default;

    VectorNTRUACCKey KeyGenAcc(const std::shared_ptr<VectorNTRUCryptoParams>& params, const NativePoly& skNTT,
                         const NativePoly& invskNTT,   ConstLWEPrivateKey& LWEsk) const override;
    void EvalAcc(const std::shared_ptr<VectorNTRUCryptoParams>& params, ConstVectorNTRUACCKey& ek, NTRUCiphertext& acc,
                 const NativeVector& a,NativePoly f) const override;

private:

    VectorNTRUEvalKey KDMKeyGenXZDDF(const std::shared_ptr<VectorNTRUCryptoParams>& params, const NativePoly& invskNTT,
                            LWEPlaintext m) const;
    VectorNTRUEvalKey KeyGenXZDDF(const std::shared_ptr<VectorNTRUCryptoParams>& params, const NativePoly& invskNTT,
                            LWEPlaintext m) const;                        

    VectorNTRUEvalKey KeyGenAuto(const std::shared_ptr<VectorNTRUCryptoParams>& params, const NativePoly& skNTT,
    const NativePoly& invskNTT, LWEPlaintext k) const;
    void AddToAccXZDDF(const std::shared_ptr<VectorNTRUCryptoParams>& params, ConstVectorNTRUEvalKey& ek,
                    NTRUCiphertext& acc) const;
    void Automorphism(const std::shared_ptr<VectorNTRUCryptoParams>& params, const NativeInteger& a,
                      ConstVectorNTRUEvalKey& ak, NTRUCiphertext& acc) const;
};

}  // namespace lbcrypto

#endif  // _VNTRU_ACC_XZDDF_H_