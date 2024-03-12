//wkx
#ifndef _VNTRU_ACC_XZNEW_H_
#define _VNTRU_ACC_XZNEW_H_

// #include "rgsw-acc.h"
#include "vntru-acc.h"

#include <memory>

using namespace std;
namespace lbcrypto {


class VectorNTRUAccumulatorXZNEW final : public VectorNTRUAccumulator {
public:
    VectorNTRUAccumulatorXZNEW() = default;

    VectorNTRUACCKey KeyGenAcc(const std::shared_ptr<VectorNTRUCryptoParams>& params, const NativePoly& skNTT,
                         const NativePoly& invskNTT,   ConstLWEPrivateKey& LWEsk) const override;
    void EvalAcc(const std::shared_ptr<VectorNTRUCryptoParams>& params, ConstVectorNTRUACCKey& ek, NTRUCiphertext& acc,
                 const NativeVector& a,NativePoly f) const override;

private:
    VectorNTRUEvalKey KeyGenXZNEW_extend(const std::shared_ptr<VectorNTRUCryptoParams>& params,
                                                             const NativePoly& invskNTT, const NativePoly& m_poly)const;
    VectorNTRUEvalKey KDMKeyGenXZNEW(const std::shared_ptr<VectorNTRUCryptoParams>& params, const NativePoly& invskNTT,
                            LWEPlaintext m) const;
    VectorNTRUEvalKey KeyGenXZNEW(const std::shared_ptr<VectorNTRUCryptoParams>& params, const NativePoly& invskNTT,
                            LWEPlaintext m) const;                        

    VectorNTRUEvalKey KeyGenAuto(const std::shared_ptr<VectorNTRUCryptoParams>& params, const NativePoly& skNTT,
    const NativePoly& invskNTT, LWEPlaintext k) const;
    void AddToAccXZNEW(const std::shared_ptr<VectorNTRUCryptoParams>& params, ConstVectorNTRUEvalKey& ek,
                    NTRUCiphertext& acc) const;
    void Automorphism(const std::shared_ptr<VectorNTRUCryptoParams>& params, const NativeInteger& a,
                      ConstVectorNTRUEvalKey& ak, NTRUCiphertext& acc) const;
};

}  // namespace lbcrypto

#endif  // _VNTRU_ACC_XZNEW_H_