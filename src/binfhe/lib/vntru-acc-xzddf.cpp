
#include "vntru-acc-xzddf.h"

#include <string>
#include <vector>
namespace lbcrypto {

VectorNTRUACCKey VectorNTRUAccumulatorXZDDF::KeyGenAcc(const std::shared_ptr<VectorNTRUCryptoParams>& params,
                                                       const NativePoly& skNTT, const NativePoly& invskNTT,
                                                       ConstLWEPrivateKey& LWEsk) const {
    //TODO
    auto sv{LWEsk->GetElement()};
    auto mod{sv.GetModulus().ConvertToInt<int32_t>()};  //q_ks
    //std::cout << "in vntru-acc-xzddf :mod=" << mod << std::endl;
    auto modHalf{mod >> 1};
    //std::cout << "in vntru-acc-xzddf :modHalf=" << modHalf << std::endl;
    //uint32_t N{params->GetN()};
    size_t n{sv.GetLength()};
    auto q{params->Getq().ConvertToInt<size_t>()};
    //std::cout << "in vntru-acc-xzddf :q=" << q << std::endl;
    // uint32_t inversea=ModInverse(5,2048);
    // std::cout<<inversea%2048<<std::endl;
    // uint32_t numAutoKeys{params->GetNumAutoKeys()};
    VectorNTRUACCKey ek = std::make_shared<VectorNTRUACCKeyImpl>(1, 2, q - 1 > n + 1 ? q - 1 : n + 1);
    //生成评估秘钥
    auto s{sv[0].ConvertToInt<int32_t>()};                                          // 0 +-1
    (*ek)[0][0][0] = KDMKeyGenXZDDF(params, invskNTT, s > modHalf ? mod - s : -s);  //第一个evk(KDM-form)
    // auto ss        = s > modHalf ? s - mod : s;
    // std::cout << "密钥生成的s" << ss << std::endl;
    // cout<<"(*ek)[0][0][0].size()="<<(*ek)[0][0][0]->GetElements().size()<<endl;
    // for(uint32_t i =0;i<(*ek)[0][0][0]->GetElements().size();i++)
    // {
    //     for(uint32_t j=0;j<8;j++)
    //     {
    //         cout<<(*ek)[0][0][0]->GetElements()[i][j]<<" ";
    //     }
    //     cout<<endl;
    // }

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(n))
    for (size_t i = 1; i < n; ++i) {
        auto s{sv[i].ConvertToInt<int32_t>()};
        (*ek)[0][0][i] = KeyGenXZDDF(params, invskNTT, s > modHalf ? mod - s : -s);
        //如果s大于modHalf，则返回s - mod，否则返回s
    }
    auto sums = 0;
    for (size_t i = 0; i < n; ++i) {
        auto s{sv[i].ConvertToInt<int32_t>()};
        //cout << " s = " << s << endl;
        sums = sums +s;
    }
    sums %= mod;
    if (sums > modHalf) {
        sums -= mod;
    }//
    // cout << "sums" << sums << endl;
    (*ek)[0][0][n] = KeyGenXZDDF(params, invskNTT, sums);
    //生成自同构秘钥
    int64_t intq = params->Getq().ConvertToInt<int64_t>();  //
    int64_t N    = params->GetN();
    for (auto i = 0; i < intq - 1; ++i) {
        (*ek)[0][1][i] = KeyGenAuto(params, skNTT, invskNTT, (2 * N / intq) * (i + 1) + 1);
    }

//     /*----------生成优化的自同构秘钥-----------*/
//     NativeInteger gen = NativeInteger(5);
//     (*ek)[0][2][0] = KeyGenAuto(params, skNTT, 2 * N - gen.ConvertToInt());
//     // m_window: window size, consider parameterization in the future
// #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(numAutoKeys))
//     for (uint32_t i = 1; i <= numAutoKeys; ++i)
//         (*ek)[0][2][i] = KeyGenAuto(params, skNTT, gen.ModExp(i, 2 * N).ConvertToInt<LWEPlaintext>());
//     return ek;


    return ek;
}

void VectorNTRUAccumulatorXZDDF::EvalAcc(const std::shared_ptr<VectorNTRUCryptoParams>& params,
                                         ConstVectorNTRUACCKey& ek, NTRUCiphertext& acc, const NativeVector& a,NativePoly f_inv) const {
    //TODO
    size_t n   = a.GetLength();
    uint32_t N = params->GetN();
    int32_t q  = params->Getq().ConvertToInt<int32_t>();
    //uint32_t M           = 2 * params->GetN();
    std::vector<uint32_t> ua(n);
    std::vector<uint32_t> w(n);
    std::vector<uint32_t> invw(n + 1);
    invw[n] = 1;
    std::vector<NativeInteger> NATIVEw(n);  //自同构的次数
    std::vector<uint32_t> invindex(n);      //对应到autk 的index

    for (size_t i = 0; i < n; i++) {
        ua[i]   = a[i].ConvertToInt<int32_t>();       //a
        w[i]    = (2 * N / q) * ua[i] + 1;            //w_i
        invw[i] = ModInverse(w[i], 2 * N) % (2 * N);  //w_inv
    }
    // std::cout << "w0=" << w[0] << std::endl;
    // std::cout << "invw0=" << invw[0] << std::endl;
    for (size_t i = 0; i < n; i++) {
        NATIVEw[i] = NativeVector::Integer((w[i] * invw[i + 1]) % (2 * N));
        //std::cout<<"inverse"<< NATIVEw[i];
        invindex[i] = (NATIVEw[i].ConvertToInt<int32_t>() - 3) / 2;

        // std::cout << "NATIVEw=" << NATIVEw[i] << std::endl;
        // std::cout << "invindex=" << invindex[i] << std::endl;
    }
    // cout << "输入的acc = " << endl;
    // for (uint32_t i = 0; i < N; i++) {
    //     cout << acc->GetElements()[i] << " ";
    // }
    //int auto_times=0;
    for (size_t i = 0; i < n; i++) {
        AddToAccXZDDF(params, (*ek)[0][0][i], acc);  ///evk_{0 ~ n-1}
        if (NATIVEw[i].ConvertToInt<int32_t>() != 1) {
            //auto_times++;
            Automorphism(params, NATIVEw[i], (*ek)[0][1][invindex[i]], acc);
        }
    }
    //cout<<"auto_times = "<<auto_times<<endl;
    // auto polyParams = params->GetPolyParams();

    // cout << "\n f = " << endl;
    // for (uint32_t i = 0; i < N; i++) {
    //     std::cout << f[i] << " ";
    // }
    // f.SetFormat(EVALUATION);

    // std::vector<NativePoly> ev = (*ek)[0][0][0]->GetElements();
    // NativePoly coek            = ev[0] * f;
    // coek.SetFormat(Format::COEFFICIENT);
    // cout << "\n coek 解密 = " << endl;
    // for (uint32_t i = 0; i < N; i++) {
    //     std::cout << coek[i] << " ";
    // }

    // NativePoly res(polyParams, Format::EVALUATION, true);
    // res = f * acc->GetElements();
    // res.SetFormat(Format::COEFFICIENT);
    // cout << "\n res解密 = " << endl;
    // for (uint32_t i = 0; i < N; i++) {
    //     std::cout << res[i] << " ";
    // }

    AddToAccXZDDF(params, (*ek)[0][0][n], acc);

    // NativePoly res2(polyParams, Format::EVALUATION, true);
    // res2 = f * acc->GetElements();
    // res2.SetFormat(Format::COEFFICIENT);
    // cout << "\n  COEFFICIENT res2解密  = " << endl;
    // for (uint32_t i = 0; i < N; i++) {
    //     std::cout << res2[i] << " ";
    // }
}

//TODO KDM-form
VectorNTRUEvalKey VectorNTRUAccumulatorXZDDF::KDMKeyGenXZDDF(const std::shared_ptr<VectorNTRUCryptoParams>& params,
                                                             const NativePoly& invskNTT, LWEPlaintext m) const {
    auto polyParams = params->GetPolyParams();  //(Q,2N)
    auto Gpow       = params->GetGPower();      //
    DiscreteUniformGeneratorImpl<NativeVector> dug;
    NativeInteger Q{params->GetQ()};
    dug.SetModulus(Q);  //确保dug的模数是Q
                        //Reduce mod q (dealing with negative number as well)
    //int64_t q  = params->Getq().ConvertToInt<int64_t>();  //
    int64_t N  = params->GetN();
    int64_t mm = (((m % N) + N) % N);  // 0 1 N-1
    bool isReducedMM{false};
    if (m < 0) {
        isReducedMM = true;
    }
    // cout << "s=" << m << endl;
    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digitsG2{(params->GetDigitsG() - 1)};
    std::vector<NativePoly> tempA(digitsG2, NativePoly(dug, polyParams, Format::COEFFICIENT));
    VectorNTRUEvalKeyImpl result(digitsG2);
    for (uint32_t i = 0; i < digitsG2; ++i) {
        // result[i][0] = tempA[i];
        // tempA[i].SetFormat(Format::EVALUATION);
        result[i] = NativePoly(params->GetDgg(), polyParams, Format::COEFFICIENT);  //采样g
        if (!isReducedMM)
            result[i][mm].ModAddFastEq(Gpow[i + 1],
                                       Q);  // g+X^m*G
        else
            result[i][mm].ModSubFastEq(Gpow[i + 1],
                                       Q);  // g-X^m*G
        // for (uint32_t j = 0; j < 8; j++) {
        //     cout << result[i][j] << " ";
        // }
        result[i].SetFormat(Format::EVALUATION);

        // cout << endl;

        result[i] = result[i] * invskNTT;
    }
    return std::make_shared<VectorNTRUEvalKeyImpl>(result);
}
//TODO NO KDM-form
VectorNTRUEvalKey VectorNTRUAccumulatorXZDDF::KeyGenXZDDF(const std::shared_ptr<VectorNTRUCryptoParams>& params,
                                                          const NativePoly& invskNTT, LWEPlaintext m) const {
    auto polyParams = params->GetPolyParams();  //(Q,2N)
    auto Gpow       = params->GetGPower();      //

    //DiscreteUniformGeneratorImpl<NativeVector> dug;
    NativeInteger Q{params->GetQ()};
    //dug.SetModulus(Q-Q);//确保dug的模数是Q
    //Reduce mod q (dealing with negative number as well)

    //int64_t q  = params->Getq().ConvertToInt<int64_t>();  //
    int64_t N  = params->GetN();
    int64_t mm = (((m % N) + N) % N);  // 0 1 q-1
    bool isReducedMM{false};
    if (m < 0) {
        isReducedMM = true;
    }
    //cout<<" mm = "<<mm<<endl;
    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digitsG2{(params->GetDigitsG() - 1)};  //2
    //std::vector<NativePoly> tempA(digitsG2, NativePoly(dug, polyParams, Format::COEFFICIENT));
    NativePoly zeroPoly(polyParams, Format::COEFFICIENT);
    zeroPoly.SetValuesToZero();
    std::vector<NativePoly> tempA(digitsG2, zeroPoly);

    VectorNTRUEvalKeyImpl result(digitsG2);
    for (uint32_t i = 0; i < digitsG2; ++i) {
        // result[i][0] = tempA[i];
        tempA[i].SetFormat(Format::COEFFICIENT);
        result[i] = NativePoly(params->GetDgg(), polyParams, Format::COEFFICIENT);  //采样g
        result[i].SetFormat(Format::EVALUATION);
        result[i] = result[i] * invskNTT;  // g/f
        if (!isReducedMM)
            tempA[i][mm].ModAddFastEq(Gpow[i + 1], Q);  // X^m*G
        else
            tempA[i][mm].ModSubFastEq(Gpow[i + 1], Q);  // X^m*G

        // for (uint32_t j = 0; j < 8; j++) {
        //     cout << tempA[i][j] << " ";
        // }
        // cout << endl;

        tempA[i].SetFormat(Format::EVALUATION);
        result[i] = result[i] + tempA[i];
    }
    return std::make_shared<VectorNTRUEvalKeyImpl>(result);
}
VectorNTRUEvalKey VectorNTRUAccumulatorXZDDF::KeyGenAuto(const std::shared_ptr<VectorNTRUCryptoParams>& params,
                                                         const NativePoly& skNTT, const NativePoly& invskNTT,
                                                         LWEPlaintext k) const {
    //auto polyParams{params->GetPolyParams()};
    // m_polyParams{std::make_shared<ILNativeParams>(2 * N, Q)},
    // auto Gpow{params->GetGPower()};//m_Gpower,是一个3长度vector (0,1024,1048576)
    auto polyParams = params->GetPolyParams();  //(Q,2N)
    auto Gpow       = params->GetGPower();      //

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    NativeInteger Q{params->GetQ()};
    dug.SetModulus(Q);

    auto skAuto{skNTT.AutomorphismTransform(k)};  //生成f(X^k)

    // for(uint32_t i=0;i<8;i++)
    // {
    //     std::cout<<"skNTT = "<<skNTT[i]<<std::endl;
    // }
    // for(uint32_t i=0;i<8;i++)
    // {
    //     std::cout<<"skAuto = "<<skAuto[i]<<std::endl;
    // }

    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digitsG{params->GetDigitsG() - 1};
    VectorNTRUEvalKeyImpl result(digitsG);

    for (uint32_t i = 0; i < digitsG; ++i) {
        result[i] = NativePoly(params->GetDgg(), polyParams, EVALUATION) + skAuto * Gpow[i + 1];   // g+f(X^j)*B
        result[i] = result[i] * invskNTT;
    }
    return std::make_shared<VectorNTRUEvalKeyImpl>(result);
}

void VectorNTRUAccumulatorXZDDF::AddToAccXZDDF(const std::shared_ptr<VectorNTRUCryptoParams>& params,
                                               ConstVectorNTRUEvalKey& ek, NTRUCiphertext& acc) const {
    //TODO
    NativePoly ct(acc->GetElements());
    ct.SetFormat(Format::COEFFICIENT);
    // cout << "ct = " << endl;
    // for (uint32_t i = 0; i < 8; i++) {
    //     std::cout << ct[i] << " ";
    // }
    // ct.SetFormat(Format::EVALUATION);

    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digitsG{(params->GetDigitsG() - 1)};
    //std::cout << "\n digitsG = " << digitsG << endl;

    std::vector<NativePoly> dct(digitsG,NativePoly(params->GetPolyParams(), Format::COEFFICIENT, true));  // d-1维N长多项式
    SignedDigitDecompose(params, ct, dct);                                                        //分解acc
    // calls digitsG2 NTTs
    NativePoly sum(params->GetPolyParams(), Format::EVALUATION, true);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(digitsG))
    for (uint32_t d = 0; d < digitsG; ++d)
        dct[d].SetFormat(Format::EVALUATION);
    // acc = dct * ek (matrix product);
    const std::vector<NativePoly>& ev = ek->GetElements();
    for (uint32_t d = 0; d < digitsG; ++d)
        sum += (dct[d] *= ev[d]);

    acc->GetElements() = sum;
}

void VectorNTRUAccumulatorXZDDF::Automorphism(const std::shared_ptr<VectorNTRUCryptoParams>& params,
                                              const NativeInteger& a, ConstVectorNTRUEvalKey& ak,
                                              NTRUCiphertext& acc) const {
    // precompute bit reversal for the automorphism into vec
    uint32_t N{params->GetN()};
    std::vector<usint> vec(N);
    PrecomputeAutoMap(N, a.ConvertToInt<usint>(), &vec);  //
    NativePoly ct(acc->GetElements());
    acc->GetElements().SetValuesToZero();
    ct = ct.AutomorphismTransform(a.ConvertToInt<usint>(), vec);
    ct.SetFormat(COEFFICIENT);
    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digitsG{params->GetDigitsG() - 1};
    std::vector<NativePoly> dct(digitsG, NativePoly(params->GetPolyParams(), Format::COEFFICIENT, true));
    SignedDigitDecompose(params, ct, dct);
    NativePoly sum(params->GetPolyParams(), Format::EVALUATION, true);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(digitsG))
    for (uint32_t d = 0; d < digitsG; ++d)
        dct[d].SetFormat(Format::EVALUATION);
    // acc = dct * input (matrix product);
    const std::vector<NativePoly>& ev = ak->GetElements();
    for (uint32_t d = 0; d < digitsG; ++d)
        sum += (dct[d] * ev[d]);

    acc->GetElements() = sum;
}

};  // namespace lbcrypto