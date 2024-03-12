
#include "vntru-acc-xznew.h"

#include <string>
#include <vector>
namespace lbcrypto {

VectorNTRUACCKey VectorNTRUAccumulatorXZNEW::KeyGenAcc(const std::shared_ptr<VectorNTRUCryptoParams>& params,
                                                       const NativePoly& skNTT, const NativePoly& invskNTT,
                                                       ConstLWEPrivateKey& LWEsk) const {
    //TODO
    auto sv{LWEsk->GetElement()};
    auto mod{sv.GetModulus().ConvertToInt<int32_t>()};  //q_ks
    auto modHalf{mod >> 1};
    size_t n{sv.GetLength()};
    auto q{params->Getq().ConvertToInt<size_t>()};
    VectorNTRUACCKey ek = std::make_shared<VectorNTRUACCKeyImpl>(1, 2, q - 1 > n + 1 ? q - 1 : n + 1);

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(n))
    //和xzddf不同 这里全部改为非kdm的加密
    for (size_t i = 0; i < n; ++i) {
        auto s{sv[i].ConvertToInt<int32_t>()};
        (*ek)[0][0][i] = KeyGenXZNEW(params, invskNTT, s > modHalf ? mod - s : -s);
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

    //NTRU'(X^{sum s}/f(X))
    (*ek)[0][0][n] = KDMKeyGenXZNEW(params, invskNTT, 5*sums);

     /*----------生成优化的自同构秘钥-----------*/
    uint32_t numAutoKeys{params->GetNumAutoKeys()};
    NativeInteger gen = NativeInteger(5);
    uint32_t N{params->GetN()};
    (*ek)[0][1][0] = KeyGenAuto(params, skNTT, invskNTT, 2 * N - gen.ConvertToInt());// X --> X^(-g)  f X^(-g)-->f X
    // m_window: window size, consider parameterization in the future
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(numAutoKeys))
    for (uint32_t i = 1; i <= numAutoKeys; ++i)
        (*ek)[0][1][i] = KeyGenAuto(params, skNTT, invskNTT, gen.ModExp(i, 2 * N).ConvertToInt<LWEPlaintext>());
    return ek;


    return ek;
}

void VectorNTRUAccumulatorXZNEW::EvalAcc(const std::shared_ptr<VectorNTRUCryptoParams>& params,
                                         ConstVectorNTRUACCKey& ek, NTRUCiphertext& acc, const NativeVector& a,NativePoly f) const {
    //TODO
    //cout<<"start eval acc"<<endl;
    // clock_t start = clock();
    size_t n   = a.GetLength();
    uint32_t N = params->GetN();
    int32_t q  = params->Getq().ConvertToInt<int32_t>();
    //uint32_t M           = 2 * params->GetN();
    std::vector<uint32_t> ua(n);
    std::vector<uint32_t> w(n);
    //std::vector<uint32_t> invw(n + 1);
    //invw[n] = 1;
    //std::vector<NativeInteger> NATIVEw(n);  //自同构的次数
    //std::vector<uint32_t> invindex(n);      //对应到autk 的index

    auto polyParams = params->GetPolyParams();


    for (size_t i = 0; i < n; i++) {
        ua[i]   = a[i].ConvertToInt<int32_t>();       //a
        //cout<<"ua[0] = "<< ua[i]<<endl;
        w[i]    = (2 * N / q) * ua[i] + 1;            //w_i
        // invw[i] = ModInverse(w[i], 2 * N) % (2 * N);  //w_inv
    }
    // std::cout << "w0=" << w[0] << std::endl;
    // std::cout << "invw0=" << invw[0] << std::endl;
    // for (size_t i = 0; i < n; i++) {
    //     NATIVEw[i] = NativeVector::Integer((w[i] * invw[i + 1]) % (2 * N));
    //     //std::cout<<"inverse"<< NATIVEw[i];
    //     invindex[i] = (NATIVEw[i].ConvertToInt<int32_t>() - 3) / 2;
    // }
    //cout << "输入的acc = " << endl;
    // NativePoly acc_in(polyParams, Format::EVALUATION, true);
    // acc_in = acc->GetElements();
    // acc_in.SetFormat(COEFFICIENT);
    // for (uint32_t i = 0; i < N; i++) {
    //     cout << acc_in[i] << " ";
    // }

    // NativePoly res1(polyParams, Format::EVALUATION, true);
    // f.SetFormat(EVALUATION);
    // res1 = f * acc->GetElements();
    // res1.SetFormat(Format::COEFFICIENT);
    // cout << "\n 盲选转前的 acc0 的解密 = " << endl;
    // for (uint32_t i = 0; i < N; i++) {
    //     std::cout << res1[i] << " ";
    // }


    /*-----------------------优化的迭代乘和自同构------------------------------------*/
    uint32_t Nh          = params->GetN() / 2;
    uint32_t M           = 2 * params->GetN();
    uint32_t numAutoKeys = params->GetNumAutoKeys();
    NativeInteger MNative(M);
    auto logGen = params->GetLogGen();
    // clock_t startMap = clock();
    std::unordered_map<int32_t, std::vector<int32_t>> permuteMap;
    for (size_t i = 0; i < n; i++) { 
        //cout<<"what ";
        auto aIOdd = w[i];
        //cout<<aIOdd<<" ";
        int32_t index = logGen[aIOdd];
        // cout<<"logGen["<<w[i]<<"] = "<<index<<endl;

        if (permuteMap.find(index) == permuteMap.end()) {
            std::vector<int32_t> indexVec;
            permuteMap[index] = indexVec;
        }
        auto& indexVec = permuteMap[index];
        indexVec.push_back(i);
    }
    // std::cout << "Map in " << float(clock()-startMap)*1000/CLOCKS_PER_SEC<<"ms" << std::endl;

    //cout<<"\n ---盲选转---"<<endl;
    NativeInteger gen(5);
    uint32_t genInt       = 5;
    uint32_t nSkips       = 0;

        //xbw
        //AddToAccXZNEW(params, (*ek)[0][0][n+2], acc);

    //cout<<"先对acc0做一次X^-g的自同构"<<endl;
    // acc->GetElements() = (acc->GetElements()).AutomorphismTransform(M - genInt); // 先对acc0做一次X^-g的自同构
    //new
    acc->GetElements() = (acc->GetElements()).AutomorphismTransform(genInt); // 先对acc0做一次X^g的自同构

    // NativePoly res22222(polyParams, Format::EVALUATION, true);
    // res22222 =  acc->GetElements();
    // res22222.SetFormat(Format::COEFFICIENT);
    // for (uint32_t i = 0; i < N; i++) {
    //     std::cout << res22222[i] << " ";
    // }
    // cout<<endl;

    // clock_t startRT = clock();
    // cout<<"乘NTRU'密文，转化成NTRU"<<endl;
    //转化成NTRU'
    //wkx
    AddToAccXZNEW(params, (*ek)[0][0][n], acc);

    // NativePoly res2222(polyParams, Format::EVALUATION, true);
    // f.SetFormat(EVALUATION);
    // res2222 = f * acc->GetElements();
    // res2222.SetFormat(Format::COEFFICIENT);
    // for (uint32_t i = 0; i < N; i++) {
    //     std::cout << res2222[i] << " ";
    // }
    // cout<<endl;
    int num_Automorphism = 1;
    /*------------------------------------------------------------------------*/

    // for a_j = 5^i
    for (size_t i = Nh - 1; i > 0; i--) {
        if (permuteMap.find(i) != permuteMap.end()) {
            //cout<<"crycle 3"<<endl;
            if (nSkips != 0) {  // Rotation by 5^nSkips
                //cout<<"自同构并密钥切换2"<<endl;
                Automorphism(params, gen.ModExp(nSkips, M), (*ek)[0][1][nSkips], acc);
                num_Automorphism++;
                nSkips = 0;
            }

            auto& indexVec = permuteMap[i];
            for (size_t j = 0; j < indexVec.size(); j++) {
                // if(indexVec[j] == 0)
                // {
                //     cout<<"X^s_0 in for w_0 = 5^i = 1 a_0 = 0"<<endl;
                //     cout<<"i = "<<i<<endl;
                // }
                AddToAccXZNEW(params, (*ek)[0][0][indexVec[j]], acc);
            }
        }
        nSkips++;

        if (nSkips == numAutoKeys || i == 1) {
            //cout<<"### 自同构并密钥切换 g^"<<nSkips<<"并解密验证此后的acc:"<<endl;
            Automorphism(params, gen.ModExp(nSkips, M), (*ek)[0][1][nSkips], acc);
            num_Automorphism++;
            // NativePoly res22(polyParams, Format::EVALUATION, true);
            // f.SetFormat(EVALUATION);
            // res22 = f * acc->GetElements();
            // res22.SetFormat(Format::COEFFICIENT);
            // for (uint32_t i = 0; i < N; i++) {
            //     std::cout << res22[i] << " ";
            // }
            // cout<<endl;
            nSkips = 0;
        }
    }


    // acc->GetElements() = (acc->GetElements()).AutomorphismTransform(M - genInt);  / X-g
    // uint32_t t = gen.ModExp(6, M).ConvertToInt<uint32_t>();
    // cout<<"\nt="<<t<<endl;
    // acc->GetElements() = (acc->GetElements()).AutomorphismTransform(t);


    
    //cout<<"\n开始对自同构X^{g^{8}}后的acc解密"<<endl;
    // NativePoly res22(polyParams, Format::EVALUATION, true);
    // f.SetFormat(EVALUATION);
    // res22 = f * acc->GetElements();
    // res22.SetFormat(Format::COEFFICIENT);
    // cout << "\n自同构X^{g^{8}}后的acc的 acc解密  系数应该全是+-Q/8" << endl;
    // for (uint32_t i = 0; i < N; i++) {
    //     std::cout << res22[i] << " ";
    // }
    // cout<<endl;

    // for a_j=1 .0
    // std::cout << "S3 in " << float(clock()-startS3)*1000/CLOCKS_PER_SEC<<"ms" << std::endl;
    // clock_t startS4 = clock();
    if (permuteMap.find(0) != permuteMap.end()) {
        //cout<<"crycle 4"<<endl;
        auto& indexVec = permuteMap[0];
        for (size_t j = 0; j < indexVec.size(); j++) {
            // if(indexVec[j] == 0)
            // {
            //     cout<<"X^s_0 in for w_0=0  a_0=0"<<endl;
            //     cout<<"i = "<<0<<endl;
            // } 
            AddToAccXZNEW(params, (*ek)[0][0][indexVec[j]], acc);
        }
    }
    // std::cout << "S4 in " << float(clock()-startS4)*1000/CLOCKS_PER_SEC<<"ms" << std::endl;
    // NativePoly res2(polyParams, Format::EVALUATION, true);
    // f.SetFormat(EVALUATION);
    // res2 = f * acc->GetElements();
    // res2.SetFormat(Format::COEFFICIENT);
    // cout << "\nsums 前的 acc解密 = 某项系数应该是+-Q/8" << endl;
    // for (uint32_t i = 0; i < N; i++) {
    //     std::cout << res2[i] << " ";
    // }
    /*------------------------------------------------------------------------*/

    // std::cout << "Rotation in " << float(clock()-startRT)*1000/CLOCKS_PER_SEC<<"ms" << std::endl;
    // -sum s
    // AddToAccXZNEW(params, (*ek)[0][0][n], acc);
    // cout<<"num_Automorphism = "<<num_Automorphism<<" ";
    // std::cout << "Evalacc in " << float(clock()-start)*1000/CLOCKS_PER_SEC<<"ms ";

    //cout<<num_Automorphism<<",";
    // cout<<"\nn="<<n<<endl;
    // cout<<"\n(*ek)[0][0][n] = "<<endl;
    // for(uint32_t i =0;i<(*ek)[0][0][n]->GetElements().size();i++)
    // {
    //     for(uint32_t j=0;j<8;j++)
    //     {
    //         NativePoly res3 = (*ek)[0][0][n]->GetElements()[i];
    //         res3.SetFormat(COEFFICIENT);
    //         cout<<res3[j]<<" ";
    //     }
    //     cout<<endl;
    // }


    // NativePoly res3(polyParams, Format::EVALUATION, true);
    // NativePoly sums = (*ek)[0][0][n]->GetElements()[0];
    // f.SetFormat(EVALUATION);
    // res3 = f * sums;
    // res3.SetFormat(Format::COEFFICIENT);
    // cout << "\nsum 的 acc解密 = " << endl;
    // for (uint32_t i = 0; i < N; i++) {
    //     std::cout << res3[i] << " ";
    // }



    /*解密acc*/
    //f.SetFormat(COEFFICIENT);
    // cout << "\n f = " << endl;
    // for (uint32_t i = 0; i < N; i++) {
    //     std::cout << f[i] << " ";
    // }
    // f.SetFormat(EVALUATION);

    // NativePoly res(polyParams, Format::EVALUATION, true);
    // f.SetFormat(EVALUATION);
    // res = f * acc->GetElements();
    // res.SetFormat(Format::COEFFICIENT);
    // cout << "\n sum 后的 acc解密 = " << endl;
    // for (uint32_t i = 0; i < N; i++) {
    //     std::cout << res[i] << " ";
    // }

    
}



//
VectorNTRUEvalKey VectorNTRUAccumulatorXZNEW::KeyGenXZNEW_extend(const std::shared_ptr<VectorNTRUCryptoParams>& params,
                                                             const NativePoly& invskNTT, const NativePoly& m_poly) const {
    auto polyParams = params->GetPolyParams();  //(Q,2N)
    auto Gpow       = params->GetGPower();      //
    DiscreteUniformGeneratorImpl<NativeVector> dug;
    NativeInteger Q{params->GetQ()};
    dug.SetModulus(Q);  //确保dug的模数是Q
                        //Reduce mod q (dealing with negative number as well)
    //int64_t q  = params->Getq().ConvertToInt<int64_t>();  //
    //int64_t N  = params->GetN();
    // int64_t mm = (((m % N) + N) % N);  // 0 1 N-1
    // bool isReducedMM{false};
    // if (m < 0) {
    //     isReducedMM = true;
    // }
    // cout << "s=" << m << endl;
    // approximate gadget decomposition is used; the first digit is ignored
    uint32_t digitsG2{(params->GetDigitsG() - 1)};
    VectorNTRUEvalKeyImpl result(digitsG2);

    NativePoly zeroPoly(polyParams, Format::COEFFICIENT);
    zeroPoly.SetValuesToZero();
    std::vector<NativePoly> tempA(digitsG2, zeroPoly);
    NativePoly coe_m_poly = m_poly;
    coe_m_poly.SetFormat(COEFFICIENT);
    //cout<<"\nin KeyGenXZNEW_extend "<<endl;
    // for(int i=0;i<8;i++)
    // {
    //     cout<<coe_m_poly[i]<<" ";
    // }
    // cout<<endl;

    // cout<<"\n m * G "<<endl;
    for (uint32_t i = 0; i < digitsG2; ++i) {
        // result[i][0] = tempA[i];
        // tempA[i].SetFormat(Format::EVALUATION);
        result[i] = NativePoly(params->GetDgg(), polyParams, Format::COEFFICIENT);  //采样g
        result[i].SetFormat(Format::EVALUATION);
        result[i] = result[i] * invskNTT;  // g/f

        tempA[i] = Gpow[i + 1]*coe_m_poly;  //  m*G
        // for(int j=0;j<8;j++)
        // {
        //     cout<<tempA[i][j]<<" ";
        // }
        // cout<<endl;

        tempA[i].SetFormat(Format::EVALUATION);
        result[i] = result[i] + tempA[i];
    }
    return std::make_shared<VectorNTRUEvalKeyImpl>(result);
}


//TODO KDM-form
VectorNTRUEvalKey VectorNTRUAccumulatorXZNEW::KDMKeyGenXZNEW(const std::shared_ptr<VectorNTRUCryptoParams>& params,
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
            result[i][mm].ModAddFastEq(Gpow[i + 1],Q);  // g+X^m*G
        else
            result[i][mm].ModSubFastEq(Gpow[i + 1],Q);  // g-X^m*G
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
VectorNTRUEvalKey VectorNTRUAccumulatorXZNEW::KeyGenXZNEW(const std::shared_ptr<VectorNTRUCryptoParams>& params,
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
    //cout<<"\nin KeyGenXZNEW mm = "<< mm <<endl;
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
VectorNTRUEvalKey VectorNTRUAccumulatorXZNEW::KeyGenAuto(const std::shared_ptr<VectorNTRUCryptoParams>& params,
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

void VectorNTRUAccumulatorXZNEW::AddToAccXZNEW(const std::shared_ptr<VectorNTRUCryptoParams>& params,
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

    std::vector<NativePoly> dct(digitsG,
                                NativePoly(params->GetPolyParams(), Format::COEFFICIENT, true));  // d-1维N长多项式
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


//自同构+密钥切换
void VectorNTRUAccumulatorXZNEW::Automorphism(const std::shared_ptr<VectorNTRUCryptoParams>& params,
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