//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  Header file for BinFHEContext class, which is used for Boolean circuit FHE schemes
 */

#ifndef BINFHE_BINFHECONTEXT_H
#define BINFHE_BINFHECONTEXT_H

#include "binfhe-base-scheme.h"

#include "lattice/stdlatticeparms.h"
#include "utils/serializable.h"

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace lbcrypto {

// TODO: reorder to optimize struct size/alignment
// TODO: 重新排列以优化结构体大小和对齐方式
struct BinFHEContextParams {
    // for intermediate prime, modulus for RingGSW / RLWE used in bootstrapping
    // 中间素数，用于启动中的RingGSW / RLWE的模数
    usint numberBits;// 数字位数
    usint cyclOrder;// 循环阶数

    // for LWE crypto parameters
    // LWE密码参数
    usint latticeParam;// 格参数
    usint mod;  // modulus for additive LWE  // 加法LWE的模数
    // modulus for key switching; if it is zero, then it is replaced with intermediate prime for LWE crypto parameters
    // 密钥切换的模数；如果为零，则替换为LWE密码参数中的中间素数
    usint modKS;        // 密钥切换模数
    double stdDev;      // 标准偏差
    usint baseKS;  // base for key switching // 密钥切换基数

    // for Ring GSW + LWE parameters
    // Ring GSW + LWE参数
    usint gadgetBase;  // gadget base used in the bootstrapping // 启动中使用的工具基数
    usint baseRK;      // base for the refreshing key // 刷新密钥基数

    // number of Automorphism keys for LMKCDEY (> 0)
    // Automorphism密钥的数量（大于0）
    usint numAutoKeys; // 自同构密钥数量

    // for key distribution
    // 密钥分布
    SecretKeyDist keyDist;  // 密钥分布 SecretKeyDist是枚举变量
};



/**
 * @brief BinFHEContext
 *
 * The wrapper class for Boolean circuit FHE
 */
//BinFHEContext是派生类，继承与基类Serializable，Serializable 是一个纯虚类，用于所有需要支持序列化的类继承
//当其他类继承 Serializable 并实现 SerializedObjectName() 函数时，它们变成了 Serializable 类的派生类，表明它们支持序列化。
//这样，这些派生类可以通过序列化库将它们的状态序列化为字节流以进行存储或传输。
class BinFHEContext : public Serializable {

//调整到前面了
private:
    // Shared pointer to Ring GSW + LWE parameters
    //指向BinFHECryptoParams对象的共享指针。它用于存储Ring GSW + LWE参数，这些参数在加密和解密过程中起关键作用。
    std::shared_ptr<BinFHECryptoParams> m_params{nullptr};

    // Shared pointer to the underlying additive LWE scheme
    //指向LWEEncryptionScheme对象的共享指针。它表示底层的加法LWE（Learning With Errors）加密方案，通常与Ring GSW + LWE一起使用。
    std::shared_ptr<LWEEncryptionScheme> m_LWEscheme{nullptr};

    // Shared pointer to the underlying RingGSW/RLWE scheme
    std::shared_ptr<BinFHEScheme> m_binfhescheme{nullptr};

    // Struct containing the bootstrapping keys
    // RingGSWBTKey类型的结构体，包含用于bootstrapping的密钥
    RingGSWBTKey m_BTKey = {0};

    //这是一个std::map，它用于存储不同参数下的bootstrapping密钥。uint32_t表示参数的标识，RingGSWBTKey表示与该参数相关的密钥
    std::map<uint32_t, RingGSWBTKey> m_BTKey_map;
    
    // Whether to optimize time for sign eval
    //这是一个布尔值，用于表示是否启用了时间优化。如果为true，则表示已启用时间优化，以提高性能；
    //如果为false，则表示未启用时间优化。这通常用于决定在计算中是否使用一些优化策略，以减少执行时间。
    bool m_timeOptimization{false};

    //wkx
    VectorNTRUBTKey m_NBTKey = {0};

    //wkx
    std::map<uint32_t, VectorNTRUBTKey> m_NBTKey_map;

public:
    //使用默认生成的构造函数。  
    BinFHEContext() = default;

    /**
   * Creates a crypto context using custom parameters.
   * Should be used with care (only for advanced users familiar with LWE
   * parameter selection).
   * 使用自定义参数创建加密上下文。
   * 应谨慎使用（仅适用于熟悉LWE参数选择的高级用户）。
   * @param n lattice parameter for additive LWE scheme 添加性LWE方案的晶格参数
   * @param N ring dimension for RingGSW/RLWE used in bootstrapping 用于RingGSW/RLWE中bootstrapping的环维度
   * @param q modulus for additive LWE 添加性LWE的模数
   * @param Q modulus for RingGSW/RLWE used in bootstrapping 用于bootstrapping操作的RingGSW/RLWE的模数
   * @param std standard deviation 标准差
   * @param baseKS the base used for key switching 用于密钥切换的基数
   * @param baseG the gadget base used in bootstrapping 用于bootstrapping中的装置基数
   * @param baseR the base used for refreshing 用于刷新的基数
   * @param keyDist secret key distribution 密钥分布
   * @param method the bootstrapping method (DM or CGGI or LMKCDEY)
   * @param numAutoKeys number of automorphism keys in LMKCDEY bootstrapping  LMKCDEY bootstrapping中的自同态密钥数量
   * @return creates the cryptocontext 创建密文
   */
    void GenerateBinFHEContext(uint32_t n, uint32_t N, const NativeInteger& q, const NativeInteger& Q, double std,
                               uint32_t baseKS, uint32_t baseG, uint32_t baseR, SecretKeyDist keyDist = UNIFORM_TERNARY,
                               BINFHE_METHOD method = GINX, uint32_t numAutoKeys = 10);

    /**
   * Creates a crypto context using custom parameters.
   * Should be used with care (only for advanced users familiar with LWE
   * parameter selection).
   * 使用自定义参数创建加密上下文。
   * 应谨慎使用（仅适用于熟悉LWE参数选择的高级用户）。
   * @param set the parameter set: TOY, MEDIUM, STD128, STD192, STD256 with variants, see binfhe_constants.h 枚举变量
   * @param arbFunc whether need to evaluate an arbitrary function using functional bootstrapping  是否需要使用功能性启动来评估任意函数
   * @param logQ log(input ciphertext modulus)
   * @param N ring dimension for RingGSW/RLWE used in bootstrapping
   * @param method the bootstrapping method (DM or CGGI or LMKCDEY)
   * @param timeOptimization whether to use dynamic bootstrapping technique
   * @return creates the cryptocontext
   */
    void GenerateBinFHEContext(BINFHE_PARAMSET set,//枚举变量
     bool arbFunc, uint32_t logQ = 11, int64_t N = 0,
                               BINFHE_METHOD method = GINX, bool timeOptimization = false);


    /*----------------------------------推荐-------------------------------------------*/
    /**
   * Creates a crypto context using predefined parameters sets. Recommended for
   * most users.
   * 使用预定义的参数集创建加密上下文。推荐给大多数用户。
   * @param set the parameter set: TOY, MEDIUM, STD128, STD192, STD256 with variants, see binfhe_constants.h
   * @param method the bootstrapping method (DM or CGGI or LMKCDEY)
   * @return create the cryptocontext
   */
    void GenerateBinFHEContext(BINFHE_PARAMSET set, BINFHE_METHOD method = GINX);

    /**
   * Creates a crypto context using custom parameters.
   * 使用自定义参数创建加密上下文。
   * @param params the parameter context
   * @param method the bootstrapping method (DM or CGGI or LMKCDEY)
   * @return create the cryptocontext
   */
    void GenerateBinFHEContext(const BinFHEContextParams& params, BINFHE_METHOD method = GINX);

    /**
   * Gets the refresh key (used for serialization).
   *
   * @return a shared pointer to the refresh key
   */
    const RingGSWACCKey& GetRefreshKey() const {
        return m_BTKey.BSkey;
    }
    const VectorNTRUACCKey& GetNRefreshKey() const {
        return m_NBTKey.BSkey;
    }//wkx

    /**
   * Gets the switching key (used for serialization).
   *
   * @return a shared pointer to the switching key
   */
    const LWESwitchingKey& GetSwitchKey() const {
        return m_BTKey.KSkey;
    }
    const LWESwitchingKey& GetNSwitchKey() const {
        return m_NBTKey.KSkey;
    }//wkx

    /**
   * Gets the public key (used for serialization).
   *
   * @return a shared pointer to the public key
   */
    const LWEPublicKey& GetPublicKey() const {
        return m_BTKey.Pkey;
    }
    const LWEPublicKey& GetNPublicKey() const {
        return m_NBTKey.Pkey;
    }//wkx

    /**
    * Gets the bootstrapping key map (used for serialization).
    *
    * @return a shared pointer to the bootstrapping key map
    * 它返回一个shared_ptr（共享指针），该指针指向一个映射（map），映射的键类型是 uint32_t，值类型是 RingGSWBTKey。
    */
    const std::shared_ptr<std::map<uint32_t, RingGSWBTKey>> GetBTKeyMap() const {
        return std::make_shared<std::map<uint32_t, RingGSWBTKey>>(m_BTKey_map);
    }
    const std::shared_ptr<std::map<uint32_t, VectorNTRUBTKey>> GetNBTKeyMap() const {
        return std::make_shared<std::map<uint32_t, VectorNTRUBTKey>>(m_NBTKey_map);
    }//wkx

    /**
   * Generates a secret key for the main LWE scheme
   *
   * @return a shared pointer to the secret key
   */
    LWEPrivateKey KeyGen() const;

    /**
   * Generates a public key, secret key pair for the main LWE scheme
   *
   * @return a shared pointer to the public key, secret key pair
   */
    LWEKeyPair KeyGenPair() const;

    /**
   * Generates a public key for a secret key for the main LWE scheme
   *
   * @return a shared pointer to the public key
   */
    LWEPublicKey PubKeyGen(ConstLWEPrivateKey& sk) const;

    /**
   * Generates a secret key used in bootstrapping
   * @return a shared pointer to the secret key
   */
    LWEPrivateKey KeyGenN() const;

    /**
   * Encrypts a bit or integer using a secret key (symmetric key encryption)
   *
   * @param sk the secret key
   * @param m the plaintext
   * @param output FRESH to generate fresh ciphertext, BOOTSTRAPPED to
   * generate a refreshed ciphertext (default)
   * @param p plaintext modulus
   * @param mod the ciphertext modulus to encrypt with; by default m_q in params
   * @return a shared pointer to the ciphertext
   */
    LWECiphertext Encrypt(ConstLWEPrivateKey& sk, LWEPlaintext m, BINFHE_OUTPUT output = BOOTSTRAPPED,
                          LWEPlaintextModulus p = 4, const NativeInteger& mod = 0) const;

    /**
   * Encrypts a bit or integer using a public key (public key encryption)
   *
   * @param pk the public key
   * @param m the plaintext
   * @param output SMALL_DIM to generate ciphertext with dimension n (default). LARGE_DIM to generate ciphertext with dimension N
   * @param p plaintext modulus
   * @param mod the ciphertext modulus to encrypt with; by default m_q in params
   * @return a shared pointer to the ciphertext
   */
    LWECiphertext Encrypt(ConstLWEPublicKey& pk, LWEPlaintext m, BINFHE_OUTPUT output = SMALL_DIM,
                          LWEPlaintextModulus p = 4, const NativeInteger& mod = 0) const;

    /**
   * Converts a ciphertext (public key encryption) with modulus Q and dimension N to ciphertext with q and n
   *
   * @param ksk the key switching key from secret key of dimension N to secret key of dimension n
   * @param ct the ciphertext to convert
   * @return a shared pointer to the ciphertext
   */
    LWECiphertext SwitchCTtoqn(ConstLWESwitchingKey& ksk, ConstLWECiphertext& ct) const;

    /**
   * Decrypts a ciphertext using a secret key
   *
   * @param sk the secret key
   * @param ct the ciphertext
   * @param result plaintext result
   * @param p plaintext modulus
   */
    void Decrypt(ConstLWEPrivateKey& sk, ConstLWECiphertext& ct, LWEPlaintext* result, LWEPlaintextModulus p = 4) const;

    /**
   * Generates a switching key to go from a secret key with (Q,N) to a secret
   * key with (q,n)
   *
   * @param sk new secret key
   * @param skN old secret key
   * @return a shared pointer to the switching key
   */
    LWESwitchingKey KeySwitchGen(ConstLWEPrivateKey& sk, ConstLWEPrivateKey& skN) const;

    /**
   * Generates boostrapping keys
   *
   * @param sk secret key
   * @param keygenMode key generation mode for symmetric or public encryption
   */
    void BTKeyGen(ConstLWEPrivateKey& sk, KEYGEN_MODE keygenMode = SYM_ENCRYPT);
    void NBTKeyGen(ConstLWEPrivateKey& sk, KEYGEN_MODE keygenMode = SYM_ENCRYPT);//wkx

    /**
   * Loads bootstrapping keys in the context (typically after deserializing)
   *
   * @param key struct with the bootstrapping keys
   */
    void BTKeyLoad(const RingGSWBTKey& key) {
        m_BTKey = key;
    }
    void NBTKeyLoad(const VectorNTRUBTKey& key) {
        m_NBTKey = key;
    }//wkx

    /**
   * Loads a bootstrapping key map element in the context (typically after deserializing)
   *
   * @param baseG baseG corresponding to the given key
   * @param key struct with the bootstrapping keys
   */
    void BTKeyMapLoadSingleElement(uint32_t baseG, const RingGSWBTKey& key) {
        m_BTKey_map[baseG] = key;
    }
    void NBTKeyMapLoadSingleElement(uint32_t baseG, const VectorNTRUBTKey& key) {
        m_NBTKey_map[baseG] = key;
    }
    /**
   * Clear the bootstrapping keys in the current context
   */
    void ClearBTKeys() {
        m_BTKey.BSkey.reset();
        m_BTKey.KSkey.reset();
        m_BTKey.Pkey.reset();
        m_BTKey_map.clear();
        //wkx
        m_NBTKey.BSkey.reset();
        m_NBTKey.KSkey.reset();
        m_NBTKey.Pkey.reset();
        m_NBTKey_map.clear();
    }

    /**
   * Evaluates a binary gate (calls bootstrapping as a subroutine)
   *
   * @param gate the gate; can be AND, OR, NAND, NOR, XOR, or XNOR
   * @param ct1 first ciphertext
   * @param ct2 second ciphertext
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalBinGate(BINGATE gate, ConstLWECiphertext& ct1, ConstLWECiphertext& ct2) const;

    /**
   * Evaluates a binary gate on vector of ciphertexts (calls bootstrapping as a subroutine)
   *
   * @param gate the gate; can be MAJORITY, AND3, OR3, AND4, OR4, or CMUX
   * @param ctvector vector of ciphertexts
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalBinGate(BINGATE gate, const std::vector<LWECiphertext>& ctvector) const;

    /**
   * Bootstraps a ciphertext (without peforming any operation)
   *
   * @param ct ciphertext to be bootstrapped
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext Bootstrap(ConstLWECiphertext& ct) const;

    /**
   * Evaluate an arbitrary function
   *
   * @param ct ciphertext to be bootstrapped
   * @param LUT the look-up table of the to-be-evaluated function
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalFunc(ConstLWECiphertext& ct, const std::vector<NativeInteger>& LUT) const;

    /**
   * Generate the LUT for the to-be-evaluated function
   *
   * @param f the to-be-evaluated function on an integer message and a plaintext modulus
   * @param p plaintext modulus
   * @return a shared pointer to the resulting ciphertext
   */
    std::vector<NativeInteger> GenerateLUTviaFunction(NativeInteger (*f)(NativeInteger m, NativeInteger p),
                                                      NativeInteger p);

    /**
   * Evaluate a round down function
   *
   * @param ct ciphertext to be bootstrapped
   * @param roundbits number of bits to be rounded
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalFloor(ConstLWECiphertext& ct, uint32_t roundbits = 0) const;

    /**
   * Evaluate a sign function over large precisions
   *
   * @param ct ciphertext to be bootstrapped
   * @param schemeSwitch flag that indicates if it should be compatible to scheme switching
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalSign(ConstLWECiphertext& ct, bool schemeSwitch = false);

    /**
   * Evaluate ciphertext decomposition
   *
   * @param ct ciphertext to be bootstrapped
   * @return a vector of shared pointers to the resulting ciphertexts
   */
    std::vector<LWECiphertext> EvalDecomp(ConstLWECiphertext& ct);

    /**
   * Evaluates NOT gate
   *
   * @param ct the input ciphertext
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalNOT(ConstLWECiphertext& ct) const;

    /**
   * Evaluates constant gate
   *
   * @param value the Boolean value to output
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalConstant(bool value) const;

    /**
   * Getter for params
   * @return
   */
    const std::shared_ptr<BinFHECryptoParams>& GetParams() {
        return m_params;
    }

    /**
   * Getter for LWE scheme
   * @return
   */
    const std::shared_ptr<LWEEncryptionScheme>& GetLWEScheme() {
        return m_LWEscheme;
    }

    /**
   * Getter for BinFHE scheme params
   * @return
   */
    const std::shared_ptr<BinFHEScheme>& GetBinFHEScheme() {
        return m_binfhescheme;
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("params", m_params));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }
        ar(::cereal::make_nvp("params", m_params));
        m_binfhescheme = std::make_shared<BinFHEScheme>(m_params->GetRingGSWParams()->GetMethod());
        //wkx
        (m_params->GetVectorNTRUParams()->GetMethod());
    }

    std::string SerializedObjectName() const override {
        return "BinFHEContext";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

    /**
   * Getter for maximum plaintext modulus
   * @return
   */
    NativeInteger GetMaxPlaintextSpace() const {
        // Under our parameter choices, beta = 128 is enough, and therefore plaintext = q/2beta
        return m_params->GetLWEParams()->Getq() / (this->GetBeta() << 1);
    }

    /**
   * Getter for the beta security parameter
   * @return
   */
    constexpr NativeInteger GetBeta() const {
        return NativeInteger(128);
    }

};

}  // namespace lbcrypto

#endif
