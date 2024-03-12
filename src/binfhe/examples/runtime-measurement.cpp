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
 * Custom Modifications:
 * - [This code is the implementation of the algorithm in the paper https://eprint.iacr.org/2023/1564]
 * 
 * This modified section follows the terms of the original BSD 2-Clause License.
 * Other modifications are provided under the terms of the BSD 2-Clause License.
 * See the BSD 2-Clause License text below:
 */


//==================================================================================
// Additional BSD License for Custom Modifications:
//
// Copyright (c) 2023 Binwu Xiang,Kaixing Wang and other contributors
//
// All rights reserved.
//
// Author TPOC: wangkaixing22@mails.ucas.ac.cn
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
#include "binfhecontext.h"

using namespace lbcrypto;


void test(uint32_t cyc_times,BINFHE_METHOD method,BINFHE_PARAMSET set)
{
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(set, method);
    auto sk = cc.KeyGen();
    int m0=1;
    int m1=1;
    // LWEPlaintext result;
    //std::cout << "Generating the bootstrapping keys..." << std::endl;
    if(method == XZDDF || method == XZNEW)
    {
        cc.NBTKeyGen(sk);
    }else{
        cc.BTKeyGen(sk);
    }


    //std::cout << "Completed the key generation." << std::endl;
    auto ct1 = cc.Encrypt(sk, m0);
    auto ct2 = cc.Encrypt(sk, m1);
    LWECiphertext ctAND1;
    //std::cout << "Start  the  gate bootstrapping " << std::endl;

    clock_t start = clock();
    for(uint32_t i=0;i<cyc_times;i++)
    {
        ctAND1 = cc.EvalBinGate(NAND, ct1, ct2);
    }
    std::cout <<cyc_times<< " times of  "<<method<<"\t"<<set<<"\tgate bootstrapping:\t" << float(clock()-start)*1000/CLOCKS_PER_SEC<<"ms" << std::endl;
    // cc.Decrypt(sk, ctAND1, &result);
}


int main() {
    uint32_t cyc_times = 100;
    test(cyc_times,XZNEW,N128G);
    test(cyc_times,XZNEW,N128G_2);
    test(cyc_times,XZNEW,N128G_3);
    test(cyc_times,XZNEW,N128G_4);
    // test(cyc_times,XZDDF,P128G_2);
    // // // test(cyc_times,XZDDF,STD128_LMKCDEY);
    // // // test(cyc_times,XZNEW,STD128_LMKCDEY);
    // test(cyc_times,LMKCDEY,STD128_LMKCDEY);
    // test(cyc_times,LMKCDEY,STD128_LMKCDEY_New);
    // test(cyc_times,AP,STD128_AP);
    // test(cyc_times,GINX,STD128);

    return 0;
}
