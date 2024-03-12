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
  Example for the FHEW scheme using the XZDDF bootstrapping
 */

#include "binfhecontext.h"

using namespace lbcrypto;
using namespace std;
int main() {
    // Sample Program: Step 1: Set CryptoContexts
    auto cc = BinFHEContext();

    cc.GenerateBinFHEContext(N128G_2, XZNEW);

    // Sample Program: Step 2: Key Generation
    auto sk = cc.KeyGen();
    // auto m_sk = sk->GetElement();
    // cout<<m_sk[0]<<endl; //2^14-1

    int m0=0;
    int m1=0;
    LWEPlaintext result;

    // Generate the bootstrapping keys (refresh and switching keys)
    std::cout << "Generating the bootstrapping keys..." << std::endl;
    cc.NBTKeyGen(sk);
    std::cout << "Completed the key generation." << std::endl;


    // Sample Program: Step 3: Encryption
    auto ct1 = cc.Encrypt(sk, m0);
    auto ct2 = cc.Encrypt(sk, m1);
    LWECiphertext ctNAND;

    // Sample Program: Step 4: Evaluation
    std::cout << "Start  the  gate bootstrapping " << endl;
    
    const double clocks2seconds = 1. / CLOCKS_PER_SEC;//  1/100万
    clock_t bs_begin, bs_end;

    clock_t start = clock();
    bs_begin = clock();
    ctNAND = cc.EvalBinGate(NAND, ct1, ct2);
    bs_end = clock();
    std::cout << "Bootstrapping in " << float(clock()-start)*1000/CLOCKS_PER_SEC<<"ms" << std::endl;
    cout <<  (bs_end - bs_begin)*clocks2seconds << " [sec/bootstrapping]" << endl;



    cc.Decrypt(sk, ctNAND, &result);//这里先对sk模切换到q了

    std::cout << "Result of encrypted computation of ( "<<m0<<" NAND "<<m1<<" ) = " << result << std::endl;

    return 0;
}
