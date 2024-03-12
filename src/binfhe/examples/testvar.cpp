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

void test(uint32_t cyc_times,BINFHE_METHOD method,BINFHE_PARAMSET set)
{
  std::cout<<method<<"\t"<<set<< std::endl;
  auto cc = BinFHEContext();
  int right_times=0;
  LWEPlaintext result;
  cc.GenerateBinFHEContext(set, method);
  auto sk = cc.KeyGen();
  int m0=0;
  int m1=0;
  if(method == XZDDF || method == XZNEW)
  {
      cc.NBTKeyGen(sk);
  }else{
      cc.BTKeyGen(sk);
  }

  for(uint32_t i=0;i<cyc_times;i++){
    auto ct1 = cc.Encrypt(sk, m0);
    auto ct2 = cc.Encrypt(sk, m1);
    LWECiphertext ctNAND;
    ctNAND = cc.EvalBinGate(NAND, ct1, ct2);
    cc.Decrypt(sk, ctNAND, &result);
    if(result == (1- m0*m1))
    {
        //cout<<"result = "<<result<<endl;
        right_times++;
        //cout<<right_times<<" right"<<endl;
    }else{
        cout<<i<<"###### false ##########"<<endl;
    }
    if(i%20 == 19)
    {
      cout<<endl;
    }
  }
  std::cout << "\nright_times = "<<right_times << std::endl;
  std::cout << "Accuracy = "<<double(right_times)/double(cyc_times)*100 << "%"<< std::endl;
  std::cout << "Result of encrypted computation of ( "<<m0<<" NAND "<<m1<<" ) = " << result << std::endl;
}



int main() {
    int cyc_times=200;
    // test(cyc_times,XZNEW,N128G_2);
    // test(cyc_times,XZDDF,P128G_2);
    // test(cyc_times,LMKCDEY,STD128_LMKCDEY);
    test(cyc_times,LMKCDEY,STD128_LMKCDEY_New);
    // test(cyc_times,AP,STD128_AP);
    // test(cyc_times,GINX,STD128);
    return 0;
}
