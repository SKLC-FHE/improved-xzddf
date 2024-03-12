
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

    int m0=5;
    int m1=4;
    LWEPlaintext result1,result2;

    // Generate the bootstrapping keys (refresh and switching keys)
    // std::cout << "Generating the bootstrapping keys..." << std::endl;
    // cc.NBTKeyGen(sk);
    // std::cout << "Completed the key generation." << std::endl;


    // Sample Program: Step 3: Encryption
    auto ct1 = cc.Encrypt(sk, m0,BOOTSTRAPPED,10);
    auto ct2 = cc.Encrypt(sk, m1);

    // auto ct3 = ct1+ct2;
    
    cc.Decrypt(sk, ct1, &result1,10);//这里先对sk模切换到q了
    cc.Decrypt(sk, ct2, &result2);//这里先对sk模切换到q了

    std::cout << "Result of encrypted "<<m0<<" = " << result1 << std::endl;
    std::cout << "Result of encrypted "<<m1<<" = " << result2 << std::endl;

    return 0;
}
