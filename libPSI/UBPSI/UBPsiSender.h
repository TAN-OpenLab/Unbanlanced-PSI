#pragma once

#include "cryptoTools/Common/Defines.h"

#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "../PsiDefines.h"

using namespace osuCrypto;    //ning

namespace Tanlab
{
    class UBPsiSender
    {
    public:
        UBPsiSender();
        ~UBPsiSender();

		u64 myStepSize;
		u64 theirStepSize;

        u64 mN, mSecParam;
        PRNG mPrng;
		u64 mTheirInputSize;


		void sendInput_k283(span<block> inputs, span<Channel> chl);
        void sendInput_Curve25519(span<block> inputs, span<Channel> chl);
        void sendInput_Ristretto(span<block> inputs, span<Channel> chl);
		void sendInput(u64 n,u64 theirInputSize, u64 secParam, block seed, span<block> inputs,  span<Channel> chl, int curveType);
        //void sendInput(std::vector<block>& inputs, std::vector<Channel*>& chl);
    };

}
