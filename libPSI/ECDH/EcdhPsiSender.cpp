#include "EcdhPsiSender.h"
#include "cryptoTools/Crypto/Curve.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Common/Timer.h"


namespace osuCrypto
{

    EcdhPsiSender::EcdhPsiSender()
    {
    }


    EcdhPsiSender::~EcdhPsiSender()
    {
    }

    void EcdhPsiSender::sendInput_k283(span<block> inputs, span<Channel> chls)
    {
		//stepSize = inputs.size();

		u64 maskSizeByte = (40 + log2(inputs.size()*mTheirInputSize) + 7) / 8;
		std::cout << "s maskSizeByte = " << maskSizeByte <<"\n";


        std::vector<PRNG> thrdPrng(chls.size());
        for (u64 i = 0; i < thrdPrng.size(); i++)
            thrdPrng[i].SetSeed(mPrng.get<block>());

        auto RsSeed = mPrng.get<block>();

		std::vector<std::vector<u8>> sendBuff2(chls.size());


		myStepSize = mN / numStep;
		theirStepSize = mTheirInputSize / numStep;

        auto routine = [&](u64 t)
        {
            u64 inputStartIdx = inputs.size() * t / chls.size();
            u64 inputEndIdx = inputs.size() * (t + 1) / chls.size();
            u64 subsetInputSize = inputEndIdx - inputStartIdx;

			u64 theirInputStartIdx = mTheirInputSize * t / chls.size();
			u64 theirInputEndIdx = mTheirInputSize * (t + 1) / chls.size();
			u64 theirSubsetInputSize = theirInputEndIdx - theirInputStartIdx;

			
            auto& chl = chls[t];
            auto& prng = thrdPrng[t];

			EllipticCurve curve(myEccpParams, thrdPrng[t].get<block>());
			RandomOracle inputHasher(sizeof(block));
			EccNumber a(curve);
			EccPoint xa(curve), point(curve), yb(curve), yba(curve);
			a.randomize(RsSeed);

			sendBuff2[t].resize(maskSizeByte * theirSubsetInputSize);
			auto sendIter2 = sendBuff2[t].data();

			for (u64 i = inputStartIdx; i < inputEndIdx; i += myStepSize)
			{
				auto curStepSize = std::min(myStepSize, inputEndIdx - i);

				std::vector<u8> sendBuff(xa.sizeBytes() * curStepSize);
				auto sendIter = sendBuff.data();

				//send H(x)^a
				for (u64 k = 0; k < curStepSize; ++k)
				{
					block seed;
					inputHasher.Reset();
					inputHasher.Update(inputs[i + k]);
					inputHasher.Final(seed);

					point.randomize(seed);
					//std::cout << "sp  " << point << "  " << toBlock(hashOut) << std::endl;

					xa = (point * a);
#ifdef PRINT
					if (i == 0)
						std::cout << "xa[" << i << "] " << xa << std::endl;
#endif	
					xa.toBytes(sendIter);
					sendIter += xa.sizeBytes();
				}
				chl.asyncSend(std::move(sendBuff));	//send H(x)^a
			}


			for (u64 i = theirInputStartIdx; i < theirInputEndIdx; i += theirStepSize)
			{
				auto curStepSize = std::min(theirStepSize, theirInputEndIdx - i);


				std::vector<u8> recvBuff(yb.sizeBytes() * curStepSize);
				std::vector<u8> temp(yba.sizeBytes());

				//recv H(y)^b
				chl.recv(recvBuff);

				if (recvBuff.size() != curStepSize * yb.sizeBytes())
				{
					std::cout << "error @ " << (LOCATION) << std::endl;
					throw std::runtime_error(LOCATION);
				}
				auto recvIter = recvBuff.data();


				//send H(y)^b^a
				for (u64 k = 0; k < curStepSize; ++k)
				{
					yb.fromBytes(recvIter); recvIter += yb.sizeBytes();
					yba = yb*a;


					yba.toBytes(temp.data());
					RandomOracle ro(sizeof(block));
					ro.Update(temp.data(), temp.size());
					block blk;
					ro.Final(blk);
					memcpy(sendIter2, &blk, maskSizeByte);
#ifdef PRINT
					if (i == 0)
					{
						std::cout << "yba[" << i << "] " << yba << std::endl;
						std::cout << "temp[" << i << "] " << toBlock(temp) << std::endl;
						std::cout << "sendIter2[" << i << "] " << toBlock(sendIter2) << std::endl;
					}
#endif
					sendIter2 += maskSizeByte;
				}
				//std::cout << "dones send H(y)^b^a" << std::endl;
			}
      
			//chl.asyncSend(std::move(sendBuff2[t]));


			};

		gTimer.setTimePoint("s before sending mask done ");

        std::vector<std::thread> thrds(chls.size());
        for (u64 i = 0; i < u64(chls.size()); ++i)
        {
            thrds[i] = std::thread([=] {
                routine(i);
            });
        }


        for (auto& thrd : thrds)
            thrd.join();

		for (u64 i = 0; i < u64(chls.size()); ++i)
		{
			thrds[i] = std::thread([=] {
				auto& chl = chls[i];
				chl.asyncSend(std::move(sendBuff2[i]));
			});
		}


		for (auto& thrd : thrds)
			thrd.join();

		//std::cout << "S done" << std::endl;

    }

	void EcdhPsiSender::sendInput_Curve25519(span<block> inputs, span<Channel> chls)
	{
		std::cout << "curveParam = Curve25519\n";

		auto curveParam = Curve25519;


		u64 maskSizeByte = (40 + log2(inputs.size() * mTheirInputSize) + 7) / 8;

		std::vector<PRNG> thrdPrng(chls.size());
		for (u64 i = 0; i < thrdPrng.size(); i++)
			thrdPrng[i].SetSeed(mPrng.get<block>());

		auto RsSeed = mPrng.get<block>();

		std::vector<std::vector<u8>> sendBuff2(chls.size());



		myStepSize = mN / numStep;
		theirStepSize = mTheirInputSize / numStep;


		auto routine = [&](u64 t)
		{
			u64 inputStartIdx = inputs.size() * t / chls.size();
			u64 inputEndIdx = inputs.size() * (t + 1) / chls.size();
			u64 subsetInputSize = inputEndIdx - inputStartIdx;

			u64 theirInputStartIdx = mTheirInputSize * t / chls.size();
			u64 theirInputEndIdx = mTheirInputSize * (t + 1) / chls.size();
			u64 theirSubsetInputSize = theirInputEndIdx - theirInputStartIdx;


			auto& chl = chls[t];
			auto& prng = thrdPrng[t];

			EllipticCurve curve(myEccpParams, thrdPrng[t].get<block>());
			RandomOracle inputHasher(sizeof(block));
			EccNumber a(curve);
			EccPoint xa(curve), point(curve), yb(curve), yba(curve);
			a.randomize(RsSeed);

			sendBuff2[t].resize(maskSizeByte * subsetInputSize);
			auto sendIter2 = sendBuff2[t].data();

			for (u64 i = inputStartIdx; i < inputEndIdx; i += myStepSize)
			{
				auto curStepSize = std::min(myStepSize, inputEndIdx - i);

				std::vector<u8> sendBuff(xa.sizeBytes() * curStepSize);
				auto sendIter = sendBuff.data();

				//send H(x)^a
				for (u64 k = 0; k < curStepSize; ++k)
				{
					block seed;
					inputHasher.Reset();
					inputHasher.Update(inputs[i + k]);
					inputHasher.Final(seed);

					point.randomize(seed);
					//std::cout << "sp  " << point << "  " << toBlock(hashOut) << std::endl;

					xa = (point * a);
#ifdef PRINT
					if (i == 0)
						std::cout << "xa[" << i << "] " << xa << std::endl;
#endif	
					xa.toBytes(sendIter);
					sendIter += xa.sizeBytes();
				}
				chl.asyncSend(std::move(sendBuff));	//send H(x)^a
			}


			for (u64 i = theirInputStartIdx; i < theirInputEndIdx; i += theirStepSize)
			{
				auto curStepSize = std::min(theirStepSize, theirInputEndIdx - i);



				std::vector<u8> recvBuff(yb.sizeBytes() * curStepSize);
				std::vector<u8> temp(yba.sizeBytes());

				//recv H(y)^b
				chl.recv(recvBuff);

				if (recvBuff.size() != curStepSize * yb.sizeBytes())
				{
					std::cout << "error @ " << (LOCATION) << std::endl;
					throw std::runtime_error(LOCATION);
				}
				auto recvIter = recvBuff.data();


				//send H(y)^b^a
				for (u64 k = 0; k < curStepSize; ++k)
				{
					yb.fromBytes(recvIter); recvIter += yb.sizeBytes();
					yba = yb * a;


					yba.toBytes(temp.data());
					RandomOracle ro(sizeof(block));
					ro.Update(temp.data(), temp.size());
					block blk;
					ro.Final(blk);
					memcpy(sendIter2, &blk, maskSizeByte);
#ifdef PRINT
					if (i == 0)
					{
						std::cout << "yba[" << i << "] " << yba << std::endl;
						std::cout << "temp[" << i << "] " << toBlock(temp) << std::endl;
						std::cout << "sendIter2[" << i << "] " << toBlock(sendIter2) << std::endl;
					}
#endif
					sendIter2 += maskSizeByte;
				}
				//std::cout << "dones send H(y)^b^a" << std::endl;
			}

			//chl.asyncSend(std::move(sendBuff2[t]));


		};

		gTimer.setTimePoint("s before sending mask done ");

		std::vector<std::thread> thrds(chls.size());
		for (u64 i = 0; i < u64(chls.size()); ++i)
		{
			thrds[i] = std::thread([=] {
				routine(i);
			});
		}


		for (auto& thrd : thrds)
			thrd.join();

		for (u64 i = 0; i < u64(chls.size()); ++i)
		{
			thrds[i] = std::thread([=] {
				auto& chl = chls[i];
				chl.asyncSend(std::move(sendBuff2[i]));
			});
		}


		for (auto& thrd : thrds)
			thrd.join();

		//std::cout << "S done" << std::endl;
		gTimer.setTimePoint("s Psi done");

	}

	void EcdhPsiSender::sendInput_Ristretto(span<block> inputs, span<Channel> chls)
	{
		std::cout << "curveParam = Ristretto\n";

		auto curveParam = Curve25519;

		u64 maskSizeByte = (40 + log2(inputs.size()* mTheirInputSize) + 7) / 8;

		std::vector<PRNG> thrdPrng(chls.size());
		for (u64 i = 0; i < thrdPrng.size(); i++)
			thrdPrng[i].SetSeed(mPrng.get<block>());

		auto RsSeed = mPrng.get<block>();

		std::vector<std::vector<u8>> sendBuff2(chls.size());



		myStepSize = mN / numStep;
		theirStepSize = mTheirInputSize / numStep;


		auto routine = [&](u64 t)
		{
			u64 inputStartIdx = inputs.size() * t / chls.size();
			u64 inputEndIdx = inputs.size() * (t + 1) / chls.size();
			u64 subsetInputSize = inputEndIdx - inputStartIdx;

			u64 theirInputStartIdx = mTheirInputSize * t / chls.size();
			u64 theirInputEndIdx = mTheirInputSize * (t + 1) / chls.size();
			u64 theirSubsetInputSize = theirInputEndIdx - theirInputStartIdx;

			auto& chl = chls[t];
			auto& prng = thrdPrng[t];

			RandomOracle inputHasher(sizeof(block));
			unsigned char* a = new unsigned char[crypto_core_ristretto255_SCALARBYTES];
			crypto_core_ristretto255_scalar_random(a);

			unsigned char* xa = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char* yb = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char* point = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char* point_hash = new unsigned char[crypto_core_ristretto255_HASHBYTES];
			unsigned char* yba = new unsigned char[crypto_core_ristretto255_BYTES];


			sendBuff2[t].resize(maskSizeByte * subsetInputSize);
			auto sendIter2 = sendBuff2[t].data();

			for (u64 i = inputStartIdx; i < inputEndIdx; i += myStepSize)
			{
				auto curStepSize = std::min(myStepSize, inputEndIdx - i);

				std::vector<u8> sendBuff(crypto_core_ristretto255_BYTES * curStepSize);
				auto sendIter = sendBuff.data();

				//send H(x)^a
				for (u64 k = 0; k < curStepSize; ++k)
				{
					block seed;
					inputHasher.Reset();
					inputHasher.Update(inputs[i + k]);
					inputHasher.Final(seed);

					ristretto255_hash_from_blk(point_hash, seed);
					crypto_core_ristretto255_from_hash(point, point_hash);

					//std::cout << "sp  " << point << "  " << toBlock(hashOut) << std::endl;

					//compute H(xi)^a
					if (crypto_scalarmult_ristretto255(xa, a, point) != 0) {

						std::cout << "s crypto_scalarmult_ristretto255(xa, a, poin) != 0\n";
						throw std::runtime_error("rt error at " LOCATION);
					}

#ifdef PRINT
					if (i == 0)
						std::cout << "xa[" << i << "] " << xa << std::endl;
#endif	
					memcpy(sendBuff.data() + k * crypto_core_ristretto255_BYTES, xa, crypto_core_ristretto255_BYTES);
				}
				chl.asyncSend(std::move(sendBuff));	//send H(x)^a
			}


			for (u64 i = theirInputStartIdx; i < theirInputEndIdx; i += theirStepSize)
			{
				auto curStepSize = std::min(theirStepSize, theirInputEndIdx - i);



				std::vector<u8> recvBuff(crypto_core_ristretto255_BYTES * curStepSize);
				std::vector<u8> temp(crypto_core_ristretto255_BYTES);

				//recv H(y)^b
				chl.recv(recvBuff);

				if (recvBuff.size() != curStepSize * crypto_core_ristretto255_BYTES)
				{
					std::cout << "error @ " << (LOCATION) << std::endl;
					throw std::runtime_error(LOCATION);
				}
				auto recvIter = recvBuff.data();


				//send H(y)^b^a
				for (u64 k = 0; k < curStepSize; ++k)
				{
					memcpy(yb, recvIter, crypto_core_ristretto255_BYTES);
					recvIter += crypto_core_ristretto255_BYTES;

					//compute H(xi)^a^b
					if (crypto_scalarmult_ristretto255(yba, a, yb) != 0) {

						std::cout << "s crypto_scalarmult_ristretto255(yba, a, yb) != 0\n";
						throw std::runtime_error("rt error at " LOCATION);
					}



					RandomOracle ro(sizeof(block));
					ro.Update(yba, crypto_core_ristretto255_BYTES);
					block blk;
					ro.Final(blk);
					memcpy(sendIter2, &blk, maskSizeByte);
#ifdef PRINT
					if (i == 0)
					{
						std::cout << "yba[" << i << "] " << yba << std::endl;
						std::cout << "temp[" << i << "] " << toBlock(temp) << std::endl;
						std::cout << "sendIter2[" << i << "] " << toBlock(sendIter2) << std::endl;
					}
#endif
					sendIter2 += maskSizeByte;
				}
				//std::cout << "dones send H(y)^b^a" << std::endl;
			}

			//chl.asyncSend(std::move(sendBuff2[t]));


		};

		gTimer.setTimePoint("s before sending mask done ");

		std::vector<std::thread> thrds(chls.size());
		for (u64 i = 0; i < u64(chls.size()); ++i)
		{
			thrds[i] = std::thread([=] {
				routine(i);
				});
		}


		for (auto& thrd : thrds)
			thrd.join();

		for (u64 i = 0; i < u64(chls.size()); ++i)
		{
			thrds[i] = std::thread([=] {
				auto& chl = chls[i];
				chl.asyncSend(std::move(sendBuff2[i]));
				});
		}


		for (auto& thrd : thrds)
			thrd.join();

		//std::cout << "S done" << std::endl;
		gTimer.setTimePoint("s Psi done");

	}

	void EcdhPsiSender::sendInput(u64 n, u64 theirInputSize, u64 secParam, block seed,span<block> inputs, span<Channel> chls, int curveType)
	{
		for (u64 i = 0; i < chls.size(); ++i)
		{
			u8 dummy[1];
			chls[i].recv(dummy, 1);
			chls[i].asyncSend(dummy, 1);
			chls[i].resetStats();
		}
		gTimer.reset();

		mTheirInputSize = theirInputSize;
		mN = inputs.size();
		mSecParam = secParam;
		mPrng.SetSeed(seed);


		if (curveType == 0)
			sendInput_k283(inputs, chls);
		else if (curveType == 1)
			sendInput_Curve25519(inputs, chls);
		else 
			sendInput_Ristretto(inputs, chls);
	}

	

}