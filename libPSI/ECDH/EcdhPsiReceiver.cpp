#include "EcdhPsiReceiver.h"
#include "cryptoTools/Crypto/Curve.h"
#include "cryptoTools/Crypto/sha1.h"
#include "cryptoTools/Common/Log.h"
#include <cryptoTools/Crypto/RandomOracle.h>
#include <unordered_map>
#include "cryptoTools/Common/Timer.h"


namespace osuCrypto
{

    EcdhPsiReceiver::EcdhPsiReceiver()
    {
    }


    EcdhPsiReceiver::~EcdhPsiReceiver()
    {
    }

    void EcdhPsiReceiver::sendInput_k283(
        span<block> inputs,
        span<Channel> chls)
    {
		//stepSize = inputs.size();
		gTimer.setTimePoint("hdpsi starts");
        std::vector<PRNG> thrdPrng(chls.size());
        for (u64 i = 0; i < thrdPrng.size(); i++)
            thrdPrng[i].SetSeed(mPrng.get<block>());

        std::mutex mtx;

		std::vector<block> thrdPrngBlock(chls.size());
		std::vector<std::vector<u64>> localIntersections(chls.size() - 1);

		u64 maskSizeByte = (40 + log2(inputs.size()*mTheirInputSize) + 7) / 8;

        auto RcSeed = mPrng.get<block>();

		std::unordered_map<u32, block> mapXab;
		mapXab.reserve(inputs.size());

        const bool isMultiThreaded = chls.size() > 1;

		myStepSize = mN / numStep;
		theirStepSize = mTheirInputSize / numStep;
		
		
		Timer timer;

		auto start = timer.setTimePoint("start");


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
			u8 hashOut[SHA1::HashSize];

			EllipticCurve curve(myEccpParams, thrdPrng[t].get<block>());

			SHA1 inputHasher;
			EccNumber b(curve);
			EccPoint yb(curve), yba(curve), point(curve), xa(curve), xab(curve);
			b.randomize(RcSeed);
			
			 for (u64 i = inputStartIdx; i < inputEndIdx; i += myStepSize)
			 {
				 auto curStepSize = std::min(myStepSize, inputEndIdx - i);

				 std::vector<u8> sendBuff(yb.sizeBytes() * curStepSize);
				 auto sendIter = sendBuff.data();
				 //	std::cout << "send H(y)^b" << std::endl;

				 //gTimer.setTimePoint("r online H(x)^b start ");

				 //send H(y)^b
				 for (u64 k = 0; k < curStepSize; ++k)
				 {

					 inputHasher.Reset();
					 inputHasher.Update(inputs[i+k]);
					 inputHasher.Final(hashOut);

					 point.randomize(toBlock(hashOut));
					 //std::cout << "sp  " << point << "  " << toBlock(hashOut) << std::endl;

					 yb = (point * b);

#ifdef PRINT
					 if (i == 0)
						 std::cout << "yb[" << i << "] " << yb << std::endl;
#endif
					 yb.toBytes(sendIter);
					 sendIter += yb.sizeBytes();
				 }
				//' gTimer.setTimePoint("r online H(x)^b done ");


				 chl.asyncSend(std::move(sendBuff));

			 }

			/* auto ybTime = timer.setTimePoint("yb");
			 auto ybTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(ybTime - start).count();*/


			 for (u64 i = theirInputStartIdx; i < theirInputEndIdx; i += theirStepSize)
			 {
				 auto curStepSize = std::min(theirStepSize, theirInputEndIdx - i);


			 //recv H(x)^a
			 //std::cout << "recv H(x)^a" << std::endl;
				 
				 std::vector<u8>temp(xab.sizeBytes());

				 //compute H(x)^a^b as map
				 //std::cout << "compute H(x)^a^b " << std::endl;

				 std::vector<u8> recvBuff(xa.sizeBytes() * curStepSize);

				 chl.recv(recvBuff);
				 if (recvBuff.size() != curStepSize * xa.sizeBytes())
				 {
					 std::cout << recvBuff.size() << " vs " << curStepSize * xa.sizeBytes() << std::endl;

					 std::cout << "error @ " << (LOCATION) << std::endl;
					 throw std::runtime_error(LOCATION);
				 }
				 auto recvIter = recvBuff.data();

				 for (u64 k = 0; k < curStepSize; ++k)
				 {
					 xa.fromBytes(recvIter); recvIter += xa.sizeBytes();
					 xab = xa*b;

					 xab.toBytes(temp.data());

					 RandomOracle ro(sizeof(block));
					 ro.Update(temp.data(), temp.size());
					 block blk;
					 ro.Final(blk);
					 auto idx = *(u32*)&blk;

#ifdef PRINT
					 if (i == 0)
					 {
						 std::cout << "xab[" << i << "] " << xab << std::endl;
						 std::cout << "idx[" << i << "] " << toBlock(idx) << std::endl;
					 }
#endif // PRINT


					 if (isMultiThreaded)
					 {
						 std::lock_guard<std::mutex> lock(mtx);
						 mapXab.insert({ idx, blk });
					 }
					 else
					 {
						 mapXab.insert({ idx, blk });
					 }
				 }
			 }
		
		/*	 auto xabTime = timer.setTimePoint("xab");
			 auto xabTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(xabTime - ybTime).count();*/
		//	 std::cout << "compute H(x)^ab:  " << xabTimeMs << "\n";


};

		
        std::vector<std::thread> thrds(chls.size());
        for (u64 i = 0; i < u64(chls.size()); ++i)
        {
            thrds[i] = std::thread([=] {
                routine(i);
            });
        }


		for (auto& thrd : thrds)
			thrd.join();

#if 1
		auto routine2 = [&](u64 t)
		{
			u64 inputStartIdx = inputs.size() * t / chls.size();
			u64 inputEndIdx = inputs.size() * (t + 1) / chls.size();
			u64 subsetInputSize = inputEndIdx - inputStartIdx;


			auto& chl = chls[t];


			std::vector<u8> recvBuff2(maskSizeByte * subsetInputSize);

			//recv H(y)^b^a
			chl.recv(recvBuff2);
			if (recvBuff2.size() != subsetInputSize * maskSizeByte)
			{
				std::cout << "error @ " << (LOCATION) << std::endl;
				throw std::runtime_error(LOCATION);
			}
			auto recvIter2 = recvBuff2.data();

			for (u64 i = inputStartIdx; i < inputEndIdx; i++)
			{

				auto& idx_yba = *(u32*)(recvIter2);

#ifdef PRINT
				if (i == 0)
					std::cout << "idx_yba[" << i << "] " << toBlock(idx_yba) << std::endl;
#endif // PRINT

				auto id = mapXab.find(idx_yba);
				if (id != mapXab.end()) {

					//std::cout << "id->first[" << i << "] " << toBlock(id->first) << std::endl;

					if (memcmp(recvIter2, &id->second, maskSizeByte) == 0)
					{
						//std::cout << "intersection item----------" << i << std::endl;
						if (t == 0)
							mIntersection.emplace_back(i);
						else
							localIntersections[t - 1].emplace_back(i);
					}
				}
				recvIter2 += maskSizeByte;

			}
			//std::cout << "done" << std::endl;

		};


		for (u64 i = 0; i < u64(chls.size()); ++i)
		{
			thrds[i] = std::thread([=] {
				routine2(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();

		u64 extraSize = 0;

		for (u64 i = 0; i < thrds.size()-1; ++i)
			extraSize += localIntersections[i].size();

		mIntersection.reserve(mIntersection.size() + extraSize);
		for (u64 i = 0; i < thrds.size()-1; ++i)
		{
			mIntersection.insert(mIntersection.end(), localIntersections[i].begin(), localIntersections[i].end());
		}
#endif


    }

	void EcdhPsiReceiver::sendInput_Curve25519(
		span<block> inputs,
		span<Channel> chls)
	{
		std::vector<PRNG> thrdPrng(chls.size());
		for (u64 i = 0; i < thrdPrng.size(); i++)
			thrdPrng[i].SetSeed(mPrng.get<block>());

		std::mutex mtx;

		std::vector<block> thrdPrngBlock(chls.size());
		std::vector<std::vector<u64>> localIntersections(chls.size() - 1);

		u64 maskSizeByte = (40 +  log2(inputs.size() * mTheirInputSize) + 7) / 8;

		auto curveParam = Curve25519;
		auto RcSeed = mPrng.get<block>();

		std::unordered_map<u32, block> mapXab;
		mapXab.reserve(inputs.size());

		const bool isMultiThreaded = chls.size() > 1;


		myStepSize = mN / numStep;
		theirStepSize = mTheirInputSize / numStep;

		Timer timer;

		auto start = timer.setTimePoint("start");


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
			u8 hashOut[SHA1::HashSize];

			EllipticCurve curve(myEccpParams, thrdPrng[t].get<block>());

			SHA1 inputHasher;
			EccNumber b(curve);
			EccPoint yb(curve), yba(curve), point(curve), xa(curve), xab(curve);
			b.randomize(RcSeed);

			for (u64 i = inputStartIdx; i < inputEndIdx; i += myStepSize)
			{
				auto curStepSize = std::min(myStepSize, inputEndIdx - i);

				std::vector<u8> sendBuff(yb.sizeBytes() * curStepSize);
				auto sendIter = sendBuff.data();
				//	std::cout << "send H(y)^b" << std::endl;

				//send H(y)^b
				for (u64 k = 0; k < curStepSize; ++k)
				{

					inputHasher.Reset();
					inputHasher.Update(inputs[i + k]);
					inputHasher.Final(hashOut);

					point.randomize(toBlock(hashOut));
					//std::cout << "sp  " << point << "  " << toBlock(hashOut) << std::endl;

					yb = (point * b);

#ifdef PRINT
					if (i == 0)
						std::cout << "yb[" << i << "] " << yb << std::endl;
#endif
					yb.toBytes(sendIter);
					sendIter += yb.sizeBytes();
				}
				chl.asyncSend(std::move(sendBuff));

			}

			/* auto ybTime = timer.setTimePoint("yb");
			auto ybTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(ybTime - start).count();*/
			// std::cout << "compute H(y)^b:  " << ybTimeMs << "\n";


			for (u64 i = theirInputStartIdx; i < theirInputEndIdx; i += theirStepSize)
			{
				auto curStepSize = std::min(theirStepSize, theirInputEndIdx - i);


				//recv H(x)^a
				//std::cout << "recv H(x)^a" << std::endl;

				std::vector<u8>temp(xab.sizeBytes());

				//compute H(x)^a^b as map
				//std::cout << "compute H(x)^a^b " << std::endl;

				std::vector<u8> recvBuff(xa.sizeBytes() * curStepSize);

				chl.recv(recvBuff);
				if (recvBuff.size() != curStepSize * xa.sizeBytes())
				{
					std::cout << recvBuff.size() << " vs " << curStepSize * xa.sizeBytes() << std::endl;

					std::cout << "error @ " << (LOCATION) << std::endl;
					throw std::runtime_error(LOCATION);
				}
				auto recvIter = recvBuff.data();

				for (u64 k = 0; k < curStepSize; ++k)
				{
					xa.fromBytes(recvIter); recvIter += xa.sizeBytes();
					xab = xa * b;

					xab.toBytes(temp.data());

					RandomOracle ro(sizeof(block));
					ro.Update(temp.data(), temp.size());
					block blk;
					ro.Final(blk);
					auto idx = *(u32*)&blk;

#ifdef PRINT
					if (i == 0)
					{
						std::cout << "xab[" << i << "] " << xab << std::endl;
						std::cout << "idx[" << i << "] " << toBlock(idx) << std::endl;
					}
#endif // PRINT


					if (isMultiThreaded)
					{
						std::lock_guard<std::mutex> lock(mtx);
						mapXab.insert({ idx, blk });
					}
					else
					{
						mapXab.insert({ idx, blk });
					}
				}
			}

			/*	 auto xabTime = timer.setTimePoint("xab");
			auto xabTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(xabTime - ybTime).count();*/
			//	 std::cout << "compute H(x)^ab:  " << xabTimeMs << "\n";


		};


		std::vector<std::thread> thrds(chls.size());
		for (u64 i = 0; i < u64(chls.size()); ++i)
		{
			thrds[i] = std::thread([=] {
				routine(i);
			});
		}


		for (auto& thrd : thrds)
			thrd.join();

		std::cout << "r exp done\n";
		gTimer.setTimePoint("r exp done");

#if 1
		//#####################Receive Mask #####################

		auto routine2 = [&](u64 t)
		{
			u64 inputStartIdx = inputs.size() * t / chls.size();
			u64 inputEndIdx = inputs.size() * (t + 1) / chls.size();
			u64 subsetInputSize = inputEndIdx - inputStartIdx;


			auto& chl = chls[t];


			std::vector<u8> recvBuff2(maskSizeByte * subsetInputSize);

			//recv H(y)^b^a
			chl.recv(recvBuff2);
			if (recvBuff2.size() != subsetInputSize * maskSizeByte)
			{
				std::cout << "error @ " << (LOCATION) << std::endl;
				throw std::runtime_error(LOCATION);
			}
			auto recvIter2 = recvBuff2.data();

			for (u64 i = inputStartIdx; i < inputEndIdx; i++)
			{

				auto& idx_yba = *(u32*)(recvIter2);

#ifdef PRINT
				if (i == 0)
					std::cout << "idx_yba[" << i << "] " << toBlock(idx_yba) << std::endl;
#endif // PRINT

				auto id = mapXab.find(idx_yba);
				if (id != mapXab.end()) {

					//std::cout << "id->first[" << i << "] " << toBlock(id->first) << std::endl;

					if (memcmp(recvIter2, &id->second, maskSizeByte) == 0)
					{
						//std::cout << "intersection item----------" << i << std::endl;
						if (t == 0)
							mIntersection.emplace_back(i);
						else
							localIntersections[t - 1].emplace_back(i);
					}
				}
				recvIter2 += maskSizeByte;

			}
			//std::cout << "done" << std::endl;

		};


		for (u64 i = 0; i < u64(chls.size()); ++i)
		{
			thrds[i] = std::thread([=] {
				routine2(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();

		u64 extraSize = 0;

		for (u64 i = 0; i < thrds.size() - 1; ++i)
			extraSize += localIntersections[i].size();

		mIntersection.reserve(mIntersection.size() + extraSize);
		for (u64 i = 0; i < thrds.size() - 1; ++i)
		{
			mIntersection.insert(mIntersection.end(), localIntersections[i].begin(), localIntersections[i].end());
		}
#endif


	}

	void EcdhPsiReceiver::sendInput_Ristretto(
		span<block> inputs,
		span<Channel> chls)
	{
		std::vector<PRNG> thrdPrng(chls.size());
		for (u64 i = 0; i < thrdPrng.size(); i++)
			thrdPrng[i].SetSeed(mPrng.get<block>());

		std::mutex mtx;

		std::vector<block> thrdPrngBlock(chls.size());
		std::vector<std::vector<u64>> localIntersections(chls.size() - 1);

		u64 maskSizeByte = (40 + log2(inputs.size()*mTheirInputSize) + 7) / 8;

		auto curveParam = Curve25519;
		auto RcSeed = mPrng.get<block>();

		std::unordered_map<u32, block> mapXab;
		mapXab.reserve(inputs.size());

		const bool isMultiThreaded = chls.size() > 1;



		myStepSize = mN / numStep;
		theirStepSize = mTheirInputSize / numStep;
		Timer timer;

		auto start = timer.setTimePoint("start");

		gTimer.setTimePoint("r start");


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
			u8 hashOut[SHA1::HashSize];


			SHA1 inputHasher;
			unsigned char* b= new unsigned char[crypto_core_ristretto255_SCALARBYTES];
			crypto_core_ristretto255_scalar_random(b);

			unsigned char* yb = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char* yba = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char* point = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char* point_hash = new unsigned char[crypto_core_ristretto255_HASHBYTES];
			unsigned char* xa = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char* xab = new unsigned char[crypto_core_ristretto255_BYTES];


			for (u64 i = inputStartIdx; i < inputEndIdx; i += myStepSize)
			{
				auto curStepSize = std::min(myStepSize, inputEndIdx - i);

				std::vector<u8> sendBuff(crypto_core_ristretto255_BYTES * curStepSize);
				//	std::cout << "send H(y)^b" << std::endl;

				//send H(y)^b
				for (u64 k = 0; k < curStepSize; ++k)
				{

					inputHasher.Reset();
					inputHasher.Update(inputs[i + k]);
					inputHasher.Final(hashOut);
					ristretto255_hash_from_blk(point_hash, toBlock(hashOut));
					crypto_core_ristretto255_from_hash(point, point_hash);

					//std::cout << "sp  " << point << "  " << toBlock(hashOut) << std::endl;

					//compute H(xi)^b
					if (crypto_scalarmult_ristretto255(yb, b, point) != 0) {

						std::cout << "crypto_scalarmult_ristretto255(yb, b, point) != 0\n";
						throw std::runtime_error("rt error at " LOCATION);
					}

#ifdef PRINT
					if (i == 0)
						std::cout << "yb[" << i << "] " << yb << std::endl;
#endif
					memcpy(sendBuff.data() + k * crypto_core_ristretto255_BYTES, yb, crypto_core_ristretto255_BYTES);

				}
				chl.asyncSend(std::move(sendBuff));

			}

			/* auto ybTime = timer.setTimePoint("yb");
			auto ybTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(ybTime - start).count();*/
			// std::cout << "compute H(y)^b:  " << ybTimeMs << "\n";


			//for (u64 i = inputStartIdx; i < inputEndIdx; i += stepSize)
			for (u64 i = theirInputStartIdx; i < theirInputEndIdx; i += theirStepSize)
			{
				auto curStepSize = std::min(theirStepSize, theirInputEndIdx - i);


				//recv H(x)^a
				//std::cout << "recv H(x)^a" << std::endl;

				std::vector<u8>temp(crypto_core_ristretto255_BYTES);

				//compute H(x)^a^b as map
				//std::cout << "compute H(x)^a^b " << std::endl;

				std::vector<u8> recvBuff(crypto_core_ristretto255_BYTES * curStepSize);

				chl.recv(recvBuff);
				if (recvBuff.size() != curStepSize * crypto_core_ristretto255_BYTES)
				{
					std::cout << recvBuff.size() << " vs " << curStepSize * crypto_core_ristretto255_BYTES << std::endl;

					std::cout << "error @ " << (LOCATION) << std::endl;
					throw std::runtime_error(LOCATION);
				}
				auto recvIter = recvBuff.data();

				for (u64 k = 0; k < curStepSize; ++k)
				{
					memcpy(xa, recvIter, crypto_core_ristretto255_BYTES);
					recvIter += crypto_core_ristretto255_BYTES;
					
					//compute H(xi)^a^b
					if (crypto_scalarmult_ristretto255(xab, b, xa) != 0) {

						std::cout << "r crypto_scalarmult_ristretto255(xab, b, xa) != 0\n";
						throw std::runtime_error("rt error at " LOCATION);
					}


					RandomOracle ro(sizeof(block));
					ro.Update(xab, crypto_core_ristretto255_BYTES);
					block blk;
					ro.Final(blk);
					auto idx = *(u32*)&blk;

#ifdef PRINT
					if (i == 0)
					{
						std::cout << "xab[" << i << "] " << xab << std::endl;
						std::cout << "idx[" << i << "] " << toBlock(idx) << std::endl;
					}
#endif // PRINT


					if (isMultiThreaded)
					{
						std::lock_guard<std::mutex> lock(mtx);
						mapXab.insert({ idx, blk });
					}
					else
					{
						mapXab.insert({ idx, blk });
					}
				}
			}

			/*	 auto xabTime = timer.setTimePoint("xab");
			auto xabTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(xabTime - ybTime).count();*/
			//	 std::cout << "compute H(x)^ab:  " << xabTimeMs << "\n";


		};


		std::vector<std::thread> thrds(chls.size());
		for (u64 i = 0; i < u64(chls.size()); ++i)
		{
			thrds[i] = std::thread([=] {
				routine(i);
				});
		}


		for (auto& thrd : thrds)
			thrd.join();

		std::cout << "r exp done\n";
		gTimer.setTimePoint("r exp done");

#if 1
		//#####################Receive Mask #####################

		auto routine2 = [&](u64 t)
		{
			u64 inputStartIdx = inputs.size() * t / chls.size();
			u64 inputEndIdx = inputs.size() * (t + 1) / chls.size();
			u64 subsetInputSize = inputEndIdx - inputStartIdx;

			u64 theirInputStartIdx = mTheirInputSize * t / chls.size();
			u64 theirInputEndIdx = mTheirInputSize * (t + 1) / chls.size();
			u64 theirSubsetInputSize = theirInputEndIdx - theirInputStartIdx;



			auto& chl = chls[t];


			std::vector<u8> recvBuff2(maskSizeByte * theirSubsetInputSize);

			//recv H(y)^b^a
			chl.recv(recvBuff2);
			if (recvBuff2.size() != theirSubsetInputSize * maskSizeByte)
			{
				std::cout << "error @ " << (LOCATION) << std::endl;
				throw std::runtime_error(LOCATION);
			}
			auto recvIter2 = recvBuff2.data();

			for (u64 i = theirInputStartIdx; i < theirInputEndIdx; i++)
			{

				auto& idx_yba = *(u32*)(recvIter2);

#ifdef PRINT
				if (i == 0)
					std::cout << "idx_yba[" << i << "] " << toBlock(idx_yba) << std::endl;
#endif // PRINT

				auto id = mapXab.find(idx_yba);
				if (id != mapXab.end()) {

					//std::cout << "id->first[" << i << "] " << toBlock(id->first) << std::endl;

					if (memcmp(recvIter2, &id->second, maskSizeByte) == 0)
					{
						//std::cout << "intersection item----------" << i << std::endl;
						if (t == 0)
							mIntersection.emplace_back(i);
						else
							localIntersections[t - 1].emplace_back(i);
					}
				}
				recvIter2 += maskSizeByte;

			}
			//std::cout << "done" << std::endl;

		};


		for (u64 i = 0; i < u64(chls.size()); ++i)
		{
			thrds[i] = std::thread([=] {
				routine2(i);
				});
		}

		for (auto& thrd : thrds)
			thrd.join();

		u64 extraSize = 0;

		for (u64 i = 0; i < thrds.size() - 1; ++i)
			extraSize += localIntersections[i].size();

		mIntersection.reserve(mIntersection.size() + extraSize);
		for (u64 i = 0; i < thrds.size() - 1; ++i)
		{
			mIntersection.insert(mIntersection.end(), localIntersections[i].begin(), localIntersections[i].end());
		}
#endif
		gTimer.setTimePoint("r computing intersection done");


	}


	void EcdhPsiReceiver::sendInput(u64 n, u64 theirInputSize, u64 secParam, block seed,
		span<block> inputs,
		span<Channel> chls, int curveType)
	{
		for (u64 i = 0; i < chls.size(); ++i)
		{
			u8 dummy[1];
			chls[i].asyncSend(dummy, 1);
			chls[i].recv(dummy, 1);
			chls[i].resetStats();
		}
		gTimer.reset();

		mN = n;
		mTheirInputSize = theirInputSize;
		mSecParam = secParam;
		mPrng.SetSeed(seed);
		mIntersection.clear();

		if (curveType == 0)
			sendInput_k283(inputs, chls);
		else if (curveType == 1)
			sendInput_Curve25519(inputs, chls);
		else
			sendInput_Ristretto(inputs, chls);


	}
}

