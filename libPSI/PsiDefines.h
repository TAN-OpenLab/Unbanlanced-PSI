#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/Curve.h>
#define NTL_Threads
#define  DEBUG
#include "PsiDefines.h"
#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/ZZ.h>
#include <sstream>
#include <string>

using namespace NTL;
#define NTL_Threads_ON
#ifdef _MSC_VER
//#define PSI_PRINT
//#define PRINT
#endif
#include <cryptoTools/Common/Timer.h>
#include <set>
#include<algorithm>
#include<string>
#include<cmath>
#include <numeric>
#include <vector>
#include <iostream>


//#define DEBUG_MINI_PSI_RIS
//#define MINI_PSI_Subsetsum



namespace osuCrypto
{
	
	static const ZZ mPrime128 = to_ZZ("340282366920938463463374607431768211507");
	static const ZZ mPrime160 = to_ZZ("1461501637330902918203684832716283019655932542983");  //nextprime(2^160)
	static const ZZ mPrime164 = to_ZZ("23384026197294446691258957323460528314494920687733");  //nextprime(2^164)
	static const ZZ mPrime168 = to_ZZ("374144419156711147060143317175368453031918731001943");  //nextprime(2^168)
	static const ZZ mPrime172 = to_ZZ("5986310706507378352962293074805895248510699696029801");  //nextprime(2^172)
	static const ZZ mPrime176 = to_ZZ("95780971304118053647396689196894323976171195136475563");  //nextprime(2^176)
	static const ZZ mPrime180 = to_ZZ("1532495540865888858358347027150309183618739122183602191");  //nextprime(2^180)
	static const ZZ mPrime184 = to_ZZ("24519928653854221733733552434404946937899825954937634843");  //nextprime(2^184)
	static const ZZ mPrime188 = to_ZZ("392318858461667547739736838950479151006397215279002157113");  //nextprime(2^188)
	static const ZZ mPrime264 = to_ZZ("29642774844752946028434172162224104410437116074403984394101141506025761187823791");  //nextprime(2^264)
	static const ZZ mPrime255_19 = to_ZZ("57896044618658097711785492504343953926634992332820282019728792003956564819949");  //nextprime(2^264)
	static const ZZ mPrime256 = to_ZZ("115792089237316195423570985008687907853269984665640564039457584007913129640233");  //nextprime(2^264)
	static const ZZ mPrime224 = to_ZZ("26959946667150639794667015087019630673637144422540572481103610249951");  //nextprime(2^264)


	//static const Ecc2mParams myEccpParams = k283;
	static const EccpParams myEccpParams = Curve25519;
	static const ZZ myPrime= mPrime256;


	static const u8 mMiniPolySlices(2); //2*128 
	static const u64 stepSize(1 << 20);
	static const u64 numStep(1 <<0);
	static const u64 stepSizeMaskSent(1<<5);
//	static const u8 numSuperBlocks(4); //wide of T (or field size) 
	static const u8 numSuperBlocks(3); //wide of T (or field size)  =3 for HD-PSI


	static const u8 first2Slices(2); //2*128 + (436-2*128)
	static const u64 recvNumDummies(1);
	static const u64 recvMaxBinSize(40);
	static std::vector<block> mOneBlocks(128); 
	static const u64 primeLong(129);
	static const u64 fieldSize(440); //TODO 4*sizeof(block)

	static const u64 bIdxForDebug(3), iIdxForDebug(0), hIdxForDebug(0);

		
	inline void getExpParams(u64 setSize, u64& numSeeds, u64& numChosen)
	{

		if (setSize <= (1 << 8))
		{
			numSeeds = 1<<7;
			numChosen = 23;
		}
		else if (setSize <= (1 << 10))
		{
			numSeeds = 1<<7;
			numChosen = 24;
		}
		else if (setSize <= (1 << 12))
		{
			numSeeds = 1<<7;
			numChosen = 25;
		}
		else if (setSize <= (1 << 14))
		{
			numSeeds = 1<<8;
			numChosen = 20;
		}
		else if (setSize <= (1 << 16))
		{
			numSeeds = 1<<9;
			numChosen = 17;
		}
		else if (setSize <= (1 << 18))
		{
			numSeeds = 1<<10;
			numChosen = 15;
		}
		else if (setSize <= (1 << 20))
		{
			numSeeds = 1<<13;
			numChosen = 11;
		}
		else if (setSize <= (1 << 22))
		{
			numSeeds = 1<<14;
			numChosen = 11;
		}
		else if (setSize <= (1 << 24))
		{
			numSeeds = 1<<15;
			numChosen = 10;
		}
	}



	inline void getBestExpParams(u64 setSize, u64& numSeeds, u64& numChosen, u64& boundCoeff)
	{

		if (setSize <= (1 << 5))
		{
			numSeeds = 1<<5;
			numChosen = 19;
			boundCoeff = 1 << 4;

		}
		else if (setSize <= (1 << 10))
		{
			numSeeds = 1 << 7;
			numChosen = 24;
			boundCoeff = 1 << 1;
		}
		else if (setSize <= (1 << 12))
		{
			numSeeds = 1 << 7;
			numChosen = 25;
			boundCoeff = 1 << 1;
		}
		else if (setSize <= (1 << 14))
		{
			numSeeds = 1 << 8;
			numChosen = 20;
			boundCoeff = 1 << 1;
		}
		else if (setSize <= (1 << 16))
		{
			numSeeds = 1 << 9;
			numChosen = 17;
			boundCoeff = 1 << 1;
		}
		else if (setSize <= (1 << 18))
		{
			numSeeds = 1 << 10;
			numChosen = 15;
			boundCoeff = 1 << 1;
		}
		else if (setSize <= (1 << 20))
		{
			numSeeds = 1 << 13;
			numChosen = 11;
			boundCoeff = 1 << 1;
		}
		else if (setSize <= (1 << 22))
		{
			numSeeds = 1 << 14;
			numChosen = 11;
			boundCoeff = 1 << 1;
		}
		else if (setSize <= (1 << 24))
		{
			numSeeds = 1 << 15;
			numChosen = 10;
			boundCoeff = 1 << 1;
		}
	}

	struct RecExpParams
	{
		u32 numSeeds;
		u32 numChosen;
		u32 boundCoeff;
		u64 numNewSeeds;
	};

	inline void getBestH1RecurrExpParams(u64 setSize, std::vector<RecExpParams>& mSeq)
	{
		if (setSize <= (1 << 8))
		{
			mSeq.resize(1);
			mSeq[0] = { 1 << 7, 23, 1 << 1,setSize }; 
		}
		else if (setSize <= (1 << 10))
		{
			mSeq.resize(2);
			mSeq[0] = { 1 << 7, 23, 1 << 1,setSize };
			mSeq[1] = { 1 << 8, 19, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 12))
		{
			mSeq.resize(2);
			mSeq[0] = { 1 << 7, 24, 1 << 1,setSize };
			mSeq[1] = { 1 << 9, 16, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 14))
		{
			mSeq.resize(3);
			mSeq[0] = { 1 << 7, 25, 1 << 1,setSize };
			mSeq[1] = { 1 << 9, 16, 1 << 1,setSize };
			mSeq[2] = { 1 << 11, 13, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 16))
		{
			mSeq.resize(4);
			mSeq[0] = { 1 << 7, 24, 1 << 1,setSize };
			mSeq[1] = { 1 << 8, 19, 1 << 1,setSize };
			mSeq[2] = { 1 << 10, 15, 1 << 1,setSize };
			mSeq[3] = { 1 << 13, 11, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 18))
		{
			mSeq.resize(4);
			mSeq[0] = { 1 << 7, 25, 1 << 1,setSize };
			mSeq[1] = { 1 << 9, 16, 1 << 1,setSize };
			mSeq[2] = { 1 << 11, 13, 1 << 1,setSize };
			mSeq[3] = { 1 << 16, 9, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 20))
		{
			mSeq.resize(4);
			mSeq[0] = { 1 << 7, 26, 1 << 1,setSize };
			mSeq[1] = { 1 << 10, 15, 1 << 1,setSize };
			mSeq[2] = { 1 << 13, 11, 1 << 1,setSize };
			mSeq[3] = { 1 << 16, 9, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 22))
		{
			mSeq.resize(5);
			mSeq[0] = { 1 << 7, 26, 1 << 1,setSize };
			mSeq[1] = { 1 << 10, 15, 1 << 1,setSize };
			mSeq[2] = { 1 << 13, 11, 1 << 1,setSize };
			mSeq[3] = { 1 << 16, 9, 1 << 1,setSize };
			mSeq[4] = { 1 << 19, 8, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 24))
		{
			mSeq.resize(5);
			mSeq[0] = { 1 << 7, 26, 1 << 1,setSize };
			mSeq[1] = { 1 << 10, 15, 1 << 1,setSize };
			mSeq[2] = { 1 << 13, 11, 1 << 1,setSize };
			mSeq[3] = { 1 << 16, 9, 1 << 1,setSize };
			mSeq[4] = { 1 << 19, 8, 1 << 1,setSize };
		}
	}


	inline void getBestRecurrExpParams(u64 setSize, std::vector<RecExpParams>& mSeq)
	{
		if (setSize <= (1 << 8))
		{
			mSeq.resize(3);
			//mSeq[0] = { 1 << 1, 1, 1 << 104,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[0] = { 1 << 1, 1, 1 << 10,setSize }; //implement 1<<128, instead of 1 << 104
			mSeq[1] = { 1 << 6, 25, 1 << 2,setSize };
			mSeq[2] = { 1 << 7, 24, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 10))
		{
			mSeq.resize(4);
			//mSeq[0] = { 1 << 1, 1, 1 << 104,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[0] = { 1 << 1, 1, 1 << 10,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[1] = { 1 << 6, 25, 1 << 2,setSize };
			mSeq[2] = { 1 << 7, 24, 1 << 1,setSize };
			mSeq[3] = { 1 << 8, 19, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 12))
		{
			mSeq.resize(5);
			//mSeq[0] = { 1 << 1, 1, 1 << 106,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[0] = { 1 << 1, 1, 1 << 10,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[1] = { 1 << 6, 25, 1 << 2,setSize };
			mSeq[2] = { 1 << 7, 24, 1 << 1,setSize };
			mSeq[3] = { 1 << 8, 19, 1 << 1,setSize };
			mSeq[4] = { 1 << 10, 14, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 14))
		{
			mSeq.resize(5);
			//mSeq[0] = { 1 << 1, 1, 1 << 106,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[0] = { 1 << 1, 1, 1 << 10,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[1] = { 1 << 6, 25, 1 << 2,setSize };
			mSeq[2] = { 1 << 7, 25, 1 << 1,setSize };
			mSeq[3] = { 1 << 8, 20, 1 << 1,setSize };
			mSeq[4] = { 1 << 11, 13, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 16))
		{
			mSeq.resize(5);
			//mSeq[0] = { 1 << 1, 1, 1 << 106,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[0] = { 1 << 1, 1, 1 << 10,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[1] = { 1 << 6, 25, 1 << 2,setSize };
			mSeq[2] = { 1 << 7, 26, 1 << 1,setSize };
			mSeq[3] = { 1 << 10, 15, 1 << 1,setSize };
			mSeq[4] = { 1 << 13, 11, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 18))
		{
			mSeq.resize(6);
		//	mSeq[0] = { 1 << 1, 1, 1 << 106,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[0] = { 1 << 1, 1, 1 << 10,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[1] = { 1 << 6, 25, 1 << 2,setSize };
			mSeq[2] = { 1 << 7, 25, 1 << 1,setSize };
			mSeq[3] = { 1 << 9, 17, 1 << 1,setSize };
			mSeq[4] = { 1 << 12, 12, 1 << 1,setSize };
			mSeq[5] = { 1 << 15, 10, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 20))
		{
			mSeq.resize(6);
			//mSeq[0] = { 1 << 1, 1, 1 << 106,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[0] = { 1 << 1, 1, 1 << 10,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[1] = { 1 << 6, 25, 1 << 2,setSize };
			mSeq[2] = { 1 << 7, 26, 1 << 1,setSize };
			mSeq[3] = { 1 << 10, 15, 1 << 1,setSize };
			mSeq[4] = { 1 << 13, 11, 1 << 1,setSize };
			mSeq[5] = { 1 << 16, 9, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 22))
		{
			mSeq.resize(7);
			//mSeq[0] = { 1 << 1, 1, 1 << 106,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[0] = { 1 << 1, 1, 1 << 10,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[1] = { 1 << 6, 25, 1 << 2,setSize };
			mSeq[2] = { 1 << 7, 26, 1 << 1,setSize };
			mSeq[3] = { 1 << 10, 15, 1 << 1,setSize };
			mSeq[4] = { 1 << 13, 11, 1 << 1,setSize };
			mSeq[5] = { 1 << 16, 9, 1 << 1,setSize };
			mSeq[6] = { 1 << 19, 8, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 24))
		{
			mSeq.resize(7);
			//mSeq[0] = { 1 << 1, 1, 1 << 106,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[0] = { 1 << 1, 1, 1 << 10,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[1] = { 1 << 6, 25, 1 << 2,setSize };
			mSeq[2] = { 1 << 7, 26, 1 << 1,setSize };
			mSeq[3] = { 1 << 10, 15, 1 << 1,setSize };
			mSeq[4] = { 1 << 13, 11, 1 << 1,setSize };
			mSeq[5] = { 1 << 16, 9, 1 << 1,setSize };
			mSeq[6] = { 1 << 19, 8, 1 << 1,setSize };
		}
	}


	inline const char* tostr(int x)
	{
			std::stringstream str;
			str << x;
			return str.str().c_str();
	}


	inline u64 getFieldSizeInBits(u64 setSize)
	{

		if (setSize <= (1 << 10))
			return 416;
		else if (setSize <= (1 << 12))
			return 420;
		else if (setSize <= (1 << 14))
			return 424;
		else if (setSize <= (1 << 16))
			return 428;
		else if (setSize <= (1 << 18))
			return 432;
		else if (setSize <= (1 << 20))
			return 436;
		else if (setSize <= (1 << 22))
			return 436;
		else if (setSize <= (1 << 24))
			return 444;

		return 444;
	}


	inline ZZ getPrimeLastSlice(u64 fieldSize)
	{
		u64 lastBit = fieldSize - 2 * 128;
		if (lastBit==160)
			return mPrime160;
		else if (lastBit == 164)
			return mPrime164;
		else if (lastBit == 168)
			return mPrime168;
		else if (lastBit == 172)
			return mPrime172;
		else if (lastBit == 176)
			return mPrime176;
		else if (lastBit == 180)
			return mPrime180;
		else if (lastBit == 184)
			return mPrime184;
		else if (lastBit == 188)
			return mPrime188;
		
		return mPrime188;
	}


	
	struct item
	{
		u64 mHashIdx;
		u64 mIdx;
	};


	static __m128i mm_bitshift_right(__m128i x, unsigned count)
	{
		__m128i carry = _mm_slli_si128(x, 8);   // old compilers only have the confusingly named _mm_slli_si128 synonym
		if (count >= 64)
			return _mm_slli_epi64(carry, count - 64);  // the non-carry part is all zero, so return early
													   // else
		return _mm_or_si128(_mm_slli_epi64(x, count), _mm_srli_epi64(carry, 64 - count));

	}


	static __m128i mm_bitshift_left(__m128i x, unsigned count)
	{
		__m128i carry = _mm_srli_si128(x, 8);   // old compilers only have the confusingly named _mm_slli_si128 synonym
		if (count >= 64)
			return _mm_srli_epi64(carry, count - 64);  // the non-carry part is all zero, so return early

		return _mm_or_si128(_mm_srli_epi64(x, count), _mm_slli_epi64(carry, 64 - count));
	}

	inline void fillOneBlock(std::vector<block>& blks)
	{
		for (int i = 0; i < blks.size(); ++i)
			blks[i] = mm_bitshift_right(OneBlock, i);
	}

	static void prfOtRows(std::vector<block>& inputs,  std::vector<std::array<block, numSuperBlocks>>& outputs, std::vector<AES>& arrAes)
	{
		std::vector<block> ciphers(inputs.size());
		outputs.resize(inputs.size());

		for (int j = 0; j < numSuperBlocks - 1; ++j) //1st 3 blocks
			for (int i = 0; i < 128; ++i) //for each column
			{
				arrAes[j * 128 + i].ecbEncBlocks(inputs.data(), inputs.size(), ciphers.data()); //do many aes at the same time for efficeincy

				for (u64 idx = 0; idx < inputs.size(); idx++)
				{
					ciphers[idx] = ciphers[idx]&mOneBlocks[i];
					outputs[idx][j] = outputs[idx][j] ^ ciphers[idx];
				}
			}

		
		int j = numSuperBlocks - 1;
		for (int i = j * 128; i < arrAes.size(); ++i)
		{
				arrAes[i].ecbEncBlocks(inputs.data(), inputs.size(), ciphers.data()); //do many aes at the same time for efficeincy
				for (u64 idx = 0; idx < inputs.size(); idx++)
				{
					ciphers[idx] = ciphers[idx] & mOneBlocks[i-j*128];
					outputs[idx][j] = outputs[idx][j] ^ ciphers[idx];
				}
			
		}

	}

	static void prfOtRow(block& input, std::array<block, numSuperBlocks>& output, std::vector<AES> arrAes, u64 hIdx=0)
	{
		block cipher;

		for (int j = 0; j < numSuperBlocks - 1; ++j) //1st 3 blocks
			for (int i = 0; i < 128; ++i) //for each column
			{
				if(hIdx==1)
					arrAes[j * 128 + i].ecbEncBlock(input^OneBlock, cipher);
				else
					arrAes[j * 128 + i].ecbEncBlock(input, cipher);

				cipher= cipher& mOneBlocks[i];
				output[j] = output[j] ^ cipher;
			}


		int j = numSuperBlocks - 1;
		for (int i = 0; i < 128; ++i)
		{
			if (j * 128 + i < arrAes.size()) {

				if (hIdx == 1)
					arrAes[j * 128 + i].ecbEncBlock(input^OneBlock, cipher);
				else
					arrAes[j * 128 + i].ecbEncBlock(input, cipher);
				
				cipher = cipher& mOneBlocks[i];
				output[j] = output[j] ^ cipher;
			}
			else {
				break;
			}
		}

		//std::cout << IoStream::lock;
		//std::cout << "\t output " << output[0] << "\n";
		//std::cout << IoStream::unlock;

	}

	inline void printArrU8(u8* Z, int size) {

		for (int i = 0; i < size; i++)
			std::cout << static_cast<unsigned int>(Z[i]);

		std::cout << std::endl;
	}


	inline int ropoField2Group(EllipticCurve& mCurve, u8* buff, EccPoint& point)
	{
		bool success;
		int iter = 0;

		big varX = mirvar(&mCurve.getMiracl(), 0);
		bytes_to_big(&mCurve.getMiracl(), point.sizeBytes() - 1, (char*)buff + 1, varX);

		do
		{
			incr(&mCurve.getMiracl(), varX, 1, varX); // pi(x)=x+1
			//num.reduce1();

			if (mCurve.isPrimeField())
				success = epoint_set(&mCurve.getMiracl(), varX, varX, buff[0], point.mVal);
			else
				success = epoint2_set(&mCurve.getMiracl(), varX, varX, buff[0], point.mVal);

			if (point_at_infinity(point.mVal))
				success = false;

			iter++;
			//std::cout << iter++ << "\t-\t F2G success= " << success << "\n";
		} while (success == false);

		return iter;
	}

	inline int ropoGroup2Field(EllipticCurve& mCurve, const EccPoint& point, std::vector<u8*>& buffs)
	{
		u8* buff = new u8[point.sizeBytes()];
		EccPoint  new_point(mCurve);
		bool success;
		int iter = 0;

		//convert point to big num
		// buff[0] holds the y bit and varX holds the x data.
		big varX = mirvar(&mCurve.getMiracl(), 0);
		if (mCurve.isPrimeField())
			buff[0] = epoint_get(&mCurve.getMiracl(), point.mVal, varX, varX) & 1;
		else
			buff[0] = epoint2_get(&mCurve.getMiracl(), point.mVal, varX, varX) & 1;

		do
		{
			decr(&mCurve.getMiracl(), varX, 1, varX); //pi^-1
			//num.reduce1();

			if (mCurve.isPrimeField())
				success = epoint_set(&mCurve.getMiracl(), varX, varX, buff[0], new_point.mVal);
			else
				success = epoint2_set(&mCurve.getMiracl(), varX, varX, buff[0], new_point.mVal);

			if (point_at_infinity(new_point.mVal))
				success = false;

			if (success == false) //add this u8* to buffs
			{
				big_to_bytes(&mCurve.getMiracl(), point.sizeBytes() - 1, varX, (char*)buff + 1, true);
				buffs.push_back(buff);
			}

			iter++;
			//std::cout << iter++ << "\t-\t G2F success= " << success << "\n";
		} while (success == false);

		return iter;
	}

#define SODIUM_STATIC
#include <sodium.h>
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_core_ristretto255.h>
//#include <sodium\private\ed25519_ref10.h>

	//===========copy from sodium
#pragma region copy_from_sodium

	typedef int32_t ropo_fe25519[10];

	typedef struct {
		ropo_fe25519 X;
		ropo_fe25519 Y;
		ropo_fe25519 Z;
		ropo_fe25519 T;
	} ropo_ge25519_p3;



	/* 37095705934669439343138083508754565189542113879843219016388785533085940283555 */
	static const ropo_fe25519 d = {
		-10913610, 13857413, -15372611, 6949391,   114729, -8787816, -6275908, -3247719, -18696448, -12055116
	};

	/* sqrt(-1) */
	static const ropo_fe25519 sqrtm1 = {
		-32595792, -7943725,  9377950,  3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482
	};

	static inline void
		ropo_fe25519_0(ropo_fe25519 h)
	{
		memset(&h[0], 0, 10 * sizeof h[0]);
	}

	static inline uint64_t
		load_3_psi(const unsigned char* in)
	{
		uint64_t result;

		result = (uint64_t)in[0];
		result |= ((uint64_t)in[1]) << 8;
		result |= ((uint64_t)in[2]) << 16;

		return result;
	}

	static inline uint64_t
		load_4_psi(const unsigned char* in)
	{
		uint64_t result;

		result = (uint64_t)in[0];
		result |= ((uint64_t)in[1]) << 8;
		result |= ((uint64_t)in[2]) << 16;
		result |= ((uint64_t)in[3]) << 24;

		return result;
	}

	inline void
		ropo_fe25519_frombytes(ropo_fe25519 h, const unsigned char* s)
	{
		int64_t h0 = load_4_psi(s);
		int64_t h1 = load_3_psi(s + 4) << 6;
		int64_t h2 = load_3_psi(s + 7) << 5;
		int64_t h3 = load_3_psi(s + 10) << 3;
		int64_t h4 = load_3_psi(s + 13) << 2;
		int64_t h5 = load_4_psi(s + 16);
		int64_t h6 = load_3_psi(s + 20) << 7;
		int64_t h7 = load_3_psi(s + 23) << 5;
		int64_t h8 = load_3_psi(s + 26) << 4;
		int64_t h9 = (load_3_psi(s + 29) & 8388607) << 2;

		int64_t carry0;
		int64_t carry1;
		int64_t carry2;
		int64_t carry3;
		int64_t carry4;
		int64_t carry5;
		int64_t carry6;
		int64_t carry7;
		int64_t carry8;
		int64_t carry9;

		carry9 = (h9 + (int64_t)(1L << 24)) >> 25;
		h0 += carry9 * 19;
		h9 -= carry9 * ((uint64_t)1L << 25);
		carry1 = (h1 + (int64_t)(1L << 24)) >> 25;
		h2 += carry1;
		h1 -= carry1 * ((uint64_t)1L << 25);
		carry3 = (h3 + (int64_t)(1L << 24)) >> 25;
		h4 += carry3;
		h3 -= carry3 * ((uint64_t)1L << 25);
		carry5 = (h5 + (int64_t)(1L << 24)) >> 25;
		h6 += carry5;
		h5 -= carry5 * ((uint64_t)1L << 25);
		carry7 = (h7 + (int64_t)(1L << 24)) >> 25;
		h8 += carry7;
		h7 -= carry7 * ((uint64_t)1L << 25);

		carry0 = (h0 + (int64_t)(1L << 25)) >> 26;
		h1 += carry0;
		h0 -= carry0 * ((uint64_t)1L << 26);
		carry2 = (h2 + (int64_t)(1L << 25)) >> 26;
		h3 += carry2;
		h2 -= carry2 * ((uint64_t)1L << 26);
		carry4 = (h4 + (int64_t)(1L << 25)) >> 26;
		h5 += carry4;
		h4 -= carry4 * ((uint64_t)1L << 26);
		carry6 = (h6 + (int64_t)(1L << 25)) >> 26;
		h7 += carry6;
		h6 -= carry6 * ((uint64_t)1L << 26);
		carry8 = (h8 + (int64_t)(1L << 25)) >> 26;
		h9 += carry8;
		h8 -= carry8 * ((uint64_t)1L << 26);

		h[0] = (int32_t)h0;
		h[1] = (int32_t)h1;
		h[2] = (int32_t)h2;
		h[3] = (int32_t)h3;
		h[4] = (int32_t)h4;
		h[5] = (int32_t)h5;
		h[6] = (int32_t)h6;
		h[7] = (int32_t)h7;
		h[8] = (int32_t)h8;
		h[9] = (int32_t)h9;
	}


	inline static void
		ropo_fe25519_reduce(ropo_fe25519 h, const ropo_fe25519 f)
	{
		int32_t h0 = f[0];
		int32_t h1 = f[1];
		int32_t h2 = f[2];
		int32_t h3 = f[3];
		int32_t h4 = f[4];
		int32_t h5 = f[5];
		int32_t h6 = f[6];
		int32_t h7 = f[7];
		int32_t h8 = f[8];
		int32_t h9 = f[9];

		int32_t q;
		int32_t carry0, carry1, carry2, carry3, carry4, carry5, carry6, carry7, carry8, carry9;

		q = (19 * h9 + ((uint32_t)1L << 24)) >> 25;
		q = (h0 + q) >> 26;
		q = (h1 + q) >> 25;
		q = (h2 + q) >> 26;
		q = (h3 + q) >> 25;
		q = (h4 + q) >> 26;
		q = (h5 + q) >> 25;
		q = (h6 + q) >> 26;
		q = (h7 + q) >> 25;
		q = (h8 + q) >> 26;
		q = (h9 + q) >> 25;

		/* Goal: Output h-(2^255-19)q, which is between 0 and 2^255-20. */
		h0 += 19 * q;
		/* Goal: Output h-2^255 q, which is between 0 and 2^255-20. */

		carry0 = h0 >> 26;
		h1 += carry0;
		h0 -= carry0 * ((uint32_t)1L << 26);
		carry1 = h1 >> 25;
		h2 += carry1;
		h1 -= carry1 * ((uint32_t)1L << 25);
		carry2 = h2 >> 26;
		h3 += carry2;
		h2 -= carry2 * ((uint32_t)1L << 26);
		carry3 = h3 >> 25;
		h4 += carry3;
		h3 -= carry3 * ((uint32_t)1L << 25);
		carry4 = h4 >> 26;
		h5 += carry4;
		h4 -= carry4 * ((uint32_t)1L << 26);
		carry5 = h5 >> 25;
		h6 += carry5;
		h5 -= carry5 * ((uint32_t)1L << 25);
		carry6 = h6 >> 26;
		h7 += carry6;
		h6 -= carry6 * ((uint32_t)1L << 26);
		carry7 = h7 >> 25;
		h8 += carry7;
		h7 -= carry7 * ((uint32_t)1L << 25);
		carry8 = h8 >> 26;
		h9 += carry8;
		h8 -= carry8 * ((uint32_t)1L << 26);
		carry9 = h9 >> 25;
		h9 -= carry9 * ((uint32_t)1L << 25);

		h[0] = h0;
		h[1] = h1;
		h[2] = h2;
		h[3] = h3;
		h[4] = h4;
		h[5] = h5;
		h[6] = h6;
		h[7] = h7;
		h[8] = h8;
		h[9] = h9;
	}

	inline void
		ropo_fe25519_tobytes(unsigned char* s, const ropo_fe25519 h)
	{
		ropo_fe25519 t;

		ropo_fe25519_reduce(t, h);
		s[0] = t[0] >> 0;
		s[1] = t[0] >> 8;
		s[2] = t[0] >> 16;
		s[3] = (t[0] >> 24) | (t[1] * ((uint32_t)1 << 2));
		s[4] = t[1] >> 6;
		s[5] = t[1] >> 14;
		s[6] = (t[1] >> 22) | (t[2] * ((uint32_t)1 << 3));
		s[7] = t[2] >> 5;
		s[8] = t[2] >> 13;
		s[9] = (t[2] >> 21) | (t[3] * ((uint32_t)1 << 5));
		s[10] = t[3] >> 3;
		s[11] = t[3] >> 11;
		s[12] = (t[3] >> 19) | (t[4] * ((uint32_t)1 << 6));
		s[13] = t[4] >> 2;
		s[14] = t[4] >> 10;
		s[15] = t[4] >> 18;
		s[16] = t[5] >> 0;
		s[17] = t[5] >> 8;
		s[18] = t[5] >> 16;
		s[19] = (t[5] >> 24) | (t[6] * ((uint32_t)1 << 1));
		s[20] = t[6] >> 7;
		s[21] = t[6] >> 15;
		s[22] = (t[6] >> 23) | (t[7] * ((uint32_t)1 << 3));
		s[23] = t[7] >> 5;
		s[24] = t[7] >> 13;
		s[25] = (t[7] >> 21) | (t[8] * ((uint32_t)1 << 4));
		s[26] = t[8] >> 4;
		s[27] = t[8] >> 12;
		s[28] = (t[8] >> 20) | (t[9] * ((uint32_t)1 << 6));
		s[29] = t[9] >> 2;
		s[30] = t[9] >> 10;
		s[31] = t[9] >> 18;
	}



	/*
	 h = -f
	 *
	 Preconditions:
	 |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
	 *
	 Postconditions:
	 |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
	 */

	static inline void
		ropo_fe25519_neg(ropo_fe25519 h, const ropo_fe25519 f)
	{
		int32_t h0 = -f[0];
		int32_t h1 = -f[1];
		int32_t h2 = -f[2];
		int32_t h3 = -f[3];
		int32_t h4 = -f[4];
		int32_t h5 = -f[5];
		int32_t h6 = -f[6];
		int32_t h7 = -f[7];
		int32_t h8 = -f[8];
		int32_t h9 = -f[9];

		h[0] = h0;
		h[1] = h1;
		h[2] = h2;
		h[3] = h3;
		h[4] = h4;
		h[5] = h5;
		h[6] = h6;
		h[7] = h7;
		h[8] = h8;
		h[9] = h9;
	}

	/*
 h = f
 */

	static inline void
		ropo_fe25519_copy(ropo_fe25519 h, const ropo_fe25519 f)
	{
		int32_t f0 = f[0];
		int32_t f1 = f[1];
		int32_t f2 = f[2];
		int32_t f3 = f[3];
		int32_t f4 = f[4];
		int32_t f5 = f[5];
		int32_t f6 = f[6];
		int32_t f7 = f[7];
		int32_t f8 = f[8];
		int32_t f9 = f[9];

		h[0] = f0;
		h[1] = f1;
		h[2] = f2;
		h[3] = f3;
		h[4] = f4;
		h[5] = f5;
		h[6] = f6;
		h[7] = f7;
		h[8] = f8;
		h[9] = f9;
	}


	/*
	 Replace (f,g) with (g,g) if b == 1;
	 replace (f,g) with (f,g) if b == 0.
	 *
	 Preconditions: b in {0,1}.
	 */

	static inline void
		ropo_fe25519_cmov(ropo_fe25519 f, const ropo_fe25519 g, unsigned int b)
	{
		const uint32_t mask = (uint32_t)(-(int32_t)b);

		int32_t f0 = f[0];
		int32_t f1 = f[1];
		int32_t f2 = f[2];
		int32_t f3 = f[3];
		int32_t f4 = f[4];
		int32_t f5 = f[5];
		int32_t f6 = f[6];
		int32_t f7 = f[7];
		int32_t f8 = f[8];
		int32_t f9 = f[9];

		int32_t x0 = f0 ^ g[0];
		int32_t x1 = f1 ^ g[1];
		int32_t x2 = f2 ^ g[2];
		int32_t x3 = f3 ^ g[3];
		int32_t x4 = f4 ^ g[4];
		int32_t x5 = f5 ^ g[5];
		int32_t x6 = f6 ^ g[6];
		int32_t x7 = f7 ^ g[7];
		int32_t x8 = f8 ^ g[8];
		int32_t x9 = f9 ^ g[9];

		x0 &= mask;
		x1 &= mask;
		x2 &= mask;
		x3 &= mask;
		x4 &= mask;
		x5 &= mask;
		x6 &= mask;
		x7 &= mask;
		x8 &= mask;
		x9 &= mask;

		f[0] = f0 ^ x0;
		f[1] = f1 ^ x1;
		f[2] = f2 ^ x2;
		f[3] = f3 ^ x3;
		f[4] = f4 ^ x4;
		f[5] = f5 ^ x5;
		f[6] = f6 ^ x6;
		f[7] = f7 ^ x7;
		f[8] = f8 ^ x8;
		f[9] = f9 ^ x9;
	}



	static inline void
		ropo_fe25519_mul(ropo_fe25519 h, const ropo_fe25519 f, const ropo_fe25519 g)
	{
		int32_t f0 = f[0];
		int32_t f1 = f[1];
		int32_t f2 = f[2];
		int32_t f3 = f[3];
		int32_t f4 = f[4];
		int32_t f5 = f[5];
		int32_t f6 = f[6];
		int32_t f7 = f[7];
		int32_t f8 = f[8];
		int32_t f9 = f[9];

		int32_t g0 = g[0];
		int32_t g1 = g[1];
		int32_t g2 = g[2];
		int32_t g3 = g[3];
		int32_t g4 = g[4];
		int32_t g5 = g[5];
		int32_t g6 = g[6];
		int32_t g7 = g[7];
		int32_t g8 = g[8];
		int32_t g9 = g[9];

		int32_t g1_19 = 19 * g1; /* 1.959375*2^29 */
		int32_t g2_19 = 19 * g2; /* 1.959375*2^30; still ok */
		int32_t g3_19 = 19 * g3;
		int32_t g4_19 = 19 * g4;
		int32_t g5_19 = 19 * g5;
		int32_t g6_19 = 19 * g6;
		int32_t g7_19 = 19 * g7;
		int32_t g8_19 = 19 * g8;
		int32_t g9_19 = 19 * g9;
		int32_t f1_2 = 2 * f1;
		int32_t f3_2 = 2 * f3;
		int32_t f5_2 = 2 * f5;
		int32_t f7_2 = 2 * f7;
		int32_t f9_2 = 2 * f9;

		int64_t f0g0 = f0 * (int64_t)g0;
		int64_t f0g1 = f0 * (int64_t)g1;
		int64_t f0g2 = f0 * (int64_t)g2;
		int64_t f0g3 = f0 * (int64_t)g3;
		int64_t f0g4 = f0 * (int64_t)g4;
		int64_t f0g5 = f0 * (int64_t)g5;
		int64_t f0g6 = f0 * (int64_t)g6;
		int64_t f0g7 = f0 * (int64_t)g7;
		int64_t f0g8 = f0 * (int64_t)g8;
		int64_t f0g9 = f0 * (int64_t)g9;
		int64_t f1g0 = f1 * (int64_t)g0;
		int64_t f1g1_2 = f1_2 * (int64_t)g1;
		int64_t f1g2 = f1 * (int64_t)g2;
		int64_t f1g3_2 = f1_2 * (int64_t)g3;
		int64_t f1g4 = f1 * (int64_t)g4;
		int64_t f1g5_2 = f1_2 * (int64_t)g5;
		int64_t f1g6 = f1 * (int64_t)g6;
		int64_t f1g7_2 = f1_2 * (int64_t)g7;
		int64_t f1g8 = f1 * (int64_t)g8;
		int64_t f1g9_38 = f1_2 * (int64_t)g9_19;
		int64_t f2g0 = f2 * (int64_t)g0;
		int64_t f2g1 = f2 * (int64_t)g1;
		int64_t f2g2 = f2 * (int64_t)g2;
		int64_t f2g3 = f2 * (int64_t)g3;
		int64_t f2g4 = f2 * (int64_t)g4;
		int64_t f2g5 = f2 * (int64_t)g5;
		int64_t f2g6 = f2 * (int64_t)g6;
		int64_t f2g7 = f2 * (int64_t)g7;
		int64_t f2g8_19 = f2 * (int64_t)g8_19;
		int64_t f2g9_19 = f2 * (int64_t)g9_19;
		int64_t f3g0 = f3 * (int64_t)g0;
		int64_t f3g1_2 = f3_2 * (int64_t)g1;
		int64_t f3g2 = f3 * (int64_t)g2;
		int64_t f3g3_2 = f3_2 * (int64_t)g3;
		int64_t f3g4 = f3 * (int64_t)g4;
		int64_t f3g5_2 = f3_2 * (int64_t)g5;
		int64_t f3g6 = f3 * (int64_t)g6;
		int64_t f3g7_38 = f3_2 * (int64_t)g7_19;
		int64_t f3g8_19 = f3 * (int64_t)g8_19;
		int64_t f3g9_38 = f3_2 * (int64_t)g9_19;
		int64_t f4g0 = f4 * (int64_t)g0;
		int64_t f4g1 = f4 * (int64_t)g1;
		int64_t f4g2 = f4 * (int64_t)g2;
		int64_t f4g3 = f4 * (int64_t)g3;
		int64_t f4g4 = f4 * (int64_t)g4;
		int64_t f4g5 = f4 * (int64_t)g5;
		int64_t f4g6_19 = f4 * (int64_t)g6_19;
		int64_t f4g7_19 = f4 * (int64_t)g7_19;
		int64_t f4g8_19 = f4 * (int64_t)g8_19;
		int64_t f4g9_19 = f4 * (int64_t)g9_19;
		int64_t f5g0 = f5 * (int64_t)g0;
		int64_t f5g1_2 = f5_2 * (int64_t)g1;
		int64_t f5g2 = f5 * (int64_t)g2;
		int64_t f5g3_2 = f5_2 * (int64_t)g3;
		int64_t f5g4 = f5 * (int64_t)g4;
		int64_t f5g5_38 = f5_2 * (int64_t)g5_19;
		int64_t f5g6_19 = f5 * (int64_t)g6_19;
		int64_t f5g7_38 = f5_2 * (int64_t)g7_19;
		int64_t f5g8_19 = f5 * (int64_t)g8_19;
		int64_t f5g9_38 = f5_2 * (int64_t)g9_19;
		int64_t f6g0 = f6 * (int64_t)g0;
		int64_t f6g1 = f6 * (int64_t)g1;
		int64_t f6g2 = f6 * (int64_t)g2;
		int64_t f6g3 = f6 * (int64_t)g3;
		int64_t f6g4_19 = f6 * (int64_t)g4_19;
		int64_t f6g5_19 = f6 * (int64_t)g5_19;
		int64_t f6g6_19 = f6 * (int64_t)g6_19;
		int64_t f6g7_19 = f6 * (int64_t)g7_19;
		int64_t f6g8_19 = f6 * (int64_t)g8_19;
		int64_t f6g9_19 = f6 * (int64_t)g9_19;
		int64_t f7g0 = f7 * (int64_t)g0;
		int64_t f7g1_2 = f7_2 * (int64_t)g1;
		int64_t f7g2 = f7 * (int64_t)g2;
		int64_t f7g3_38 = f7_2 * (int64_t)g3_19;
		int64_t f7g4_19 = f7 * (int64_t)g4_19;
		int64_t f7g5_38 = f7_2 * (int64_t)g5_19;
		int64_t f7g6_19 = f7 * (int64_t)g6_19;
		int64_t f7g7_38 = f7_2 * (int64_t)g7_19;
		int64_t f7g8_19 = f7 * (int64_t)g8_19;
		int64_t f7g9_38 = f7_2 * (int64_t)g9_19;
		int64_t f8g0 = f8 * (int64_t)g0;
		int64_t f8g1 = f8 * (int64_t)g1;
		int64_t f8g2_19 = f8 * (int64_t)g2_19;
		int64_t f8g3_19 = f8 * (int64_t)g3_19;
		int64_t f8g4_19 = f8 * (int64_t)g4_19;
		int64_t f8g5_19 = f8 * (int64_t)g5_19;
		int64_t f8g6_19 = f8 * (int64_t)g6_19;
		int64_t f8g7_19 = f8 * (int64_t)g7_19;
		int64_t f8g8_19 = f8 * (int64_t)g8_19;
		int64_t f8g9_19 = f8 * (int64_t)g9_19;
		int64_t f9g0 = f9 * (int64_t)g0;
		int64_t f9g1_38 = f9_2 * (int64_t)g1_19;
		int64_t f9g2_19 = f9 * (int64_t)g2_19;
		int64_t f9g3_38 = f9_2 * (int64_t)g3_19;
		int64_t f9g4_19 = f9 * (int64_t)g4_19;
		int64_t f9g5_38 = f9_2 * (int64_t)g5_19;
		int64_t f9g6_19 = f9 * (int64_t)g6_19;
		int64_t f9g7_38 = f9_2 * (int64_t)g7_19;
		int64_t f9g8_19 = f9 * (int64_t)g8_19;
		int64_t f9g9_38 = f9_2 * (int64_t)g9_19;

		int64_t h0 = f0g0 + f1g9_38 + f2g8_19 + f3g7_38 + f4g6_19 + f5g5_38 +
			f6g4_19 + f7g3_38 + f8g2_19 + f9g1_38;
		int64_t h1 = f0g1 + f1g0 + f2g9_19 + f3g8_19 + f4g7_19 + f5g6_19 + f6g5_19 +
			f7g4_19 + f8g3_19 + f9g2_19;
		int64_t h2 = f0g2 + f1g1_2 + f2g0 + f3g9_38 + f4g8_19 + f5g7_38 + f6g6_19 +
			f7g5_38 + f8g4_19 + f9g3_38;
		int64_t h3 = f0g3 + f1g2 + f2g1 + f3g0 + f4g9_19 + f5g8_19 + f6g7_19 +
			f7g6_19 + f8g5_19 + f9g4_19;
		int64_t h4 = f0g4 + f1g3_2 + f2g2 + f3g1_2 + f4g0 + f5g9_38 + f6g8_19 +
			f7g7_38 + f8g6_19 + f9g5_38;
		int64_t h5 = f0g5 + f1g4 + f2g3 + f3g2 + f4g1 + f5g0 + f6g9_19 + f7g8_19 +
			f8g7_19 + f9g6_19;
		int64_t h6 = f0g6 + f1g5_2 + f2g4 + f3g3_2 + f4g2 + f5g1_2 + f6g0 +
			f7g9_38 + f8g8_19 + f9g7_38;
		int64_t h7 = f0g7 + f1g6 + f2g5 + f3g4 + f4g3 + f5g2 + f6g1 + f7g0 +
			f8g9_19 + f9g8_19;
		int64_t h8 = f0g8 + f1g7_2 + f2g6 + f3g5_2 + f4g4 + f5g3_2 + f6g2 + f7g1_2 +
			f8g0 + f9g9_38;
		int64_t h9 =
			f0g9 + f1g8 + f2g7 + f3g6 + f4g5 + f5g4 + f6g3 + f7g2 + f8g1 + f9g0;

		int64_t carry0;
		int64_t carry1;
		int64_t carry2;
		int64_t carry3;
		int64_t carry4;
		int64_t carry5;
		int64_t carry6;
		int64_t carry7;
		int64_t carry8;
		int64_t carry9;

		/*
		 |h0| <= (1.65*1.65*2^52*(1+19+19+19+19)+1.65*1.65*2^50*(38+38+38+38+38))
		 i.e. |h0| <= 1.4*2^60; narrower ranges for h2, h4, h6, h8
		 |h1| <= (1.65*1.65*2^51*(1+1+19+19+19+19+19+19+19+19))
		 i.e. |h1| <= 1.7*2^59; narrower ranges for h3, h5, h7, h9
		 */

		carry0 = (h0 + (int64_t)(1L << 25)) >> 26;
		h1 += carry0;
		h0 -= carry0 * ((uint64_t)1L << 26);
		carry4 = (h4 + (int64_t)(1L << 25)) >> 26;
		h5 += carry4;
		h4 -= carry4 * ((uint64_t)1L << 26);
		/* |h0| <= 2^25 */
		/* |h4| <= 2^25 */
		/* |h1| <= 1.71*2^59 */
		/* |h5| <= 1.71*2^59 */

		carry1 = (h1 + (int64_t)(1L << 24)) >> 25;
		h2 += carry1;
		h1 -= carry1 * ((uint64_t)1L << 25);
		carry5 = (h5 + (int64_t)(1L << 24)) >> 25;
		h6 += carry5;
		h5 -= carry5 * ((uint64_t)1L << 25);
		/* |h1| <= 2^24; from now on fits into int32 */
		/* |h5| <= 2^24; from now on fits into int32 */
		/* |h2| <= 1.41*2^60 */
		/* |h6| <= 1.41*2^60 */

		carry2 = (h2 + (int64_t)(1L << 25)) >> 26;
		h3 += carry2;
		h2 -= carry2 * ((uint64_t)1L << 26);
		carry6 = (h6 + (int64_t)(1L << 25)) >> 26;
		h7 += carry6;
		h6 -= carry6 * ((uint64_t)1L << 26);
		/* |h2| <= 2^25; from now on fits into int32 unchanged */
		/* |h6| <= 2^25; from now on fits into int32 unchanged */
		/* |h3| <= 1.71*2^59 */
		/* |h7| <= 1.71*2^59 */

		carry3 = (h3 + (int64_t)(1L << 24)) >> 25;
		h4 += carry3;
		h3 -= carry3 * ((uint64_t)1L << 25);
		carry7 = (h7 + (int64_t)(1L << 24)) >> 25;
		h8 += carry7;
		h7 -= carry7 * ((uint64_t)1L << 25);
		/* |h3| <= 2^24; from now on fits into int32 unchanged */
		/* |h7| <= 2^24; from now on fits into int32 unchanged */
		/* |h4| <= 1.72*2^34 */
		/* |h8| <= 1.41*2^60 */

		carry4 = (h4 + (int64_t)(1L << 25)) >> 26;
		h5 += carry4;
		h4 -= carry4 * ((uint64_t)1L << 26);
		carry8 = (h8 + (int64_t)(1L << 25)) >> 26;
		h9 += carry8;
		h8 -= carry8 * ((uint64_t)1L << 26);
		/* |h4| <= 2^25; from now on fits into int32 unchanged */
		/* |h8| <= 2^25; from now on fits into int32 unchanged */
		/* |h5| <= 1.01*2^24 */
		/* |h9| <= 1.71*2^59 */

		carry9 = (h9 + (int64_t)(1L << 24)) >> 25;
		h0 += carry9 * 19;
		h9 -= carry9 * ((uint64_t)1L << 25);
		/* |h9| <= 2^24; from now on fits into int32 unchanged */
		/* |h0| <= 1.1*2^39 */

		carry0 = (h0 + (int64_t)(1L << 25)) >> 26;
		h1 += carry0;
		h0 -= carry0 * ((uint64_t)1L << 26);
		/* |h0| <= 2^25; from now on fits into int32 unchanged */
		/* |h1| <= 1.01*2^24 */

		h[0] = (int32_t)h0;
		h[1] = (int32_t)h1;
		h[2] = (int32_t)h2;
		h[3] = (int32_t)h3;
		h[4] = (int32_t)h4;
		h[5] = (int32_t)h5;
		h[6] = (int32_t)h6;
		h[7] = (int32_t)h7;
		h[8] = (int32_t)h8;
		h[9] = (int32_t)h9;
	}


	/*
	 h = f * f
	 Can overlap h with f.
	 *
	 Preconditions:
	 |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
	 *
	 Postconditions:
	 |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
	 */

	static inline void
		ropo_fe25519_sq(ropo_fe25519 h, const ropo_fe25519 f)
	{
		int32_t f0 = f[0];
		int32_t f1 = f[1];
		int32_t f2 = f[2];
		int32_t f3 = f[3];
		int32_t f4 = f[4];
		int32_t f5 = f[5];
		int32_t f6 = f[6];
		int32_t f7 = f[7];
		int32_t f8 = f[8];
		int32_t f9 = f[9];

		int32_t f0_2 = 2 * f0;
		int32_t f1_2 = 2 * f1;
		int32_t f2_2 = 2 * f2;
		int32_t f3_2 = 2 * f3;
		int32_t f4_2 = 2 * f4;
		int32_t f5_2 = 2 * f5;
		int32_t f6_2 = 2 * f6;
		int32_t f7_2 = 2 * f7;
		int32_t f5_38 = 38 * f5; /* 1.959375*2^30 */
		int32_t f6_19 = 19 * f6; /* 1.959375*2^30 */
		int32_t f7_38 = 38 * f7; /* 1.959375*2^30 */
		int32_t f8_19 = 19 * f8; /* 1.959375*2^30 */
		int32_t f9_38 = 38 * f9; /* 1.959375*2^30 */

		int64_t f0f0 = f0 * (int64_t)f0;
		int64_t f0f1_2 = f0_2 * (int64_t)f1;
		int64_t f0f2_2 = f0_2 * (int64_t)f2;
		int64_t f0f3_2 = f0_2 * (int64_t)f3;
		int64_t f0f4_2 = f0_2 * (int64_t)f4;
		int64_t f0f5_2 = f0_2 * (int64_t)f5;
		int64_t f0f6_2 = f0_2 * (int64_t)f6;
		int64_t f0f7_2 = f0_2 * (int64_t)f7;
		int64_t f0f8_2 = f0_2 * (int64_t)f8;
		int64_t f0f9_2 = f0_2 * (int64_t)f9;
		int64_t f1f1_2 = f1_2 * (int64_t)f1;
		int64_t f1f2_2 = f1_2 * (int64_t)f2;
		int64_t f1f3_4 = f1_2 * (int64_t)f3_2;
		int64_t f1f4_2 = f1_2 * (int64_t)f4;
		int64_t f1f5_4 = f1_2 * (int64_t)f5_2;
		int64_t f1f6_2 = f1_2 * (int64_t)f6;
		int64_t f1f7_4 = f1_2 * (int64_t)f7_2;
		int64_t f1f8_2 = f1_2 * (int64_t)f8;
		int64_t f1f9_76 = f1_2 * (int64_t)f9_38;
		int64_t f2f2 = f2 * (int64_t)f2;
		int64_t f2f3_2 = f2_2 * (int64_t)f3;
		int64_t f2f4_2 = f2_2 * (int64_t)f4;
		int64_t f2f5_2 = f2_2 * (int64_t)f5;
		int64_t f2f6_2 = f2_2 * (int64_t)f6;
		int64_t f2f7_2 = f2_2 * (int64_t)f7;
		int64_t f2f8_38 = f2_2 * (int64_t)f8_19;
		int64_t f2f9_38 = f2 * (int64_t)f9_38;
		int64_t f3f3_2 = f3_2 * (int64_t)f3;
		int64_t f3f4_2 = f3_2 * (int64_t)f4;
		int64_t f3f5_4 = f3_2 * (int64_t)f5_2;
		int64_t f3f6_2 = f3_2 * (int64_t)f6;
		int64_t f3f7_76 = f3_2 * (int64_t)f7_38;
		int64_t f3f8_38 = f3_2 * (int64_t)f8_19;
		int64_t f3f9_76 = f3_2 * (int64_t)f9_38;
		int64_t f4f4 = f4 * (int64_t)f4;
		int64_t f4f5_2 = f4_2 * (int64_t)f5;
		int64_t f4f6_38 = f4_2 * (int64_t)f6_19;
		int64_t f4f7_38 = f4 * (int64_t)f7_38;
		int64_t f4f8_38 = f4_2 * (int64_t)f8_19;
		int64_t f4f9_38 = f4 * (int64_t)f9_38;
		int64_t f5f5_38 = f5 * (int64_t)f5_38;
		int64_t f5f6_38 = f5_2 * (int64_t)f6_19;
		int64_t f5f7_76 = f5_2 * (int64_t)f7_38;
		int64_t f5f8_38 = f5_2 * (int64_t)f8_19;
		int64_t f5f9_76 = f5_2 * (int64_t)f9_38;
		int64_t f6f6_19 = f6 * (int64_t)f6_19;
		int64_t f6f7_38 = f6 * (int64_t)f7_38;
		int64_t f6f8_38 = f6_2 * (int64_t)f8_19;
		int64_t f6f9_38 = f6 * (int64_t)f9_38;
		int64_t f7f7_38 = f7 * (int64_t)f7_38;
		int64_t f7f8_38 = f7_2 * (int64_t)f8_19;
		int64_t f7f9_76 = f7_2 * (int64_t)f9_38;
		int64_t f8f8_19 = f8 * (int64_t)f8_19;
		int64_t f8f9_38 = f8 * (int64_t)f9_38;
		int64_t f9f9_38 = f9 * (int64_t)f9_38;

		int64_t h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
		int64_t h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
		int64_t h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
		int64_t h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
		int64_t h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
		int64_t h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
		int64_t h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
		int64_t h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
		int64_t h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
		int64_t h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;

		int64_t carry0;
		int64_t carry1;
		int64_t carry2;
		int64_t carry3;
		int64_t carry4;
		int64_t carry5;
		int64_t carry6;
		int64_t carry7;
		int64_t carry8;
		int64_t carry9;

		carry0 = (h0 + (int64_t)(1L << 25)) >> 26;
		h1 += carry0;
		h0 -= carry0 * ((uint64_t)1L << 26);
		carry4 = (h4 + (int64_t)(1L << 25)) >> 26;
		h5 += carry4;
		h4 -= carry4 * ((uint64_t)1L << 26);

		carry1 = (h1 + (int64_t)(1L << 24)) >> 25;
		h2 += carry1;
		h1 -= carry1 * ((uint64_t)1L << 25);
		carry5 = (h5 + (int64_t)(1L << 24)) >> 25;
		h6 += carry5;
		h5 -= carry5 * ((uint64_t)1L << 25);

		carry2 = (h2 + (int64_t)(1L << 25)) >> 26;
		h3 += carry2;
		h2 -= carry2 * ((uint64_t)1L << 26);
		carry6 = (h6 + (int64_t)(1L << 25)) >> 26;
		h7 += carry6;
		h6 -= carry6 * ((uint64_t)1L << 26);

		carry3 = (h3 + (int64_t)(1L << 24)) >> 25;
		h4 += carry3;
		h3 -= carry3 * ((uint64_t)1L << 25);
		carry7 = (h7 + (int64_t)(1L << 24)) >> 25;
		h8 += carry7;
		h7 -= carry7 * ((uint64_t)1L << 25);

		carry4 = (h4 + (int64_t)(1L << 25)) >> 26;
		h5 += carry4;
		h4 -= carry4 * ((uint64_t)1L << 26);
		carry8 = (h8 + (int64_t)(1L << 25)) >> 26;
		h9 += carry8;
		h8 -= carry8 * ((uint64_t)1L << 26);

		carry9 = (h9 + (int64_t)(1L << 24)) >> 25;
		h0 += carry9 * 19;
		h9 -= carry9 * ((uint64_t)1L << 25);

		carry0 = (h0 + (int64_t)(1L << 25)) >> 26;
		h1 += carry0;
		h0 -= carry0 * ((uint64_t)1L << 26);

		h[0] = (int32_t)h0;
		h[1] = (int32_t)h1;
		h[2] = (int32_t)h2;
		h[3] = (int32_t)h3;
		h[4] = (int32_t)h4;
		h[5] = (int32_t)h5;
		h[6] = (int32_t)h6;
		h[7] = (int32_t)h7;
		h[8] = (int32_t)h8;
		h[9] = (int32_t)h9;
	}



	/*
	 h = f - g
	 Can overlap h with f or g.
	 *
	 Preconditions:
	 |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
	 |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
	 *
	 Postconditions:
	 |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
	 */

	static inline void
		ropo_fe25519_sub(ropo_fe25519 h, const ropo_fe25519 f, const ropo_fe25519 g)
	{
		int32_t h0 = f[0] - g[0];
		int32_t h1 = f[1] - g[1];
		int32_t h2 = f[2] - g[2];
		int32_t h3 = f[3] - g[3];
		int32_t h4 = f[4] - g[4];
		int32_t h5 = f[5] - g[5];
		int32_t h6 = f[6] - g[6];
		int32_t h7 = f[7] - g[7];
		int32_t h8 = f[8] - g[8];
		int32_t h9 = f[9] - g[9];

		h[0] = h0;
		h[1] = h1;
		h[2] = h2;
		h[3] = h3;
		h[4] = h4;
		h[5] = h5;
		h[6] = h6;
		h[7] = h7;
		h[8] = h8;
		h[9] = h9;
	}



	/*
	 h = f + g
	 Can overlap h with f or g.
	 *
	 Preconditions:
	 |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
	 |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
	 *
	 Postconditions:
	 |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
	 */

	static inline void
		ropo_fe25519_add(ropo_fe25519 h, const ropo_fe25519 f, const ropo_fe25519 g)
	{
		int32_t h0 = f[0] + g[0];
		int32_t h1 = f[1] + g[1];
		int32_t h2 = f[2] + g[2];
		int32_t h3 = f[3] + g[3];
		int32_t h4 = f[4] + g[4];
		int32_t h5 = f[5] + g[5];
		int32_t h6 = f[6] + g[6];
		int32_t h7 = f[7] + g[7];
		int32_t h8 = f[8] + g[8];
		int32_t h9 = f[9] + g[9];

		h[0] = h0;
		h[1] = h1;
		h[2] = h2;
		h[3] = h3;
		h[4] = h4;
		h[5] = h5;
		h[6] = h6;
		h[7] = h7;
		h[8] = h8;
		h[9] = h9;
	}

	/*
 h = -f
 *
 Preconditions:
 |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
 *
 Postconditions:
 |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
 */

	static inline void
		ropo_fe25519_1(ropo_fe25519 h)
	{
		h[0] = 1;
		h[1] = 0;
		memset(&h[2], 0, 8 * sizeof h[0]);
	}

	static inline int
		ropo_fe25519_iszero(const ropo_fe25519 f)
	{
		unsigned char s[32];

		ropo_fe25519_tobytes(s, f);

		return sodium_is_zero(s, 32);
	}

	static inline int
		ropo_fe25519_isnegative(const ropo_fe25519 f)
	{
		unsigned char s[32];

		ropo_fe25519_tobytes(s, f);

		return s[0] & 1;
	}

	static inline void
		ropo_fe25519_cneg(ropo_fe25519 h, const ropo_fe25519 f, unsigned int b)
	{
		ropo_fe25519 negf;

		ropo_fe25519_neg(negf, f);
		ropo_fe25519_copy(h, f);
		ropo_fe25519_cmov(h, negf, b);
	}


	static inline void
		ropo_fe25519_invert(ropo_fe25519 out, const ropo_fe25519 z)
	{
		ropo_fe25519 t0;
		ropo_fe25519 t1;
		ropo_fe25519 t2;
		ropo_fe25519 t3;
		int     i;

		ropo_fe25519_sq(t0, z);
		ropo_fe25519_sq(t1, t0);
		ropo_fe25519_sq(t1, t1);
		ropo_fe25519_mul(t1, z, t1);
		ropo_fe25519_mul(t0, t0, t1);
		ropo_fe25519_sq(t2, t0);
		ropo_fe25519_mul(t1, t1, t2);
		ropo_fe25519_sq(t2, t1);
		for (i = 1; i < 5; ++i) {
			ropo_fe25519_sq(t2, t2);
		}
		ropo_fe25519_mul(t1, t2, t1);
		ropo_fe25519_sq(t2, t1);
		for (i = 1; i < 10; ++i) {
			ropo_fe25519_sq(t2, t2);
		}
		ropo_fe25519_mul(t2, t2, t1);
		ropo_fe25519_sq(t3, t2);
		for (i = 1; i < 20; ++i) {
			ropo_fe25519_sq(t3, t3);
		}
		ropo_fe25519_mul(t2, t3, t2);
		ropo_fe25519_sq(t2, t2);
		for (i = 1; i < 10; ++i) {
			ropo_fe25519_sq(t2, t2);
		}
		ropo_fe25519_mul(t1, t2, t1);
		ropo_fe25519_sq(t2, t1);
		for (i = 1; i < 50; ++i) {
			ropo_fe25519_sq(t2, t2);
		}
		ropo_fe25519_mul(t2, t2, t1);
		ropo_fe25519_sq(t3, t2);
		for (i = 1; i < 100; ++i) {
			ropo_fe25519_sq(t3, t3);
		}
		ropo_fe25519_mul(t2, t3, t2);
		ropo_fe25519_sq(t2, t2);
		for (i = 1; i < 50; ++i) {
			ropo_fe25519_sq(t2, t2);
		}
		ropo_fe25519_mul(t1, t2, t1);
		ropo_fe25519_sq(t1, t1);
		for (i = 1; i < 5; ++i) {
			ropo_fe25519_sq(t1, t1);
		}
		ropo_fe25519_mul(out, t1, t0);
	}

	static inline void
		ropo_fe25519_abs(ropo_fe25519 h, const ropo_fe25519 f)
	{
		ropo_fe25519_cneg(h, f, ropo_fe25519_isnegative(f));
	}

	static inline void
		ropo_fe25519_pow22523(ropo_fe25519 out, const ropo_fe25519 z)
	{
		ropo_fe25519 t0;
		ropo_fe25519 t1;
		ropo_fe25519 t2;
		int     i;

		ropo_fe25519_sq(t0, z);
		ropo_fe25519_sq(t1, t0);
		ropo_fe25519_sq(t1, t1);
		ropo_fe25519_mul(t1, z, t1);
		ropo_fe25519_mul(t0, t0, t1);
		ropo_fe25519_sq(t0, t0);
		ropo_fe25519_mul(t0, t1, t0);
		ropo_fe25519_sq(t1, t0);
		for (i = 1; i < 5; ++i) {
			ropo_fe25519_sq(t1, t1);
		}
		ropo_fe25519_mul(t0, t1, t0);
		ropo_fe25519_sq(t1, t0);
		for (i = 1; i < 10; ++i) {
			ropo_fe25519_sq(t1, t1);
		}
		ropo_fe25519_mul(t1, t1, t0);
		ropo_fe25519_sq(t2, t1);
		for (i = 1; i < 20; ++i) {
			ropo_fe25519_sq(t2, t2);
		}
		ropo_fe25519_mul(t1, t2, t1);
		ropo_fe25519_sq(t1, t1);
		for (i = 1; i < 10; ++i) {
			ropo_fe25519_sq(t1, t1);
		}
		ropo_fe25519_mul(t0, t1, t0);
		ropo_fe25519_sq(t1, t0);
		for (i = 1; i < 50; ++i) {
			ropo_fe25519_sq(t1, t1);
		}
		ropo_fe25519_mul(t1, t1, t0);
		ropo_fe25519_sq(t2, t1);
		for (i = 1; i < 100; ++i) {
			ropo_fe25519_sq(t2, t2);
		}
		ropo_fe25519_mul(t1, t2, t1);
		ropo_fe25519_sq(t1, t1);
		for (i = 1; i < 50; ++i) {
			ropo_fe25519_sq(t1, t1);
		}
		ropo_fe25519_mul(t0, t1, t0);
		ropo_fe25519_sq(t0, t0);
		ropo_fe25519_sq(t0, t0);
		ropo_fe25519_mul(out, t0, z);
	}

	static inline  void
		ropo_fe25519_sq2(ropo_fe25519 h, const ropo_fe25519 f)
	{
		int32_t f0 = f[0];
		int32_t f1 = f[1];
		int32_t f2 = f[2];
		int32_t f3 = f[3];
		int32_t f4 = f[4];
		int32_t f5 = f[5];
		int32_t f6 = f[6];
		int32_t f7 = f[7];
		int32_t f8 = f[8];
		int32_t f9 = f[9];

		int32_t f0_2 = 2 * f0;
		int32_t f1_2 = 2 * f1;
		int32_t f2_2 = 2 * f2;
		int32_t f3_2 = 2 * f3;
		int32_t f4_2 = 2 * f4;
		int32_t f5_2 = 2 * f5;
		int32_t f6_2 = 2 * f6;
		int32_t f7_2 = 2 * f7;
		int32_t f5_38 = 38 * f5; /* 1.959375*2^30 */
		int32_t f6_19 = 19 * f6; /* 1.959375*2^30 */
		int32_t f7_38 = 38 * f7; /* 1.959375*2^30 */
		int32_t f8_19 = 19 * f8; /* 1.959375*2^30 */
		int32_t f9_38 = 38 * f9; /* 1.959375*2^30 */

		int64_t f0f0 = f0 * (int64_t)f0;
		int64_t f0f1_2 = f0_2 * (int64_t)f1;
		int64_t f0f2_2 = f0_2 * (int64_t)f2;
		int64_t f0f3_2 = f0_2 * (int64_t)f3;
		int64_t f0f4_2 = f0_2 * (int64_t)f4;
		int64_t f0f5_2 = f0_2 * (int64_t)f5;
		int64_t f0f6_2 = f0_2 * (int64_t)f6;
		int64_t f0f7_2 = f0_2 * (int64_t)f7;
		int64_t f0f8_2 = f0_2 * (int64_t)f8;
		int64_t f0f9_2 = f0_2 * (int64_t)f9;
		int64_t f1f1_2 = f1_2 * (int64_t)f1;
		int64_t f1f2_2 = f1_2 * (int64_t)f2;
		int64_t f1f3_4 = f1_2 * (int64_t)f3_2;
		int64_t f1f4_2 = f1_2 * (int64_t)f4;
		int64_t f1f5_4 = f1_2 * (int64_t)f5_2;
		int64_t f1f6_2 = f1_2 * (int64_t)f6;
		int64_t f1f7_4 = f1_2 * (int64_t)f7_2;
		int64_t f1f8_2 = f1_2 * (int64_t)f8;
		int64_t f1f9_76 = f1_2 * (int64_t)f9_38;
		int64_t f2f2 = f2 * (int64_t)f2;
		int64_t f2f3_2 = f2_2 * (int64_t)f3;
		int64_t f2f4_2 = f2_2 * (int64_t)f4;
		int64_t f2f5_2 = f2_2 * (int64_t)f5;
		int64_t f2f6_2 = f2_2 * (int64_t)f6;
		int64_t f2f7_2 = f2_2 * (int64_t)f7;
		int64_t f2f8_38 = f2_2 * (int64_t)f8_19;
		int64_t f2f9_38 = f2 * (int64_t)f9_38;
		int64_t f3f3_2 = f3_2 * (int64_t)f3;
		int64_t f3f4_2 = f3_2 * (int64_t)f4;
		int64_t f3f5_4 = f3_2 * (int64_t)f5_2;
		int64_t f3f6_2 = f3_2 * (int64_t)f6;
		int64_t f3f7_76 = f3_2 * (int64_t)f7_38;
		int64_t f3f8_38 = f3_2 * (int64_t)f8_19;
		int64_t f3f9_76 = f3_2 * (int64_t)f9_38;
		int64_t f4f4 = f4 * (int64_t)f4;
		int64_t f4f5_2 = f4_2 * (int64_t)f5;
		int64_t f4f6_38 = f4_2 * (int64_t)f6_19;
		int64_t f4f7_38 = f4 * (int64_t)f7_38;
		int64_t f4f8_38 = f4_2 * (int64_t)f8_19;
		int64_t f4f9_38 = f4 * (int64_t)f9_38;
		int64_t f5f5_38 = f5 * (int64_t)f5_38;
		int64_t f5f6_38 = f5_2 * (int64_t)f6_19;
		int64_t f5f7_76 = f5_2 * (int64_t)f7_38;
		int64_t f5f8_38 = f5_2 * (int64_t)f8_19;
		int64_t f5f9_76 = f5_2 * (int64_t)f9_38;
		int64_t f6f6_19 = f6 * (int64_t)f6_19;
		int64_t f6f7_38 = f6 * (int64_t)f7_38;
		int64_t f6f8_38 = f6_2 * (int64_t)f8_19;
		int64_t f6f9_38 = f6 * (int64_t)f9_38;
		int64_t f7f7_38 = f7 * (int64_t)f7_38;
		int64_t f7f8_38 = f7_2 * (int64_t)f8_19;
		int64_t f7f9_76 = f7_2 * (int64_t)f9_38;
		int64_t f8f8_19 = f8 * (int64_t)f8_19;
		int64_t f8f9_38 = f8 * (int64_t)f9_38;
		int64_t f9f9_38 = f9 * (int64_t)f9_38;

		int64_t h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
		int64_t h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
		int64_t h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
		int64_t h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
		int64_t h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
		int64_t h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
		int64_t h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
		int64_t h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
		int64_t h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
		int64_t h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;

		int64_t carry0;
		int64_t carry1;
		int64_t carry2;
		int64_t carry3;
		int64_t carry4;
		int64_t carry5;
		int64_t carry6;
		int64_t carry7;
		int64_t carry8;
		int64_t carry9;

		h0 += h0;
		h1 += h1;
		h2 += h2;
		h3 += h3;
		h4 += h4;
		h5 += h5;
		h6 += h6;
		h7 += h7;
		h8 += h8;
		h9 += h9;

		carry0 = (h0 + (int64_t)(1L << 25)) >> 26;
		h1 += carry0;
		h0 -= carry0 * ((uint64_t)1L << 26);
		carry4 = (h4 + (int64_t)(1L << 25)) >> 26;
		h5 += carry4;
		h4 -= carry4 * ((uint64_t)1L << 26);

		carry1 = (h1 + (int64_t)(1L << 24)) >> 25;
		h2 += carry1;
		h1 -= carry1 * ((uint64_t)1L << 25);
		carry5 = (h5 + (int64_t)(1L << 24)) >> 25;
		h6 += carry5;
		h5 -= carry5 * ((uint64_t)1L << 25);

		carry2 = (h2 + (int64_t)(1L << 25)) >> 26;
		h3 += carry2;
		h2 -= carry2 * ((uint64_t)1L << 26);
		carry6 = (h6 + (int64_t)(1L << 25)) >> 26;
		h7 += carry6;
		h6 -= carry6 * ((uint64_t)1L << 26);

		carry3 = (h3 + (int64_t)(1L << 24)) >> 25;
		h4 += carry3;
		h3 -= carry3 * ((uint64_t)1L << 25);
		carry7 = (h7 + (int64_t)(1L << 24)) >> 25;
		h8 += carry7;
		h7 -= carry7 * ((uint64_t)1L << 25);

		carry4 = (h4 + (int64_t)(1L << 25)) >> 26;
		h5 += carry4;
		h4 -= carry4 * ((uint64_t)1L << 26);
		carry8 = (h8 + (int64_t)(1L << 25)) >> 26;
		h9 += carry8;
		h8 -= carry8 * ((uint64_t)1L << 26);

		carry9 = (h9 + (int64_t)(1L << 24)) >> 25;
		h0 += carry9 * 19;
		h9 -= carry9 * ((uint64_t)1L << 25);

		carry0 = (h0 + (int64_t)(1L << 25)) >> 26;
		h1 += carry0;
		h0 -= carry0 * ((uint64_t)1L << 26);

		h[0] = (int32_t)h0;
		h[1] = (int32_t)h1;
		h[2] = (int32_t)h2;
		h[3] = (int32_t)h3;
		h[4] = (int32_t)h4;
		h[5] = (int32_t)h5;
		h[6] = (int32_t)h6;
		h[7] = (int32_t)h7;
		h[8] = (int32_t)h8;
		h[9] = (int32_t)h9;
	}


	static inline int
		ropo_ge25519_frombytes(ropo_ge25519_p3* h, const unsigned char* s)
	{
		ropo_fe25519 u;
		ropo_fe25519 v;
		ropo_fe25519 v3;
		ropo_fe25519 vxx;
		ropo_fe25519 m_root_check, p_root_check;
		ropo_fe25519 negx;
		ropo_fe25519 x_sqrtm1;
		int     has_m_root, has_p_root;

		ropo_fe25519_frombytes(h->Y, s);
		ropo_fe25519_1(h->Z);
		ropo_fe25519_sq(u, h->Y);
		ropo_fe25519_mul(v, u, d);
		ropo_fe25519_sub(u, u, h->Z); /* u = y^2-1 */
		ropo_fe25519_add(v, v, h->Z); /* v = dy^2+1 */

		ropo_fe25519_sq(v3, v);
		ropo_fe25519_mul(v3, v3, v); /* v3 = v^3 */
		ropo_fe25519_sq(h->X, v3);
		ropo_fe25519_mul(h->X, h->X, v);
		ropo_fe25519_mul(h->X, h->X, u); /* x = uv^7 */

		ropo_fe25519_pow22523(h->X, h->X); /* x = (uv^7)^((q-5)/8) */
		ropo_fe25519_mul(h->X, h->X, v3);
		ropo_fe25519_mul(h->X, h->X, u); /* x = uv^3(uv^7)^((q-5)/8) */

		ropo_fe25519_sq(vxx, h->X);
		ropo_fe25519_mul(vxx, vxx, v);
		ropo_fe25519_sub(m_root_check, vxx, u); /* vx^2-u */
		ropo_fe25519_add(p_root_check, vxx, u); /* vx^2+u */
		has_m_root = ropo_fe25519_iszero(m_root_check);
		has_p_root = ropo_fe25519_iszero(p_root_check);
		ropo_fe25519_mul(x_sqrtm1, h->X, sqrtm1); /* x*sqrt(-1) */
		ropo_fe25519_cmov(h->X, x_sqrtm1, 1 - has_m_root);

		ropo_fe25519_neg(negx, h->X);
		ropo_fe25519_cmov(h->X, negx, ropo_fe25519_isnegative(h->X) ^ (s[31] >> 7));
		ropo_fe25519_mul(h->T, h->X, h->Y);

		return (has_m_root | has_p_root) - 1;
	}


	static inline int
		ropo_ristretto255_sqrt_ratio_m1(ropo_fe25519 x, const ropo_fe25519 u, const ropo_fe25519 v)
	{
		ropo_fe25519 v3;
		ropo_fe25519 vxx;
		ropo_fe25519 m_root_check, p_root_check, f_root_check;
		ropo_fe25519 x_sqrtm1;
		int     has_m_root, has_p_root, has_f_root;

		ropo_fe25519_sq(v3, v);
		ropo_fe25519_mul(v3, v3, v); /* v3 = v^3 */
		ropo_fe25519_sq(x, v3);
		ropo_fe25519_mul(x, x, v);
		ropo_fe25519_mul(x, x, u); /* x = uv^7 */

		ropo_fe25519_pow22523(x, x); /* x = (uv^7)^((q-5)/8) */
		ropo_fe25519_mul(x, x, v3);
		ropo_fe25519_mul(x, x, u); /* x = uv^3(uv^7)^((q-5)/8) */

		ropo_fe25519_sq(vxx, x);
		ropo_fe25519_mul(vxx, vxx, v); /* vx^2 */
		ropo_fe25519_sub(m_root_check, vxx, u); /* vx^2-u */
		ropo_fe25519_add(p_root_check, vxx, u); /* vx^2+u */
		ropo_fe25519_mul(f_root_check, u, sqrtm1); /* u*sqrt(-1) */
		ropo_fe25519_add(f_root_check, vxx, f_root_check); /* vx^2+u*sqrt(-1) */
		has_m_root = ropo_fe25519_iszero(m_root_check);
		has_p_root = ropo_fe25519_iszero(p_root_check);
		has_f_root = ropo_fe25519_iszero(f_root_check);
		ropo_fe25519_mul(x_sqrtm1, x, sqrtm1); /* x*sqrt(-1) */

		ropo_fe25519_cmov(x, x_sqrtm1, has_p_root | has_f_root);
		ropo_fe25519_abs(x, x);

		return has_m_root | has_p_root;
	}

	static inline int
		ropo_ristretto255_is_canonical(const unsigned char* s)
	{
		unsigned char c;
		unsigned char d;
		unsigned int  i;

		c = (s[31] & 0x7f) ^ 0x7f;
		for (i = 30; i > 0; i--) {
			c |= s[i] ^ 0xff;
		}
		c = (((unsigned int)c) - 1U) >> 8;
		d = (0xed - 1U - (unsigned int)s[0]) >> 8;

		return 1 - (((c & d) | s[0]) & 1);
	}

	inline int
		ropo_ristretto255_frombytes(ropo_ge25519_p3* h, const unsigned char* s)
	{
		ropo_fe25519 inv_sqrt;
		ropo_fe25519 one;
		ropo_fe25519 s_;
		ropo_fe25519 ss;
		ropo_fe25519 u1, u2;
		ropo_fe25519 u1u1, u2u2;
		ropo_fe25519 v;
		ropo_fe25519 v_u2u2;
		int     was_square;

		if (ropo_ristretto255_is_canonical(s) == 0) {
			return -1;
		}
		ropo_fe25519_frombytes(s_, s);
		ropo_fe25519_sq(ss, s_);                /* ss = s^2 */

		ropo_fe25519_1(u1);
		ropo_fe25519_sub(u1, u1, ss);           /* u1 = 1-ss */
		ropo_fe25519_sq(u1u1, u1);              /* u1u1 = u1^2 */

		ropo_fe25519_1(u2);
		ropo_fe25519_add(u2, u2, ss);           /* u2 = 1+ss */
		ropo_fe25519_sq(u2u2, u2);              /* u2u2 = u2^2 */

		ropo_fe25519_mul(v, d, u1u1);           /* v = d*u1^2 */
		ropo_fe25519_neg(v, v);                 /* v = -d*u1^2 */
		ropo_fe25519_sub(v, v, u2u2);           /* v = -(d*u1^2)-u2^2 */

		ropo_fe25519_mul(v_u2u2, v, u2u2);      /* v_u2u2 = v*u2^2 */

		ropo_fe25519_1(one);
		was_square = ropo_ristretto255_sqrt_ratio_m1(inv_sqrt, one, v_u2u2);
		ropo_fe25519_mul(h->X, inv_sqrt, u2);
		ropo_fe25519_mul(h->Y, inv_sqrt, h->X);
		ropo_fe25519_mul(h->Y, h->Y, v);

		ropo_fe25519_mul(h->X, h->X, s_);
		ropo_fe25519_add(h->X, h->X, h->X);
		ropo_fe25519_abs(h->X, h->X);
		ropo_fe25519_mul(h->Y, u1, h->Y);
		ropo_fe25519_1(h->Z);
		ropo_fe25519_mul(h->T, h->X, h->Y);

		return -((1 - was_square) |
			ropo_fe25519_isnegative(h->T) | ropo_fe25519_iszero(h->Y));
	}
	
	

	/* 1 - d ^ 2 */
	static const ropo_fe25519 ropo_onemsqd = {
		6275446, -16617371, -22938544, -3773710, 11667077, 7397348, -27922721, 1766195, -24433858, 672203
	};


	/* (d - 1) ^ 2 */
	static const ropo_fe25519 ropo_sqdmone = {
		15551795, -11097455, -13425098, -10125071, -11896535, 10178284, -26634327, 4729244, -5282110, -10116402
	};

	/* sqrt(ad - 1) with a = -1 (mod p) */
	static const ropo_fe25519 ropo_sqrtadm1 = {
		24849947, -153582, -23613485, 6347715, -21072328, -667138, -25271143, -15367704, -870347, 14525639
	};

	static inline void
		ropo_ristretto255_elligator(ropo_ge25519_p3* p, const ropo_fe25519 t)
	{
		ropo_fe25519 c;
		ropo_fe25519 n;
		ropo_fe25519 one;
		ropo_fe25519 r;
		ropo_fe25519 rpd;
		ropo_fe25519 s, s_prime;
		ropo_fe25519 ss;
		ropo_fe25519 u, v;
		ropo_fe25519 w0, w1, w2, w3;
		int     wasnt_square;

		ropo_fe25519_1(one);
		ropo_fe25519_sq(r, t);                  /* r = t^2 */
		ropo_fe25519_mul(r, sqrtm1, r);         /* r = sqrt(-1)*t^2 */
		ropo_fe25519_add(u, r, one);            /* u = r+1 */
		ropo_fe25519_mul(u, u, ropo_onemsqd);        /* u = (r+1)*(1-d^2) */
		ropo_fe25519_1(c);
		ropo_fe25519_neg(c, c);                 /* c = -1 */
		ropo_fe25519_add(rpd, r, d);            /* rpd = r*d */
		ropo_fe25519_mul(v, r, d);              /* v = r*d */
		ropo_fe25519_sub(v, c, v);              /* v = c-r*d */
		ropo_fe25519_mul(v, v, rpd);            /* v = (c-r*d)*(r+d) */

		wasnt_square = 1 - ropo_ristretto255_sqrt_ratio_m1(s, u, v);
		ropo_fe25519_mul(s_prime, s, t);
		ropo_fe25519_abs(s_prime, s_prime);
		ropo_fe25519_neg(s_prime, s_prime);     /* s_prime = -|s*t| */
		ropo_fe25519_cmov(s, s_prime, wasnt_square);
		ropo_fe25519_cmov(c, r, wasnt_square);

		ropo_fe25519_sub(n, r, one);            /* n = r-1 */
		ropo_fe25519_mul(n, n, c);              /* n = c*(r-1) */
		ropo_fe25519_mul(n, n, ropo_sqdmone);        /* n = c*(r-1)*(d-1)^2 */
		ropo_fe25519_sub(n, n, v);              /* n =  c*(r-1)*(d-1)^2-v */

		ropo_fe25519_add(w0, s, s);             /* w0 = 2s */
		ropo_fe25519_mul(w0, w0, v);            /* w0 = 2s*v */
		ropo_fe25519_mul(w1, n, ropo_sqrtadm1);      /* w1 = n*sqrt(ad-1) */
		ropo_fe25519_sq(ss, s);                 /* ss = s^2 */
		ropo_fe25519_sub(w2, one, ss);          /* w2 = 1-s^2 */
		ropo_fe25519_add(w3, one, ss);          /* w3 = 1+s^2 */

		ropo_fe25519_mul(p->X, w0, w3);
		ropo_fe25519_mul(p->Y, w2, w1);
		ropo_fe25519_mul(p->Z, w1, w3);
		ropo_fe25519_mul(p->T, w0, w2);
	}

	//=============end copy
#pragma endregion

	inline void ristretto255_hash_from_blk(unsigned char* sum, block seed)
	{
		PRNG prng;
		prng.SetSeed(seed);

		for (size_t i = 0; i < crypto_core_ristretto255_HASHBYTES/sizeof(block); i++)
		{
			block blk = prng.get<block>();
			memcpy(sum+i* sizeof(block), (u8*)&blk, sizeof(block));
		}
	}

	inline int ristretto_fe25519_add(unsigned char* sum, const unsigned char* a, const unsigned char* b)
		{
			sum = new unsigned char[crypto_core_ristretto255_BYTES];
			ropo_fe25519 fe_a;
			ropo_fe25519 fe_b;
			ropo_fe25519_frombytes(fe_a, a);
			ropo_fe25519_frombytes(fe_b, b);
			ropo_fe25519_add(fe_a, fe_a, fe_b);
			ropo_fe25519_tobytes(sum, fe_a);
		}

	inline int ristretto_ropoGroup2Field(const unsigned char* gr, std::vector<unsigned char*>& buffs, ropo_fe25519 one)
	{
		bool success;
		int iter = 0;
		ropo_fe25519 fe_gr;
		unsigned char* p = new unsigned char[crypto_core_ristretto255_BYTES];

		ropo_fe25519_frombytes(fe_gr, gr);

		//unsigned char k[crypto_core_ristretto255_SCALARBYTES]; //for test
		//crypto_core_ristretto255_scalar_random(k);  
		//ropo_fe25519_tobytes(p, fe_gr);  //P(yi)=p
		//std::cout << toBlock((u8*)&p) << "\n ";

		do
		{
			ropo_fe25519_sub(fe_gr, fe_gr, one); //simulate permute pi^-1

			/*unsigned char pi[crypto_core_ristretto255_BYTES];
			randombytes_buf(pi, sizeof pi);
			ropo_fe25519_frombytes(fe_gr, pi);*/

			ropo_fe25519_tobytes(p, fe_gr);  //P(yi)=p
			//std::cout << toBlock((u8*)p) << "  p\n ";

			success = crypto_core_ristretto255_is_valid_point(p);
			if (success == false)
				buffs.push_back(p);

			iter++;

			//unsigned char b[crypto_core_ristretto255_BYTES];
			//if (success) {
			//	if (crypto_scalarmult_ristretto255(b, k, p) != 0) {
			//		std::cout << "crypto_scalarmult_ristretto255(b, k, s) != 0\n";
			//		return -1;
			//	}
			//}

		} while (success == false);

		//// TEST F to G
		//for (int idx = 0; idx < buffs.size(); idx++)
		//{

		//	std::cout << toBlock((u8*)buffs[idx]) <<  " buff internal point#######\n";


		//	ropo_fe25519 fe_buff;
		//	ropo_fe25519_frombytes(fe_buff, buffs[idx]);
		//	unsigned char p[crypto_core_ristretto255_BYTES];

		//	do
		//	{
		//		ropo_fe25519_add(fe_buff, fe_buff, one); //simulate permute pi
		//		
		//		ropo_fe25519_tobytes(p, fe_buff);

		//		success = crypto_core_ristretto255_is_valid_point(p);
		//		iter++;
		//		//std::cout << iter++ << "\t-\t F2G success= " << success << "\n";
		//	} while (success == false);

		//	std::cout << toBlock((u8*)&p) << " recovered internal\n ";
		//}
		//std::cout << "#trials:" << iter << "\n";

		return iter;
	}


	inline int ristretto_ropoField2Group(unsigned char* buff, unsigned char* gr, ropo_fe25519 one)
	{
		bool success;
		int iter = 0;
		
		//std::cout << toBlock(buff) << " buff internal2 #######\n";
		
		ropo_fe25519 fe_buff;
		ropo_fe25519_frombytes(fe_buff, buff);

		do
		{
			ropo_fe25519_add(fe_buff, fe_buff, one); //simulate permute pi
			ropo_fe25519_tobytes(gr, fe_buff);

			success = crypto_core_ristretto255_is_valid_point(gr);
			iter++;
			//std::cout << iter++ << "\t-\t F2G success= " << success << "\n";
		} while (success == false);

		//std::cout << toBlock((u8*)gr) << " recovered\n ";

		return iter;
	}


	inline void Ristretto_main_test()
	{
		ropo_fe25519 one;
		ropo_fe25519_1(one);
		int numTrial = 10000;
		unsigned char r[crypto_core_ristretto255_SCALARBYTES]; //g^r
		unsigned char gr[crypto_core_ristretto255_BYTES];
		unsigned char* gr_recovered = new unsigned char[crypto_core_ristretto255_BYTES];

		//==================G->2^F->F->G
		//gTimer.reset();
		//gTimer.setTimePoint("Ristretto_curveRoPOTest: start");
		for (int iTrial = 0; iTrial < numTrial; iTrial++)
		{
			//std::cout << "\n\n======================\n";
			// choose random g^ri until T^-1(g^ri) !=0
			int iter = 0;
			std::vector<unsigned char*> buffs;
			do {
				buffs.clear();

				crypto_core_ristretto255_scalar_random(r);
				crypto_scalarmult_ristretto255_base(gr, r);
				auto cnt_g2f = ristretto_ropoGroup2Field(gr, buffs, one);
				iter++;
			} while (buffs.size() == 0);

			//std::cout << " #trial:"  << iter << " buffs.size() : " << buffs.size() << "\n"; 
			std::cout << toBlock((u8*)&gr) << " orignial point#######\n";

			//std::cout << toBlock((u8*)buffs[buffs.size()-1]) << " buff point#######\n";
			// choose random si from buffs
			//unsigned char* buff = new unsigned char[crypto_core_ristretto255_BYTES];

			int idx = rand() % buffs.size();
			//for (int idx = 0; idx < buffs.size(); idx++)
			{
				//buff = buffs[idx];
				//std::cout << idx << " idx \t" << toBlock((u8*)buffs[idx]) << " buff point#######\n";


				auto cnt_f2g = ristretto_ropoField2Group(buffs[idx], gr_recovered, one);
				std::cout << toBlock((u8*)gr_recovered) << " recovered point#######\n";
			}
		}
		//gTimer.setTimePoint("Ristretto_curveRoPOTest: end");
		//std::cout << gTimer << "\n";


	}

	inline void Ristretto_evalExp(int n)
	{
		PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
		u64 mMyInputSize = 1 << n;

#if 1
		//////============clasic g^ri==========

		{
			gTimer.reset();
			gTimer.setTimePoint("clasic g^ri starts");
			std::vector<unsigned char*> g_r;
			g_r.resize(mMyInputSize);

			for (u64 i = 0; i < mMyInputSize; i++)
			{
				unsigned char* r = new unsigned char[crypto_core_ristretto255_SCALARBYTES];
				g_r[i] = new unsigned char[crypto_core_ristretto255_BYTES];
				crypto_core_ristretto255_scalar_random(r);
				crypto_scalarmult_ristretto255_base(g_r[i], r);
			}
			gTimer.setTimePoint("clasic g^ri done");
			std::cout << gTimer << "\n";


			//	int cnt = 0;
			//	std::vector<string> checkUnique;

			//	for (u64 i = 0; i < mMyInputSize; i++)
			//	{
			//		u8* temp = new u8[g_r[i].sizeBytes()];
			//		g_r[i].toBytes(temp);

			//		string str_sum = arrU8toString(temp, g_r[i].sizeBytes());

			//		if (std::find(checkUnique.begin(), checkUnique.end(), str_sum) == checkUnique.end())
			//			checkUnique.push_back(str_sum);
			//		else
			//		{
			//			std::cout << "dupl. : " << str_sum << "\n";
			//			cnt++;
			//		}
			//	}
			//	std::cout << "cnt= " << cnt << "\t checkUnique.size()= " << checkUnique.size() << "\n\n";
			//
		}
#endif
		//////============HSS g^ri==========
		{	gTimer.reset();
		gTimer.setTimePoint("HSS g^ri starts");

		u64 mSetSeedsSize, mChoseSeedsSize, mBoundCoeffs;
		getBestExpParams(mMyInputSize, mSetSeedsSize, mChoseSeedsSize, mBoundCoeffs);

		std::vector<unsigned char*> nSeeds;
		std::vector<unsigned char*> pG_seeds;
		nSeeds.resize(mSetSeedsSize);
		pG_seeds.resize(mSetSeedsSize);


		//seeds
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			// get a random value from Z_p
			nSeeds[i] = new unsigned char[crypto_core_ristretto255_SCALARBYTES];
			crypto_core_ristretto255_scalar_random(nSeeds[i]);

			pG_seeds[i] = new unsigned char[crypto_core_ristretto255_BYTES];;  //g^ri
			crypto_scalarmult_ristretto255_base(pG_seeds[i], nSeeds[i]);
		}
		gTimer.setTimePoint("HSS g^seed done");

		std::vector<u64> indices(mSetSeedsSize);
		std::vector<unsigned char* > g_r;
		g_r.resize(mMyInputSize);

		for (u64 i = 0; i < mMyInputSize; i++)
		{
			if (mMyInputSize < (1 << 9))
			{
				std::iota(indices.begin(), indices.end(), 0);
				std::random_shuffle(indices.begin(), indices.end()); //random permutation and get 1st K indices
			}
			else
			{
				indices.resize(0);
				while (indices.size() < mChoseSeedsSize)
				{
					int rnd = rand() % mSetSeedsSize;
					if (std::find(indices.begin(), indices.end(), rnd) == indices.end())
						indices.push_back(rnd);
				}
			}



			if (mBoundCoeffs == 2)
			{
				g_r[i] = new unsigned char[crypto_core_ristretto255_BYTES] {};

				for (u64 j = 1; j < mChoseSeedsSize; j++)
					crypto_core_ristretto255_add(g_r[i], g_r[i], pG_seeds[indices[j]]); //g^sum //h=2   ci=1

			}
			else
			{
				std::cout << "mBoundCoeffs Don't support\n";
				throw std::runtime_error("rt error at " LOCATION);

				//g_r.emplace_back(mCurve);
				//for (u64 j = 0; j < mChoseSeedsSize; j++)
				//{
				//	int rnd = 1 + rand() % (mBoundCoeffs - 1);
				//	EccNumber ci(mCurve, rnd);
				//	g_r[i] = g_r[i] + pG_seeds[indices[j]] * ci; //g^sum
				//}
			}
		}

		gTimer.setTimePoint("HDD g^ri done");
		std::cout << gTimer << "\n";

#ifdef DOUBLE-CHECK
		int cnt = 0;
		std::vector<string> checkUnique;

		for (u64 i = 0; i < mMyInputSize; i++)
		{
			u8* temp = new u8[g_r[i].sizeBytes()];
			g_r[i].toBytes(temp);

			string str_sum = arrU8toString(temp, g_r[i].sizeBytes());

			if (std::find(checkUnique.begin(), checkUnique.end(), str_sum) == checkUnique.end())
				checkUnique.push_back(str_sum);
			else
			{
				std::cout << "dupl. : " << str_sum << "\n";
				cnt++;
			}
		}
		std::cout << "cnt= " << cnt << "\t checkUnique.size()= " << checkUnique.size() << "\n\n";

#endif // DOUBLE-CHECK


		}

		//////============recursive h=2 HSS g^ri==========
		{
			gTimer.reset();
			gTimer.setTimePoint("Recursive h=2 HSS g^ri starts");

			std::vector<RecExpParams> mSeqParams;
			getBestH1RecurrExpParams(mMyInputSize, mSeqParams);

			std::vector<unsigned char*> nSeeds; //level
			std::vector<std::vector<unsigned char*>> pG_seeds(mSeqParams.size() + 1);
			nSeeds.resize(mSeqParams[0].numSeeds);
			pG_seeds[0].resize(mSeqParams[0].numSeeds);


			//seeds
			for (u64 i = 0; i < mSeqParams[0].numSeeds; i++)
			{
				// get a random value from Z_p
				nSeeds[i] = new unsigned char[crypto_core_ristretto255_SCALARBYTES];
				crypto_core_ristretto255_scalar_random(nSeeds[i]);

				pG_seeds[0][i] = new unsigned char[crypto_core_ristretto255_BYTES];;  //g^ri
				crypto_scalarmult_ristretto255_base(pG_seeds[0][i], nSeeds[i]);

			}
			gTimer.setTimePoint("Recursive h=2 HSS g^seed done");



			for (int idxLvl = 0; idxLvl < mSeqParams.size(); idxLvl++)
			{
				std::vector<u64> indices(mSeqParams[idxLvl].numSeeds);

				bool isLast = (idxLvl + 1 == mSeqParams.size());
				int numNextLvlSeed;

				if (isLast)
					numNextLvlSeed = mSeqParams[idxLvl].numNewSeeds;
				else
					numNextLvlSeed = mSeqParams[idxLvl + 1].numSeeds;

				pG_seeds[idxLvl + 1].resize(numNextLvlSeed);

				for (u64 i = 0; i < numNextLvlSeed; i++)
				{

					if (numNextLvlSeed < (1 << 9))
					{
						std::iota(indices.begin(), indices.end(), 0);
						std::random_shuffle(indices.begin(), indices.end()); //random permutation and get 1st K indices
					}
					else
					{
						indices.resize(0);
						while (indices.size() < mSeqParams[idxLvl].numChosen)
						{
							int rnd = rand() % mSeqParams[idxLvl].numSeeds;
							if (std::find(indices.begin(), indices.end(), rnd) == indices.end())
								indices.push_back(rnd);
						}
					}

					pG_seeds[idxLvl + 1][0] =  new unsigned char[crypto_core_ristretto255_BYTES];
					pG_seeds[idxLvl + 1][0] = pG_seeds[idxLvl][indices[0]];

					for (u64 j = 1; j < mSeqParams[idxLvl].numChosen; j++)
					{
						pG_seeds[idxLvl + 1][i] = new unsigned char[crypto_core_ristretto255_BYTES] {};

						crypto_core_ristretto255_add(pG_seeds[idxLvl + 1][i], pG_seeds[idxLvl + 1][i], pG_seeds[idxLvl][indices[j]]); //g^sum //h=2   ci=1
					}
				}
			}


			gTimer.setTimePoint("Recursive h=2 HDD g^ri done");
			std::cout << gTimer << "\n";

#ifdef DOUBLE-CHECK
			int lvlLast = mSeqParams.size();
			int cnt = 0;
			std::vector<string> checkUnique;

			for (u64 i = 0; i < mMyInputSize; i++)
			{
				u8* temp = new u8[pG_seeds[lvlLast][i].sizeBytes()];
				pG_seeds[lvlLast][i].toBytes(temp);

				string str_sum = arrU8toString(temp, pG_seeds[lvlLast][i].sizeBytes());

				if (std::find(checkUnique.begin(), checkUnique.end(), str_sum) == checkUnique.end())
					checkUnique.push_back(str_sum);
				else
				{
					std::cout << "dupl. : " << str_sum << "\n";
					cnt++;
				}
			}
			std::cout << "cnt= " << cnt << "\t checkUnique.size()= " << checkUnique.size() << "\n\n";

			/*	for (int i = 0; i < checkUnique.size(); i++)
			{
			std::cout << "checkUnique. : " << checkUnique[i] << "\n";

			}*/
#endif	
		}

		//////============recursive h>2 HSS g^ri==========
		{
			gTimer.reset();
			gTimer.setTimePoint("Recursive h>2 HSS g^ri starts");

			std::vector<RecExpParams> mSeqParams;
			getBestRecurrExpParams(mMyInputSize, mSeqParams);

			std::vector<unsigned char*> nSeeds; //level
			std::vector<std::vector<unsigned char*>> pG_seeds(mSeqParams.size() + 1);
			nSeeds.resize(mSeqParams[0].numSeeds);
			pG_seeds[0].resize(mSeqParams[0].numSeeds);


			//seeds
			for (u64 i = 0; i < mSeqParams[0].numSeeds; i++)
			{
				// get a random value from Z_p
				nSeeds[i] = new unsigned char[crypto_core_ristretto255_SCALARBYTES];
				crypto_core_ristretto255_scalar_random(nSeeds[i]);

				pG_seeds[0][i] = new unsigned char[crypto_core_ristretto255_BYTES];;  //g^ri
				crypto_scalarmult_ristretto255_base(pG_seeds[0][i], nSeeds[i]);
			}
			gTimer.setTimePoint("Recursive h>2 HSS g^seed done");



			for (int idxLvl = 0; idxLvl < mSeqParams.size(); idxLvl++)
			{
				std::vector<u64> indices(mSeqParams[idxLvl].numSeeds);

				bool isLast = (idxLvl + 1 == mSeqParams.size());
				int numNextLvlSeed;

				if (isLast)
					numNextLvlSeed = mSeqParams[idxLvl].numNewSeeds;
				else
					numNextLvlSeed = mSeqParams[idxLvl + 1].numSeeds;

				pG_seeds[idxLvl + 1].resize(numNextLvlSeed);

				for (u64 i = 0; i < numNextLvlSeed; i++)
				{
					//std::iota(indices.begin(), indices.end(), 0);
					//std::random_shuffle(indices.begin(), indices.end()); //random permutation and get 1st K indices

					if (numNextLvlSeed < (1 << 9))
					{
						std::iota(indices.begin(), indices.end(), 0);
						std::random_shuffle(indices.begin(), indices.end()); //random permutation and get 1st K indices
					}
					else
					{
						indices.resize(0);
						while (indices.size() < mSeqParams[idxLvl].numChosen)
						{
							int rnd = rand() % mSeqParams[idxLvl].numSeeds;
							if (std::find(indices.begin(), indices.end(), rnd) == indices.end())
								indices.push_back(rnd);
						}
					}



					if (mSeqParams[idxLvl].boundCoeff == 2)
						for (u64 j = 0; j < mSeqParams[idxLvl].numChosen; j++)
						{
							pG_seeds[idxLvl + 1][i] = new unsigned char[crypto_core_ristretto255_BYTES] {};
							crypto_core_ristretto255_add(pG_seeds[idxLvl + 1][i], pG_seeds[idxLvl + 1][i], pG_seeds[idxLvl][indices[j]]); //g^sum //h=2   ci=1
						}
					else if (mSeqParams[idxLvl].boundCoeff == (1 << 2))
					{

						std::cout << "mBoundCoeffs Don't support\n";
						throw std::runtime_error("rt error at " LOCATION);

						//for (u64 j = 0; j < mSeqParams[idxLvl].numChosen; j++)
						//{
						//	int ci = 1 + rand() % (mSeqParams[idxLvl].boundCoeff - 1);

						//	for (u64 idxRep = 0; idxRep < ci; idxRep++) //repeat ci time
						//	{
						//		pG_seeds[idxLvl + 1][i] = pG_seeds[idxLvl + 1][i] + pG_seeds[idxLvl][indices[j]]; // (g^ri)^ci
						//	}

						//}
					}
					else
					{
						std::cout << "mBoundCoeffs Don't support\n";
						throw std::runtime_error("rt error at " LOCATION);

						//for (u64 j = 0; j < mSeqParams[idxLvl].numChosen; j++)
						//{
						//	//need <2^104 but implemnt 2^128
						//	int rnd = rand() % mSeqParams[idxLvl].boundCoeff;
						//	EccNumber ci(mCurve, prng);
						//	pG_seeds[idxLvl + 1][i] = pG_seeds[idxLvl + 1][i] + pG_seeds[idxLvl][indices[j]] * ci; //\sum g^ri
						//}
					}

				}
			}


			gTimer.setTimePoint("Recursive h>2 HDD g^ri done");
			std::cout << gTimer << "\n";

			//#ifdef DOUBLE-CHECK
#if 0
			int lvlLast = mSeqParams.size();

			std::cout << "pG_seeds[lvlLast].size()=" << pG_seeds[lvlLast].size() << "\n";

			int cnt = 0;
			std::vector<string> checkUnique;

			for (u64 i = 0; i < mMyInputSize; i++)
			{
				u8* temp = new u8[pG_seeds[lvlLast][i].sizeBytes()];
				pG_seeds[lvlLast][i].toBytes(temp);

				string str_sum = arrU8toString(temp, pG_seeds[lvlLast][i].sizeBytes());

				if (std::find(checkUnique.begin(), checkUnique.end(), str_sum) == checkUnique.end())
					checkUnique.push_back(str_sum);
				else
				{
					std::cout << "dupl. : " << str_sum << "\n";
					cnt++;
				}
			}
			std::cout << "cnt= " << cnt << "\t checkUnique.size()= " << checkUnique.size() << "\n\n";

			/*	for (int i = 0; i < checkUnique.size(); i++)
			{
			std::cout << "checkUnique. : " << checkUnique[i] << "\n";

			}*/
#endif	
		}

	}


#pragma region psi_elligator


#if 1
	static const ropo_fe25519 A = {
  486662, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};

	static const ropo_fe25519 SqrtM1 = {
  -32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654,
  326686, 11406482,
	};

	// sqrtMinusA is sqrt(-486662)
	static const ropo_fe25519 sqrtMinusA = {
	  12222970, 8312128, 11511410, -9067497, 15300785, 241793, -25456130, -14121551,
	  12187136, -3972024
	};

	// sqrtMinusHalf is sqrt(-1/2)
	static const ropo_fe25519 sqrtMinusHalf = {
	  -17256545, 3971863, 28865457, -1750208, 27359696, -16640980, 12573105,
	  1002827, -163343, 11073975,
	};

	// halfQMinus1Bytes is (2^255-20)/2 expressed in little endian form.
	static const uint8_t halfQMinus1Bytes[32] = {
	  0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0x3f
	};

	//inline void* (* volatile memset_volatile)(void*, int, size_t) = std::memset;

	// feBytesLess returns one if a <= b and zero otherwise.
	static inline  unsigned int feBytesLE(const uint8_t(&a)[32],
		const uint8_t(&b)[32]) {
		int32_t equalSoFar = -1;  /* equalSoFar := int32(-1) */
		int32_t greater = 0;      /* greater := int32(0) */

		for (size_t i = 31; i < 32; i--) {
			int32_t x = static_cast<int32_t>(a[i]); /* x := int32(a[i]) */
			int32_t y = static_cast<int32_t>(b[i]); /* y := int32(b[i]) */

			greater = (~equalSoFar & greater) | (equalSoFar & ((x - y) >> 31));
			equalSoFar = equalSoFar & (((x ^ y) - 1) >> 31);
		}

		return static_cast<unsigned int>(~equalSoFar & 1 & greater);
	}

	// q58 calculates out = z^((p-5)/8).
	static inline void q58(ropo_fe25519& out,
		const ropo_fe25519& z) {
		ropo_fe25519 t1, t2, t3;  /* var t1, t2, t3 edwards25519.FieldElement */
		int i;                    /* var i int */

		ropo_fe25519_sq(t1, z);           /* edwards25519.FeSquare(&t1, z) // 2^1 */
		ropo_fe25519_mul(t1, t1, z);          /* edwards25519.FeMul(&t1, &t1, z) // 2^1 + 2^0 */
		ropo_fe25519_sq(t1, t1);            /* edwards25519.FeSquare(&t1, &t1) // 2^2 + 2^1 */
		ropo_fe25519_sq(t2, t1);          /* edwards25519.FeSquare(&t2, &t1) // 2^3 + 2^2 */
		ropo_fe25519_sq(t2, t2);            /* edwards25519.FeSquare(&t2, &t2) // 2^4 + 2^3 */
		ropo_fe25519_mul(t2, t2, t1);         /* edwards25519.FeMul(&t2, &t2, &t1) // 4,3,2,1 */
		ropo_fe25519_mul(t1, t2, z);      /* edwards25519.FeMul(&t1, &t2, z) // 4..0 */
		ropo_fe25519_sq(t2, t1);          /* edwards25519.FeSquare(&t2, &t1) // 5..1 */
		for (i = 1; i < 5; i++) { // 9,8,7,6,5
			ropo_fe25519_sq(t2, t2);          /* edwards25519.FeSquare(&t2, &t2) */
		}
		ropo_fe25519_mul(t1, t1, t2);         /* edwards25519.FeMul(&t1, &t2, &t1) // 9,8,7,6,5,4,3,2,1,0 */
		ropo_fe25519_sq(t2, t1);          /* edwards25519.FeSquare(&t2, &t1) // 10..1 */
		for (i = 1; i < 10; i++) { // 19..10 
			ropo_fe25519_sq(t2, t2);          /*edwards25519.FeSquare(&t2, &t2) */
		}
		ropo_fe25519_mul(t2, t2, t1);         /* edwards25519.FeMul(&t2, &t2, &t1) // 19..0 */
		ropo_fe25519_sq(t3, t2);          /* edwards25519.FeSquare(&t3, &t2) // 20..1 */
		for (i = 1; i < 20; i++) { // 39..20
			ropo_fe25519_sq(t3, t3);          /* edwards25519.FeSquare(&t3, &t3) */
		}
		ropo_fe25519_mul(t2, t2, t3);         /* edwards25519.FeMul(&t2, &t3, &t2) // 39..0 */
		ropo_fe25519_sq(t2, t2);            /* edwards25519.FeSquare(&t2, &t2) // 40..1 */
		for (i = 1; i < 10; i++) { // 49..10
			ropo_fe25519_sq(t2, t2);          /* edwards25519.FeSquare(&t2, &t2) */
		}
		ropo_fe25519_mul(t1, t1, t2);         /* edwards25519.FeMul(&t1, &t2, &t1) // 49..0 */
		ropo_fe25519_sq(t2, t1);          /* edwards25519.FeSquare(&t2, &t1) // 50..1 */
		for (i = 1; i < 50; i++) { // 99..50
			ropo_fe25519_sq(t2, t2);          /* edwards25519.FeSquare(&t2, &t2) */
		}
		ropo_fe25519_mul(t2, t2, t1);         /* edwards25519.FeMul(&t2, &t2, &t1) // 99..0 */
		ropo_fe25519_sq(t3, t2);          /* edwards25519.FeSquare(&t3, &t2) // 100..1 */
		for (i = 1; i < 100; i++) { // 199..100
			ropo_fe25519_sq(t3, t3);          /* edwards25519.FeSquare(&t3, &t3) */
		}
		ropo_fe25519_mul(t2, t2, t3);         /* edwards25519.FeMul(&t2, &t3, &t2) // 199..0 */
		ropo_fe25519_sq(t2, t2);            /* edwards25519.FeSquare(&t2, &t2) // 200..1 */
		for (i = 1; i < 50; i++) { // 249..50
			ropo_fe25519_sq(t2, t2);          /* edwards25519.FeSquare(&t2, &t2) */
		}
		ropo_fe25519_mul(t1, t1, t2);         /* edwards25519.FeMul(&t1, &t2, &t1) // 249..0 */
		ropo_fe25519_sq(t1, t1);            /* edwards25519.FeSquare(&t1, &t1) // 250..1 */
		ropo_fe25519_sq(t1, t1);            /* edwards25519.FeSquare(&t1, &t1) // 251..2 */
		ropo_fe25519_mul(out, t1, z);     /* edwards25519.FeMul(out, &t1, z) // 251..2,0 */
	}


	// chi calculates out = z^((p-1)/2). The result is either 1, 0, or -1 depending
	// on whether z is a non-zero square, zero, or a non-square.
	static inline void chi(ropo_fe25519& out, const ropo_fe25519& z) {
		ropo_fe25519 t0, t1, t2, t3;
		int i;

		ropo_fe25519_sq(t0, z);         /* edwards25519.FeSquare(&t0, z) // 2^1 */
		ropo_fe25519_mul(t1, t0, z);    /* edwards25519.FeMul(&t1, &t0, z) // 2^1 + 2^0 */
		ropo_fe25519_sq(t0, t1);        /* edwards25519.FeSquare(&t0, &t1) // 2^2 + 2^1 */
		ropo_fe25519_sq(t2, t0);        /* edwards25519.FeSquare(&t2, &t0) // 2^3 + 2^2 */
		ropo_fe25519_sq(t2, t2);          /* edwards25519.FeSquare(&t2, &t2) // 4,3 */
		ropo_fe25519_mul(t2, t2, t0);       /* edwards25519.FeMul(&t2, &t2, &t0) // 4,3,2,1 */
		ropo_fe25519_mul(t1, t2, z);    /* edwards25519.FeMul(&t1, &t2, z) // 4..0 */
		ropo_fe25519_sq(t2, t1);        /* edwards25519.FeSquare(&t2, &t1) // 5..1 */
		for (i = 1; i < 5; i++) { // 9,8,7,6,5
			ropo_fe25519_sq(t2, t2);          /* edwards25519.FeSquare(&t2, &t2) */
		}
		ropo_fe25519_mul(t1, t1, t2);       /* edwards25519.FeMul(&t1, &t2, &t1) // 9,8,7,6,5,4,3,2,1,0 */
		ropo_fe25519_sq(t2, t1);        /* edwards25519.FeSquare(&t2, &t1) // 10..1 */
		for (i = 1; i < 10; i++) { // 19..10
			ropo_fe25519_sq(t2, t2);          /* edwards25519.FeSquare(&t2, &t2) */
		}
		ropo_fe25519_mul(t2, t2, t1);       /* edwards25519.FeMul(&t2, &t2, &t1) // 19..0 */
		ropo_fe25519_sq(t3, t2);        /* edwards25519.FeSquare(&t3, &t2) // 20..1 */
		for (i = 1; i < 20; i++) { // 39..20
			ropo_fe25519_sq(t3, t3);          /* edwards25519.FeSquare(&t3, &t3) */
		}
		ropo_fe25519_mul(t2, t2, t3);       /* edwards25519.FeMul(&t2, &t3, &t2) // 39..0 */
		ropo_fe25519_sq(t2, t2);          /* edwards25519.FeSquare(&t2, &t2) // 40..1 */
		for (i = 1; i < 10; i++) { // 49..10
			ropo_fe25519_sq(t2, t2);          /* edwards25519.FeSquare(&t2, &t2) */
		}
		ropo_fe25519_mul(t1, t1, t2);       /* edwards25519.FeMul(&t1, &t2, &t1) // 49..0 */
		ropo_fe25519_sq(t2, t1);        /* edwards25519.FeSquare(&t2, &t1) // 50..1 */
		for (i = 1; i < 50; i++) { // 99..50
			ropo_fe25519_sq(t2, t2);          /* edwards25519.FeSquare(&t2, &t2) */
		}
		ropo_fe25519_mul(t2, t2, t1);       /* edwards25519.FeMul(&t2, &t2, &t1) // 99..0 */
		ropo_fe25519_sq(t3, t2);        /* edwards25519.FeSquare(&t3, &t2) // 100..1 */
		for (i = 1; i < 100; i++) { // 199..100
			ropo_fe25519_sq(t3, t3);          /*edwards25519.FeSquare(&t3, &t3) */
		}
		ropo_fe25519_mul(t2, t2, t3);       /* edwards25519.FeMul(&t2, &t3, &t2) // 199..0 */
		ropo_fe25519_sq(t2, t2);          /* edwards25519.FeSquare(&t2, &t2) // 200..1 */
		for (i = 1; i < 50; i++) { // 249..50
			ropo_fe25519_sq(t2, t2);          /* edwards25519.FeSquare(&t2, &t2) */
		}
		ropo_fe25519_mul(t1, t1, t2);       /* edwards25519.FeMul(&t1, &t2, &t1) // 249..0 */
		ropo_fe25519_sq(t1, t1);          /* edwards25519.FeSquare(&t1, &t1) // 250..1 */
		for (i = 1; i < 4; i++) { // 253..4
			ropo_fe25519_sq(t1, t1);          /* edwards25519.FeSquare(&t1, &t1) */
		}
		ropo_fe25519_mul(out, t1, t0);  /* edwards25519.FeMul(out, &t1, &t0) // 253..4,2,1 */
	}


	bool inline ScalarBaseMult2(unsigned char* publicKey,
		unsigned char* representative,
		const unsigned char* privateKey) {

		unsigned char* AAbytes = new unsigned char[crypto_core_ristretto255_BYTES];

		ropo_ge25519_p3 AA;           /* var A edwards25519.ExtendedGroupElement */

		crypto_scalarmult_ristretto255_base(AAbytes, privateKey);

		//unsigned char* t = new unsigned char[crypto_core_ristretto255_BYTES];
		//for (unsigned int i = 0; i < 32; ++i) {
		//	t[i] = privateKey[i];
		//}
		//t[31] &= 127;

		//ge25519_p3     Q;
		//ge25519_scalarmult_base(&Q, t);

		/*std::cout << toBlock((u8*)AAbytes) << "\t AAbytes\n";
		std::cout << toBlock((u8*)privateKey) << "\t privateKey\n";*/
		ropo_ge25519_frombytes(&AA, AAbytes);

		ropo_fe25519 inv1;
		ropo_fe25519_sub(inv1, AA.Z, AA.Y); /* edwards25519.FeSub(&inv1, &A.Z, &A.Y) */
		ropo_fe25519_mul(inv1, inv1, AA.X); /* edwards25519.FeMul(&inv1, &inv1, &A.X) */
		ropo_fe25519_invert(inv1, inv1);   /* edwards25519.FeInvert(&inv1, &inv1) */

		ropo_fe25519 t0, u;
		ropo_fe25519_mul(u, inv1, AA.X);  /* edwards25519.FeMul(&u, &inv1, &A.X) */
		ropo_fe25519_add(t0, AA.Y, AA.Z); /* edwards25519.FeAdd(&t0, &A.Y, &A.Z) */
		ropo_fe25519_mul(u, u, t0);          /* edwards25519.FeMul(&u, &u, &t0) */

		ropo_fe25519 v;
		ropo_fe25519_mul(v, t0, inv1);    /* edwards25519.FeMul(&v, &t0, &inv1) */
		ropo_fe25519_mul(v, v, AA.Z);        /* edwards25519.FeMul(&v, &v, &A.Z) */
		ropo_fe25519_mul(v, v, sqrtMinusA);  /* edwards25519.FeMul(&v, &v, &sqrtMinusA) */

		ropo_fe25519 b;
		ropo_fe25519_add(b, u, A);        /* edwards25519.FeAdd(&b, &u, &edwards25519.A) */

		ropo_fe25519 c, b3, b8;
		ropo_fe25519_sq(b3, b);           /* edwards25519.FeSquare(&b3, &b) // 2 */
		ropo_fe25519_mul(b3, b3, b);          /* edwards25519.FeMul(&b3, &b3, &b) // 3 */
		ropo_fe25519_sq(c, b3);           /* edwards25519.FeSquare(&c, &b3) // 6 */
		ropo_fe25519_mul(c, c, b);           /* edwards25519.FeMul(&c, &c, &b) // 7 */
		ropo_fe25519_mul(b8, c, b);       /* edwards25519.FeMul(&b8, &c, &b) // 8 */
		ropo_fe25519_mul(c, c, u);           /* edwards25519.FeMul(&c, &c, &u) */
		q58(c, c);          /* q58(&c, &c) */

		ropo_fe25519 chi;
		ropo_fe25519_sq(chi, c);          /* edwards25519.FeSquare(&chi, &c) */
		ropo_fe25519_sq(chi, chi);           /* edwards25519.FeSquare(&chi, &chi) */

		ropo_fe25519_sq(t0, u);           /* edwards25519.FeSquare(&t0, &u) */
		ropo_fe25519_mul(chi, chi, t0);        /* edwards25519.FeMul(&chi, &chi, &t0) */

		ropo_fe25519_sq(t0, b);           /* edwards25519.FeSquare(&t0, &b) // 2 */
		ropo_fe25519_mul(t0, t0, b);          /* edwards25519.FeMul(&t0, &t0, &b) // 3 */
		ropo_fe25519_sq(t0, t0);            /* edwards25519.FeSquare(&t0, &t0) // 6 */
		ropo_fe25519_mul(t0, t0, b);          /* edwards25519.FeMul(&t0, &t0, &b) // 7 */
		ropo_fe25519_sq(t0, t0);            /* edwards25519.FeSquare(&t0, &t0) // 14 */
		ropo_fe25519_mul(chi, chi, t0);        /* edwards25519.FeMul(&chi, &chi, &t0) */
		ropo_fe25519_neg(chi, chi);          /* edwards25519.FeNeg(&chi, &chi) */

		uint8_t chiBytes[32];
		ropo_fe25519_tobytes(chiBytes, chi);  /*edwards25519.FeToBytes(&chiBytes, &chi) */
		// chi[1] is either 0 or 0xff
		if (chiBytes[1] == 0xff) {
			return false;
		}

		// Calculate r1 = sqrt(-u/(2*(u+A)))
		ropo_fe25519 r1;
		ropo_fe25519_mul(r1, c, u);       /* edwards25519.FeMul(&r1, &c, &u) */
		ropo_fe25519_mul(r1, r1, b3);         /* edwards25519.FeMul(&r1, &r1, &b3) */
		ropo_fe25519_mul(r1, r1, sqrtMinusHalf);  /* edwards25519.FeMul(&r1, &r1, &sqrtMinusHalf) */

		ropo_fe25519 maybeSqrtM1;
		ropo_fe25519_sq(t0, r1);          /* edwards25519.FeSquare(&t0, &r1) */
		ropo_fe25519_mul(t0, t0, b);          /* edwards25519.FeMul(&t0, &t0, &b) */
		ropo_fe25519_add(t0, t0, t0);         /* edwdfards25519.FeAdd(&t0, &t0, &t0) */
		ropo_fe25519_add(t0, t0, u);          /* edwards25519.FeAdd(&t0, &t0, &u) */

		ropo_fe25519_1(maybeSqrtM1);  /* edwards25519.FeOne(&maybeSqrtM1) */
		ropo_fe25519_cmov(maybeSqrtM1, SqrtM1, !ropo_fe25519_iszero(t0)); /* edwards25519.FeCMove(&maybeSqrtM1, &edwards25519.SqrtM1, edwards25519.FeIsNonZero(&t0)) */
		ropo_fe25519_mul(r1, r1, maybeSqrtM1);/* edwards25519.FeMul(&r1, &r1, &maybeSqrtM1) */

		// Calculate r = sqrt(-(u+A)/(2u))
		ropo_fe25519 r;
		ropo_fe25519_sq(t0, c);           /* edwards25519.FeSquare(&t0, &c) // 2 */
		ropo_fe25519_mul(t0, t0, c);          /* edwards25519.FeMul(&t0, &t0, &c) // 3 */
		ropo_fe25519_sq(t0, t0);            /* edwards25519.FeSquare(&t0, &t0) // 6 */
		ropo_fe25519_mul(r, t0, c);       /* edwards25519.FeMul(&r, &t0, &c) // 7 */

		ropo_fe25519_sq(t0, u);           /* edwards25519.FeSquare(&t0, &u) // 2 */
		ropo_fe25519_sq(t0, u);          /* edwards25519.FeMul(&t0, &t0, &u) // 3 */
		ropo_fe25519_mul(r, r, t0);          /* edwards25519.FeMul(&r, &r, &t0) */

		ropo_fe25519_sq(t0, b8);          /* edwards25519.FeSquare(&t0, &b8) // 16 */
		ropo_fe25519_mul(t0, t0, b8);         /* edwards25519.FeMul(&t0, &t0, &b8) // 24 */
		ropo_fe25519_mul(t0, t0, b);          /* edwards25519.FeMul(&t0, &t0, &b) // 25 */
		ropo_fe25519_mul(r, r, t0);          /* edwards25519.FeMul(&r, &r, &t0) */
		ropo_fe25519_mul(r, r, sqrtMinusHalf); /* edwards25519.FeMul(&r, &r, &sqrtMinusHalf) */

		ropo_fe25519_sq(t0, r);           /* edwards25519.FeSquare(&t0, &r) */
		ropo_fe25519_mul(t0, t0, u);          /* edwards25519.FeMul(&t0, &t0, &u) */
		ropo_fe25519_add(t0, t0, t0);         /* edwards25519.FeAdd(&t0, &t0, &t0) */
		ropo_fe25519_add(t0, t0, b);          /* edwards25519.FeAdd(&t0, &t0, &b) */
		ropo_fe25519_1(maybeSqrtM1);  /* edwards25519.FeOne(&maybeSqrtM1) */
		ropo_fe25519_cmov(maybeSqrtM1, SqrtM1, !ropo_fe25519_iszero(t0)); /* edwards25519.FeCMove(&maybeSqrtM1, &edwards25519.SqrtM1, edwards25519.FeIsNonZero(&t0)) */
		ropo_fe25519_mul(r, r, maybeSqrtM1); /* edwards25519.FeMul(&r, &r, &maybeSqrtM1) */

		uint8_t vBytes[32];
		ropo_fe25519_tobytes(vBytes, v);  /* edwards25519.FeToBytes(&vBytes, &v) */
		unsigned int vInSquareRootImage = feBytesLE(vBytes, halfQMinus1Bytes); /* vInSquareRootImage := feBytesLE(&vBytes, &halfQMinus1Bytes) */
		ropo_fe25519_cmov(r, r1, vInSquareRootImage); /* edwards25519.FeCMove(&r, &r1, vInSquareRootImage) */

		/* 5.5: Here |b| means b if b in {0, 1, ..., (q - 1)/2}, otherwise -b. */
		uint8_t rBytes[32];
		ropo_fe25519_tobytes(rBytes, r);
		unsigned int negateB = (1 & ~feBytesLE(rBytes, halfQMinus1Bytes));
		ropo_fe25519_neg(r1, r);
		ropo_fe25519_cmov(r, r1, negateB);

		ropo_fe25519_tobytes(publicKey, u); /* edwards25519.FeToBytes(publicKey, &u) */
		ropo_fe25519_tobytes(representative, r);  /* edwards25519.FeToBytes(representative, &r) */
		return true;
	}

	// RepresentativeToPublicKey converts a uniform representative value for a
// curve25519 public key, as produced by ScalarBaseMult, to a curve25519 public
// key.
	inline void  RepresentativeToPublicKey2(unsigned char* publicKey,
		const unsigned char* representative) {
		ropo_fe25519 rr2, v, e;
		ropo_fe25519_frombytes(rr2, representative);  /* edwards25519.FeFromBytes(&rr2, representative) */

		ropo_fe25519_sq2(rr2, rr2);     /* edwards25519.FeSquare2(&rr2, &rr2) */
		rr2[0]++;         /* rr2[0]++ */
		ropo_fe25519_invert(rr2, rr2);     /* edwards25519.FeInvert(&rr2, &rr2) */
		ropo_fe25519_mul(v, A, rr2);    /* edwards25519.FeMul(&v, &edwards25519.A, &rr2) */
		ropo_fe25519_neg(v, v);          /* edwards25519.FeNeg(&v, &v) */

		ropo_fe25519 v2, v3;
		ropo_fe25519_sq(v2, v);         /* edwards25519.FeSquare(&v2, &v) */
		ropo_fe25519_mul(v3, v, v2);    /* edwards25519.FeMul(&v3, &v, &v2) */
		ropo_fe25519_add(e, v3, v);     /* edwards25519.FeAdd(&e, &v3, &v) */
		ropo_fe25519_mul(v2, v2, A);        /* edwards25519.FeMul(&v2, &v2, &edwards25519.A) */
		ropo_fe25519_add(e, e, v2);        /* edwards25519.FeAdd(&e, &v2, &e) */
		chi(e, e);        /* chi(&e, &e) */
		uint8_t eBytes[32];
		ropo_fe25519_tobytes(eBytes, e);  /* edwards25519.FeToBytes(&eBytes, &e) */
		// eBytes[1] is either 0 (for e = 1) or 0xff (for e = -1)
		unsigned int eIsMinus1 = eBytes[1] & 1;
		ropo_fe25519 negV;
		ropo_fe25519_neg(negV, v);      /* edwards25519.FeNeg(&negV, &v) */
		ropo_fe25519_cmov(v, negV, eIsMinus1);  /* edwards25519.FeCMove(&v, &negV, eIsMinus1) */

		ropo_fe25519_0(v2);              /* edwards25519.FeZero(&v2) */
		ropo_fe25519_cmov(v2, A, eIsMinus1);  /* edwards25519.FeCMove(&v2, &edwards25519.A, eIsMinus1) */
		ropo_fe25519_sub(v, v, v2);           /* edwards25519.FeSub(&v, &v, &v2) */


#if 0

		/* yed = (x-1)/(x+1) */
		{
			ropo_fe25519 one;
			ropo_fe25519 x_plus_one;
			ropo_fe25519 x_plus_one_inv;
			ropo_fe25519 x_minus_one;
			ropo_fe25519 yed;

			ropo_fe25519_1(one);
			ropo_fe25519_add(x_plus_one, v, one);
			ropo_fe25519_sub(x_minus_one, v, one);
			ropo_fe25519_invert(x_plus_one_inv, x_plus_one);
			ropo_fe25519_mul(yed, x_minus_one, x_plus_one_inv);
			ropo_fe25519_tobytes(publicKey, yed);
		}

		unsigned char x_sign;

		x_sign = publicKey[31] & 0x80;
		publicKey[31] &= 0x7f;

		/* recover x */
		ropo_ge25519_p3   p3;

		publicKey[31] |= x_sign;
		if (ropo_ge25519_frombytes(&p3, publicKey) != 0) {
			std::cout << "ropo_ge25519_frombytes(&p3, publicKey)\n";

			abort(); /* LCOV_EXCL_LINE */
		}

		//unsigned char x_sign = pk1[31] & 0x80;
		//pk1[31] &= 0x7f;

		///* recover x */
		//pk1[31] |= x_sign;


		unsigned char k[crypto_core_ristretto255_SCALARBYTES];
		crypto_core_ristretto255_scalar_random(k);
		unsigned char b[crypto_core_ristretto255_BYTES];

		//g^s^k
		if (crypto_scalarmult_ristretto255(b, k, publicKey) != 0) {
			std::cout << "crypto_scalarmult_ristretto255(b, k, publicKey) != 0\n";
			//return -1;
		}
#endif

		ropo_fe25519_tobytes(publicKey, v); /* edwards25519.FeToBytes(publicKey, &v) */
	}
#endif

#pragma endregion


	inline void Ristretto_curveRoPOTimming()
	{
		ropo_fe25519 one;
		ropo_fe25519_1(one);
		int numTrial = 10000;
		int total_iter = 0;
		unsigned char r[crypto_core_ristretto255_SCALARBYTES]; //g^r
		unsigned char gr[crypto_core_ristretto255_BYTES];
		unsigned char* gr_recovered = new unsigned char[crypto_core_ristretto255_BYTES];

		//==================G->2^F->F->G
		gTimer.reset();
		gTimer.setTimePoint("Ristretto_curveRoPOTimming: start");
		for (int iTrial = 0; iTrial < numTrial; iTrial++)
		{
			//std::cout << "\n\n======================\n";
			// choose random g^ri until T^-1(g^ri) !=0
			int iter = 0;
			std::vector<unsigned char*> buffs;
			do {
				buffs.clear();

				crypto_core_ristretto255_scalar_random(r);
				crypto_scalarmult_ristretto255_base(gr, r);
				auto cnt_g2f = ristretto_ropoGroup2Field(gr, buffs, one);
				iter++;
			} while (buffs.size() == 0);

			total_iter += iter;
			//std::cout << " #trial:"  << iter << " buffs.size() : " << buffs.size() << "\n"; 
			//std::cout << toBlock((u8*)&gr) << " orignial point#######\n";

			//std::cout << toBlock((u8*)buffs[buffs.size()-1]) << " buff point#######\n";
			// choose random si from buffs
			//unsigned char* buff = new unsigned char[crypto_core_ristretto255_BYTES];

			int idx = rand() % buffs.size();
			//for (int idx = 0; idx < buffs.size(); idx++)
			{
				//buff = buffs[idx];
				//std::cout << idx << " idx \t" << toBlock((u8*)buffs[idx]) << " buff point#######\n";


				auto cnt_f2g = ristretto_ropoField2Group(buffs[idx], gr_recovered, one);
				//std::cout << toBlock((u8*)gr_recovered) << " recovered point#######\n";
			}
		}
		gTimer.setTimePoint("Ristretto_curveRoPOTimming: end");
		std::cout << gTimer << "\n";

		std::cout << "#trial: " << numTrial << " ========\n";
		std::cout << "#trial to find T: " << total_iter << " ========\n";
	}

	inline void Ristretto_curveElligatorTiming()
	{
		ropo_fe25519 one;
		ropo_fe25519_1(one);
		int numTrial = 10000;
		int total_iter = 0;
		unsigned char r[crypto_core_ristretto255_SCALARBYTES]; //g^r
		unsigned char gr[crypto_core_ristretto255_BYTES];
		unsigned char* gr_recovered = new unsigned char[crypto_core_ristretto255_BYTES];

		//==================G->2^F->F->G
		gTimer.reset();
		gTimer.setTimePoint("Ristretto_curveElligatorTiming: start");
		for (int iTrial = 0; iTrial < numTrial; iTrial++)
		{
			//std::cout << "\n\n======================\n";
			// choose random g^ri until T^-1(g^ri) !=0
			int iter = 0;

			unsigned char pk[crypto_core_ristretto255_BYTES] = {};
			unsigned char representative[crypto_core_ristretto255_BYTES] = {};
			bool success;
			unsigned char* point_ri = new unsigned char[crypto_core_ristretto255_BYTES];

			do {
				success = ScalarBaseMult2(pk, representative, r);
				iter++;
			} while (!success);

			total_iter += iter;

			//std::cout << " #trial:"  << iter << " buffs.size() : " << buffs.size() << "\n"; 
			//std::cout << toBlock((u8*)&gr) << " orignial point#######\n";

			//std::cout << toBlock((u8*)buffs[buffs.size()-1]) << " buff point#######\n";
			// choose random si from buffs
			//unsigned char* buff = new unsigned char[crypto_core_ristretto255_BYTES];

			//int idx = rand() % buffs.size();
			//for (int idx = 0; idx < buffs.size(); idx++)
			{
				//buff = buffs[idx];
				//std::cout << idx << " idx \t" << toBlock((u8*)buffs[idx]) << " buff point#######\n";

				RepresentativeToPublicKey2(point_ri, point_ri);
				//std::cout << toBlock((u8*)gr_recovered) << " recovered point#######\n";
			}
		}
		gTimer.setTimePoint("Ristretto_curveElligatorTiming: end");
		std::cout << gTimer << "\n";
		std::cout << "#trial: " << numTrial << " ========\n";
		std::cout << "#trial to find T: " << total_iter << " ========\n";
	}



	inline void Ristretto_exp_Timming(int numTrial)
	{
		std::vector<unsigned char*> gr_vec(numTrial);
		std::vector<unsigned char*> scalar_b(numTrial);
		std::vector<unsigned char*> grb(numTrial);
		unsigned char r[crypto_core_ristretto255_SCALARBYTES]; //g^r

		for (int i = 0; i < numTrial; i++)
		{
			gr_vec[i] = new unsigned char[crypto_core_ristretto255_BYTES];
			grb[i] = new unsigned char[crypto_core_ristretto255_BYTES];
			scalar_b[i] = new unsigned char[crypto_core_ristretto255_SCALARBYTES];
			crypto_core_ristretto255_scalar_random(scalar_b[i]);
			crypto_core_ristretto255_scalar_random(r);
			crypto_scalarmult_ristretto255_base(gr_vec[i], r);
		}

		//==================compute g^a^b
		gTimer.reset();
		gTimer.setTimePoint("Ristretto_exp_Timming: start");
		for (int i = 0; i< numTrial; i++)
		{
			crypto_scalarmult_ristretto255(grb[i], scalar_b[i], gr_vec[i]);
		}

		gTimer.setTimePoint("Ristretto_exp_Timming: end");
		std::cout << gTimer << "\n";

		std::cout << "#trial: " << numTrial << " ========\n";
	}

}
