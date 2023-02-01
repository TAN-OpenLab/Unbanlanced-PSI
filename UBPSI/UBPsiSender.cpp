#include "UBPsiSender.h"
#include "cryptoTools/Crypto/Curve.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Common/Timer.h"

#include <string>     // std::string, std::to_string

#include "algorithm"  //ning
using namespace std;    //ning
using namespace osuCrypto;    //ning

namespace Tanlab
{

    UBPsiSender::UBPsiSender()
    {
    }


    UBPsiSender::~UBPsiSender()
    {
    }

    void UBPsiSender::sendInput_k283(span<block> inputs, span<Channel> chls)
    {
		
    }

	void UBPsiSender::sendInput_Curve25519(span<block> inputs, span<Channel> chls)
	{
		

	}

	void UBPsiSender::sendInput_Ristretto(span<block> inputs, span<Channel> chls)
	{
		std::cout << "curveParam = Ristretto2\n";

		

			//ning0000000000000000000000000000000000000000000000000000000000

			auto& chl = chls[0];
			gTimer.setTimePoint("离线 start");

  			//u64 inputFieldSize = 1024;
			//u64 SenderSetSize = 256;
			//u64 ReceiverSetSize = 256;

  			u64 inputFieldSize = 1024;
			u64 SenderSetSize = 256;
			u64 ReceiverSetSize = 256;

			std::vector<u8> recvG0(crypto_core_ristretto255_BYTES * inputFieldSize);//种子公钥
			std::vector<u8> recvG1(crypto_core_ristretto255_BYTES * inputFieldSize);//种子公钥
			std::vector<u8> buffG0(crypto_core_ristretto255_BYTES * inputFieldSize);//实际公钥
			std::vector<u8> buffG1(crypto_core_ristretto255_BYTES * inputFieldSize);//实际公钥
			std::vector<u8> recvgt(crypto_core_ristretto255_BYTES);
			std::vector<int> latinS0(inputFieldSize);
			unsigned char* pkG0 = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char* pkG1 = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char* gt = new unsigned char[crypto_core_ristretto255_BYTES];

			//接收种子公钥矩阵第0行recvG0
			chl.recv(recvG0);
			if (recvG0.size() != inputFieldSize*crypto_core_ristretto255_BYTES )
			{
				std::cout << "接收种子公钥矩阵第0行recvG0错误 recvG0.size() = " << recvG0.size()<< std::endl;

				std::cout << "error @ " << (LOCATION) << std::endl;
				throw std::runtime_error(LOCATION);
			}
			//接收种子公钥矩阵第0行recvG0,end

			//接收种子公钥矩阵第1行recvG1
			chl.recv(recvG1);
			if (recvG1.size() != inputFieldSize*crypto_core_ristretto255_BYTES )
			{
				std::cout << "接收种子公钥矩阵第1行recvG1错误 recvG1.size() =" << recvG1.size()<< std::endl;

				std::cout << "error @ " << (LOCATION) << std::endl;
				throw std::runtime_error(LOCATION);
			}
			//接收种子公钥矩阵第1行recvG1,end

			//接收g^t
			chl.recv(recvgt);
			if (recvgt.size() != crypto_core_ristretto255_BYTES)
			{
				std::cout << "接收g^t错误 recvgt.size()= " << recvgt.size()<< std::endl;

				std::cout << "error @ " << (LOCATION) << std::endl;
				throw std::runtime_error(LOCATION);
			}
			//接收g^t,end 

			//调试使用
			unsigned char  gt9[crypto_core_ristretto255_BYTES];/////////
			unsigned char* skt = new unsigned char[crypto_core_ristretto255_SCALARBYTES];

			std::vector<u8> recvskt(crypto_core_ristretto255_SCALARBYTES);
			chl.recv(recvskt);//接收receiver的私钥skt(调试使用)


			memcpy(skt, recvskt.data(), crypto_core_ristretto255_SCALARBYTES);

			unsigned char  skt9[crypto_core_ristretto255_SCALARBYTES];
			memcpy(skt9, skt, crypto_core_ristretto255_SCALARBYTES);
			std::cout<< "skt9 is "<<skt9<<"\n";
			unsigned char gene[crypto_core_ristretto255_BYTES];
			crypto_scalarmult_ristretto255_base(gene, skt);
			std::cout<< "gene is "<<gene<<"\n";//用于观察两方生成元是否相等
			//调试使用,end

			//接收拉丁方S0
			chl.recv(latinS0);
			if (latinS0.size() != inputFieldSize)
			{
				std::cout << "接收拉丁方S0错误, LS.size()= " << latinS0.size()<< std::endl;

				std::cout << "error @ " << (LOCATION) << std::endl;
				throw std::runtime_error(LOCATION);
			}
			std::cout << "接收拉丁方end" <<  std::endl;
			//接收拉丁方end

			//generate latinsquare
			//int LS[inputFieldSize][inputFieldSize];
			//for(int j = 0; j < inputFieldSize; j++)
			//{
			//	LS[0][j] = latinS0[j];
				//std::cout << "latinS0["<<j<<"]=" <<latinS0[j]<< "\n";
				//for(int i = 1; i < inputFieldSize; i++)
				//{
				//	LS[i][j] = (LS[i-1][j]+1) % inputFieldSize;
					//std::cout << "LS["<<i<<"]["<<j<<"]=" <<LS[i][j]<< "\n";
				//}	
			  	//std::cout << "LS[0]["<<j<<"]" << LS[0][j]<<"\n";				
			//} 

			std::cout << "generate latinsquare end" <<  std::endl;
			//generate latinsquare end

			//定义SenderSetX
			std::vector<int> SenderSetX(SenderSetSize);
			std::vector<int> SelectPool(inputFieldSize);
			int randoma;
    			//srand(time(nullptr)); // 用当前时间作为种子
			for(int i = 0; i < inputFieldSize; i++)
			{    
				SelectPool[i] = i;			
			}
			for(int i = 0; i < SenderSetSize; i++)
			{    
				randoma=rand()%(inputFieldSize-i);        
				SenderSetX[i] = SelectPool[randoma];
				SelectPool.erase(SelectPool.begin()+randoma);
				std::cout<< "SenderSetX["<<i<<"]:"<<SenderSetX[i] <<"\n";					
			}
			std::cout << "定义SenderSetX end" <<  std::endl;
			//定义SenderSetX end
			gTimer.setTimePoint("离线结束");
			//接收密文
			std::vector<int> ci(ReceiverSetSize);
			chl.recv(ci);
			if (ci.size() != ReceiverSetSize)
			{
				std::cout << " 接收密文错误ci.size()= " << ci.size()<< std::endl;

				std::cout << "error @ " << (LOCATION) << std::endl;
				throw std::runtime_error(LOCATION);
			}
			//std::cout << "ci[1]=" << ci[1]<< std::endl;
			std::cout << "接收密文end" <<  std::endl;
			//接收密文end

			gTimer.setTimePoint("接收密文结束");
			//生成验证信息
			unsigned char* ei = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char* hi = new unsigned char[crypto_core_ristretto255_BYTES];
			//unsigned char hi[crypto_core_ristretto255_BYTES];
			//unsigned char ei[crypto_core_ristretto255_BYTES];
			unsigned char ei9[crypto_core_ristretto255_BYTES];//////
			unsigned char hi9[crypto_core_ristretto255_BYTES];//////

			//std::vector<u8> sendG0(crypto_core_ristretto255_BYTES * inputFieldSize);
			unsigned char keyr[crypto_core_ristretto255_SCALARBYTES];
			crypto_core_ristretto255_scalar_random(keyr);
			unsigned char* gr = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char* gtr = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char  gtr9[crypto_core_ristretto255_BYTES];/////////
			std::vector<u8> sendei(crypto_core_ristretto255_BYTES * ReceiverSetSize);
			std::vector<u8> sendhi(crypto_core_ristretto255_BYTES * ReceiverSetSize);
			crypto_scalarmult_ristretto255_base(gr, keyr);

			unsigned char hit[crypto_core_ristretto255_BYTES];////////
			unsigned char hit_gv[crypto_core_ristretto255_BYTES];/////////

			for(int i = 0; i < ReceiverSetSize; i++)
			{
				//置换,生成buffG0,buffG1
				for(int j = 0; j < inputFieldSize; j++)
				//for(int j = 0; j < 2; j++)
				{	
					int m=0;
					//for (int k = 0; k<1024; k++)
					//{
						//std::cout << "LS[ci[i]][j]=" << LS[ci[i]][j] <<"\n";
					//	std::cout << "LS[0][k]=" << LS[0][k] <<"\n";
					//}
					int LS_jci = (latinS0[j]+ci[i]) % inputFieldSize;
					while ( LS_jci != latinS0[m])	
					{
						m=m+1;
						//std::cout << "LS[ci[i]][j]=" << LS[ci[i]][j] <<"\n";
						//std::cout << "m=" << m <<"\n";
						//std::cout << "LS[0][m]=" << LS[0][m] <<"\n";
					}
					//std::cout << "j=" << j  << "时,m=" << m <<"\n";		
					memcpy(buffG0.data() + j * crypto_core_ristretto255_BYTES, recvG0.data() + m * crypto_core_ristretto255_BYTES, crypto_core_ristretto255_BYTES);
					memcpy(buffG1.data() + j * crypto_core_ristretto255_BYTES, recvG1.data() + m * crypto_core_ristretto255_BYTES, crypto_core_ristretto255_BYTES);
				}	
				//置换,生成buffG0,buffG1,end

				//生成hi,ei
				memcpy(hi, gr, crypto_core_ristretto255_BYTES);
				memcpy(gt, recvgt.data(), crypto_core_ristretto255_BYTES);
				//memcpy(gt9, recvgt.data(), crypto_core_ristretto255_BYTES);
				//std::cout << "receiver gt is " << gt9 << "\n";
				//std::cout << "receiver gr is " << gr << "\n";

				if (crypto_scalarmult_ristretto255(gtr, keyr, gt) != 0) {

					std::cout << "crypto_scalarmult_ristretto255(gtr, keyr, gt) != 0\n";
					throw std::runtime_error("rt error at " LOCATION);
				}
				memcpy(ei, gtr, crypto_core_ristretto255_BYTES);

				//memcpy(gtr9, gtr, crypto_core_ristretto255_BYTES);
				//std::cout << "receiver gtr is " << gtr << "\n";
				//std::cout << "origin ei="<<ei<<"\n";
				//std::cout << "origin hi="<<hi<<"\n";

				for(int k = 0; k < SenderSetSize; k++)
				{
								
					//memcpy(hi9, buffG0.data() + SenderSetX[k] * crypto_core_ristretto255_BYTES, crypto_core_ristretto255_BYTES);
					//memcpy(ei9, buffG1.data() + SenderSetX[k] * crypto_core_ristretto255_BYTES, crypto_core_ristretto255_BYTES);

					//std::cout << "test  hi9 \n"<<hi9;
					//std::cout << "test  ei9 \n"<<ei9;
					int m=0;
					int same = (latinS0[SenderSetX[k]]+ci[i]) % inputFieldSize;

					while ( latinS0[m] != same)	
					{
						m=m+1;
						//std::cout << "LS[ci[i]][j]=" << LS[ci[i]][j] <<"\n";
						//std::cout << "m=" << m <<"\n";
						//std::cout << "LS[0][m]=" << LS[0][m] <<"\n";
					}
					memcpy(pkG0, recvG0.data() + m * crypto_core_ristretto255_BYTES, crypto_core_ristretto255_BYTES);
					memcpy(pkG1, recvG1.data() + m * crypto_core_ristretto255_BYTES, crypto_core_ristretto255_BYTES);

					//std::cout << "test  pkG0 \n"<<pkG0;
					//std::cout << "test  pkG1 \n"<<pkG1;
					crypto_core_ristretto255_add(hi, hi, pkG0);
					crypto_core_ristretto255_add(ei, ei, pkG1);
	
					
				}
				//生成hi,ei,end	
				

				//调试使用
				//if (crypto_scalarmult_ristretto255(hit, skt, hi) != 0) {

				//	std::cout << "crypto_scalarmult_ristretto255(hit, skt, hi) != 0\n";
				//	throw std::runtime_error("rt error at " LOCATION);
				//}

				//memcpy(hi9, hi, crypto_core_ristretto255_BYTES);
				//memcpy(ei9, ei, crypto_core_ristretto255_BYTES);
				//std::cout << "ei9="<<ei9<<"  sizeof(ei9)="<<sizeof(ei9)<<"\n";
				//std::cout << "hi9="<<hi9<<"  sizeof(hi9)="<<sizeof(hi9)<<"\n";
				//std::cout << "hit="<<hit<<"  sizeof(hit)="<<sizeof(hit)<<"\n";

	
				//std::cout << "ei9[33]="<<ei9[33]<<"  sizeof(ei9)="<<sizeof(ei9)<<"\n";
				//std::cout << "hi9[31]="<<hi9[31]<<"  sizeof(hi9)="<<sizeof(hi9)<<"\n";
				//调试使用,end

				//generate sendei,sendhi
				memcpy(sendhi.data() + i * crypto_core_ristretto255_BYTES, hi, crypto_core_ristretto255_BYTES);
				memcpy(sendei.data() + i * crypto_core_ristretto255_BYTES, ei, crypto_core_ristretto255_BYTES);				
				//generate sendei,sendhi, end

			}
			//生成验证信息,end
			gTimer.setTimePoint("生成验证信息,end");

			//调试使用
			unsigned char item01[crypto_core_ristretto255_BYTES];
			unsigned char item02[crypto_core_ristretto255_BYTES];
			memcpy(item01, sendhi.data() +  crypto_core_ristretto255_BYTES,  crypto_core_ristretto255_BYTES);
			memcpy(item02,sendei.data() +  crypto_core_ristretto255_BYTES, crypto_core_ristretto255_BYTES);
			std::cout<< "item01hi is "<<item01<< "sizeof(item01) is "<<sizeof(item01)<<"\n";
			std::cout<< "item02ei is "<<item02<<"sizeof(item02) is "<<sizeof(item02)<<"\n";	
			//调试使用,end

			//send hi ei
			chl.asyncSend(std::move(sendhi));
			chl.asyncSend(std::move(sendei));
			//send hi ei, end

	
//endning0000000000000000000000000000000000000000000000000000000000



	}

	void UBPsiSender::sendInput(u64 n, u64 theirInputSize, u64 secParam, block seed,span<block> inputs, span<Channel> chls, int curveType)
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
