#include "UBPsiReceiver.h"
#include "cryptoTools/Crypto/Curve.h"
#include "cryptoTools/Crypto/sha1.h"
#include "cryptoTools/Common/Log.h"
#include <cryptoTools/Crypto/RandomOracle.h>
#include <unordered_map>
#include "cryptoTools/Common/Timer.h"

#include <boost/type_index.hpp>//ning
#include "algorithm"  //ning
#include <string>     // std::string, std::to_string
using namespace std;    //ning
using namespace osuCrypto;    //ning

namespace Tanlab
{

    UBPsiReceiver::UBPsiReceiver()
    {
    }


    UBPsiReceiver::~UBPsiReceiver()
    {
    }

    void UBPsiReceiver::sendInput_k283(
        span<block> inputs,
        span<Channel> chls)
    {
		

    }

	void UBPsiReceiver::sendInput_Curve25519(
		span<block> inputs,
		span<Channel> chls)
	{
		

	}

	void UBPsiReceiver::sendInput_Ristretto(
		span<block> inputs,
		span<Channel> chls)
	{
		
		Timer timer;

		auto start = timer.setTimePoint("start");

		gTimer.setTimePoint("r start");

			//ning0000000000000000000000000000000000000000000000000000000000
			auto& chl = chls[0];
			gTimer.setTimePoint("离线 start");
			//发送公钥矩阵
			//u64 inputFieldSize = 1024;
			//u64 ReceiverSetSize = 256;

			u64 inputFieldSize = 1024;
			u64 ReceiverSetSize = 256;
			u64 skk = 0;

			unsigned char* skv = new unsigned char[crypto_core_ristretto255_SCALARBYTES];
			unsigned char* skt = new unsigned char[crypto_core_ristretto255_SCALARBYTES];
			unsigned char* gv = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char* gt = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char  gt9[crypto_core_ristretto255_BYTES];////////////
			crypto_core_ristretto255_scalar_random(skt);
			crypto_core_ristretto255_scalar_random(skv);
			crypto_scalarmult_ristretto255_base(gv, skv);
			crypto_scalarmult_ristretto255_base(gt, skt);

			std::vector<u8> sendG0(crypto_core_ristretto255_BYTES * inputFieldSize);
			std::vector<u8> sendG1(crypto_core_ristretto255_BYTES * inputFieldSize);
			std::vector<u8> sendgt(crypto_core_ristretto255_BYTES);
			memcpy(sendgt.data(), gt, crypto_core_ristretto255_BYTES);

			memcpy(gt9, gt, crypto_core_ristretto255_BYTES);
			//std::cout << "sender gt is " << gt9 << "\n";




			std::vector<u8> recvei(crypto_core_ristretto255_BYTES * ReceiverSetSize);
			std::vector<u8> recvhi(crypto_core_ristretto255_BYTES * ReceiverSetSize);
			unsigned char* pkG0scal = new unsigned char[crypto_core_ristretto255_SCALARBYTES];//上标,随机值
			unsigned char* pkG0 = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char  pkG09[crypto_core_ristretto255_BYTES];/////
			unsigned char* pkG1 = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char  pkG19[crypto_core_ristretto255_BYTES];/////

			for (u64 i = 0; i < inputFieldSize; i += 1)
			{

				crypto_core_ristretto255_scalar_random(pkG0scal);
				crypto_scalarmult_ristretto255_base(pkG0, pkG0scal);
				memcpy(pkG09, pkG0, crypto_core_ristretto255_BYTES);

				//cout << "pkG09:"<< pkG09<<"sizeof(pkG09)"<<sizeof(pkG09)<<"\n";
	
	
				if (crypto_scalarmult_ristretto255(pkG1, skt, pkG0) != 0) 				{
    					std::cout << "crypto_scalarmult_ristretto255(pkG1, t, pkG0) != 0\n";
					//return -1;
				}

				memcpy(sendG0.data() + i * crypto_core_ristretto255_BYTES, pkG0, crypto_core_ristretto255_BYTES);
				if (skk==i)
				{
					crypto_core_ristretto255_add(pkG1, pkG1, gv);
					//std::cout << "skk=" << skk <<"\n";
				}
				memcpy(sendG1.data() + i * crypto_core_ristretto255_BYTES, pkG1, crypto_core_ristretto255_BYTES);

				
				//memcpy(pkG19, pkG1, crypto_core_ristretto255_BYTES);
				//cout << "pkG19:"<< pkG19<<"sizeof(pkG19)"<<sizeof(pkG19)<<"\n";
				//cout << "sendG0.data():"<< sendG0.data()<<"sizeof(sendG0):"<<sizeof(sendG0)<<"\n";
				
			}

			chl.asyncSend(std::move(sendG0));
			//std::cout << "0000000chl.asyncSend(std::move(sendG0))" <<"\n";
			chl.asyncSend(std::move(sendG1));
			//std::cout << "0000000chl.asyncSend(std::move(sendG1))" <<"\n";
			chl.asyncSend(std::move(sendgt));
			//std::cout << "0000000chl.asyncSend(std::move(sendgt))" <<"\n";


			//send skt,调试使用
			std::vector<u8> sendskt(crypto_core_ristretto255_SCALARBYTES);
			memcpy(sendskt.data(), skt, crypto_core_ristretto255_SCALARBYTES);

			unsigned char  skt9[crypto_core_ristretto255_SCALARBYTES];
			memcpy(skt9, skt, crypto_core_ristretto255_SCALARBYTES);
			//std::cout<< "skt9 is "<<skt9<<"\n";

			//unsigned char *itemskt = sendskt.data();
			//std::cout<< "skt is "<<skt<<"\n";
			//std::cout<< "skt is "<<itemskt<<"\n";
			chl.asyncSend(std::move(sendskt));
			//send skt,调试使用 end
			//发送公钥矩阵结束

			gTimer.setTimePoint("pkG0 pkG1 start");
			//发送拉丁方
			std::vector<int> latinS0(inputFieldSize);
			for(int i = 0; i < inputFieldSize; i++)
			{    latinS0[i] = i;
			   //cout << "latinS0[i]" << latinS0vector[i]<<"\n";				
			}
			//std::vector<int> latinS0vector(sizeof(int) * inputFieldSize);
			mt19937 item1(random_device{}());
			shuffle(latinS0.begin(),latinS0.end(),item1);//将数组元素打乱，但每次都是同一种打乱顺序

			chl.asyncSend(latinS0);
			//发送拉丁方end

			gTimer.setTimePoint("ls0 start");
			//generate latinsquare
			//int LS[inputFieldSize][inputFieldSize];
			//for(int j = 0; j < inputFieldSize; j++)
			//{
			//	LS[0][j] = latinS0[j];
			//	for(int i = 1; i < inputFieldSize; i++)
			//	{
			//		LS[i][j] = (LS[i-1][j]+1) % inputFieldSize;
			//	}
			   //cout << "latinS0[i]" << latinS0vector[i]<<"\n";
			   //cout << "LS[0]["<<j<<"]" << LS[0][j]<<"\n";					
			//} 
			//cout << "LS[0][0]" <<LS[0][0]<< "\n";
			//cout << "LS[1][0]" <<LS[1][0]<< "\n";
			std::cout << "generate latinsquare end" <<  std::endl;
			//generate latinsquare end

			gTimer.setTimePoint("LS");

			//定义ReceiverSetY,ning
			std::vector<int> ReceiverSetY(ReceiverSetSize);
			std::vector<int> SelectPool(inputFieldSize);
			int randoma;
    			srand(time(nullptr)); // 用当前时间作为种子
			for(int i = 0; i < inputFieldSize; i++)
			{    
				SelectPool[i] = i;			
			}
			for(int i = 0; i < ReceiverSetSize; i++)
			{    
				randoma=rand()%(inputFieldSize-i);        
				ReceiverSetY[i] = SelectPool[randoma];
				SelectPool.erase(SelectPool.begin()+randoma);
				//std::cout<< "ReceiverSetY["<<i<<"]:"<<ReceiverSetY[i] <<"\n";					
			}
			std::cout << "定义ReceiverSetY end" <<  std::endl;
			//定义ReceiverSetY end,ning

			gTimer.setTimePoint("定义ReceiverSetY end");
			//加密,发送密文ning
			std::vector<int> ci(ReceiverSetSize);
			int j;
			int LS_j;
			for(int i = 0; i < ReceiverSetSize; i++)
			{  
				j = 0;
				//cout<< "LS[0][skk]:"<<LS[0][skk] <<"LS[j][ReceiverSetY[i]]:"<<LS[j][ReceiverSetY[i]]<<"\n";
				LS_j = latinS0[ReceiverSetY[i]];
				
				while(LS_j != latinS0[skk])	
				{
					//cout<<"LS[j][ReceiverSetY["<<i<<"]]:"<<LS[j][ReceiverSetY[i]]<<"\n";
					j=j+1;	
					LS_j = (LS_j+1)  % inputFieldSize;
					//cout<< "j:"<<j <<"i:"<<i<<"\n";	
				}  
				ci[i] = j;
				//cout<< "j:"<<j <<"i:"<<i<<"\n";
				//cout<< "LS[j][ReceiverSetY[i]]:"<<LS[j][ReceiverSetY[i]] <<"\n";
				//std::cout<< "ci[i]:"<<ci[i]<<"\n";
					
			}
			//cout<< "ci.size()="<< ci.size()<<"\n";
			chl.asyncSend(ci);
			//加密,发送密文ning,end
			gTimer.setTimePoint("加密,发送密文,end");
			//receive ei hi
			chl.recv(recvhi);
			if (recvhi.size() != ReceiverSetSize * crypto_core_ristretto255_BYTES)
			{
				std::cout << " 接收验证信息recvhi.size()= " << recvhi.size()<< std::endl;

				std::cout << "error @ " << (LOCATION) << std::endl;
				throw std::runtime_error(LOCATION);
			}
			chl.recv(recvei);
			if (recvei.size() != ReceiverSetSize * crypto_core_ristretto255_BYTES)
			{
				std::cout << " 接收验证信息recvei.size()= " << recvei.size()<< std::endl;

				std::cout << "error @ " << (LOCATION) << std::endl;
				throw std::runtime_error(LOCATION);
			}

			//receive hi ei, end
			gTimer.setTimePoint("receive hi ei, end");
			//验证 hi ei
			//std::cout << "验证 hi ei" << std::endl;
			//unsigned char* hi = new unsigned char[crypto_core_ristretto255_BYTES];
			//unsigned char* ei = new unsigned char[crypto_core_ristretto255_BYTES];
			//unsigned char* hit = new unsigned char[crypto_core_ristretto255_BYTES];
			//unsigned char* hit_gv = new unsigned char[crypto_core_ristretto255_BYTES];

			unsigned char hi[crypto_core_ristretto255_BYTES];
			unsigned char ei[crypto_core_ristretto255_BYTES];

			//unsigned char hi9[crypto_core_ristretto255_BYTES];///////
			//unsigned char ei9[crypto_core_ristretto255_BYTES];//////

			unsigned char hit[crypto_core_ristretto255_BYTES];
			unsigned char hit_gv[crypto_core_ristretto255_BYTES];
			int ri[ReceiverSetSize];

			for(int i = 0; i < ReceiverSetSize; i++)
			{
				memcpy(hi, recvhi.data() + i * crypto_core_ristretto255_BYTES, crypto_core_ristretto255_BYTES);
				memcpy(ei, recvei.data() + i * crypto_core_ristretto255_BYTES, crypto_core_ristretto255_BYTES);
				//std::cout << "ei="<<ei<<"  sizeof(ei)="<<sizeof(ei)<<"\n";
				//std::cout << "hi="<<hi<<"  sizeof(hi)="<<sizeof(hi)<<"\n";
				//std::cout << "ei[31]="<<ei[31]<<"  sizeof(ei)="<<sizeof(ei)<<"\n";
				//std::cout << "hi[31]="<<hi[31]<<"  sizeof(hi)="<<sizeof(hi)<<"\n";


				if (crypto_scalarmult_ristretto255(hit, skt, hi) != 0) {

					std::cout << "crypto_scalarmult_ristretto255(hit, skt, hi) != 0\n";
					throw std::runtime_error("rt error at " LOCATION);
				}
				crypto_core_ristretto255_add(hit_gv, hit, gv);

				//std::cout << "hit="<<hit<<"\n";
				ri[i] = 9;
				int ri_item = 0;
				for(int j = 0; j < crypto_core_ristretto255_BYTES; j++)
				{
					if (ei[j]!= hit[j]) {
						ri_item = 1;
						break;						
					}

				}
				if (ri_item == 0) {

					ri[i] = 0; 
					std::cout << "ri["<<i<<"]="<<ri[i]<<"no\n";
				}
				else  {
					for(int j = 0; j < crypto_core_ristretto255_BYTES; j++)
					{
						if (ei[j]!= hit_gv[j]) {
							ri_item = 2;
							break;						
						}
					}
					if (ri_item == 1) {

						ri[i] = 1; 
						std::cout << "ri["<<i<<"]="<<ri[i]<<"yes\n";
					}
					else  {
						ri[i] = 2;
						std::cout << "ri["<<i<<"] error! --ning\n";
							
					}
				
				}

		
				//memcpy(hi9, recvhi.data() + i * crypto_core_ristretto255_BYTES, crypto_core_ristretto255_BYTES);
				//memcpy(ei9, recvei.data() + i * crypto_core_ristretto255_BYTES, crypto_core_ristretto255_BYTES);

				
			}
			//验证 hi ei, end
			gTimer.setTimePoint("验证 hi ei, end");
			unsigned char gene[crypto_core_ristretto255_BYTES];
			crypto_scalarmult_ristretto255_base(gene, skt);
			//std::cout<< "gene is "<<gene<<"\n";


	
			//unsigned char* item01 = new unsigned char[crypto_core_ristretto255_BYTES];
			//unsigned char* item02 = new unsigned char[crypto_core_ristretto255_BYTES];
			unsigned char item01[crypto_core_ristretto255_BYTES];
			unsigned char item02[crypto_core_ristretto255_BYTES];
			memcpy(item01, recvhi.data() +  crypto_core_ristretto255_BYTES,  crypto_core_ristretto255_BYTES);
			memcpy(item02,recvei.data() + crypto_core_ristretto255_BYTES, crypto_core_ristretto255_BYTES);
			std::cout<< "item01 is "<<item01<<"\n";
			std::cout<< "item02 is "<<item02<<"\n";	

			
//endning0000000000000000000000000000000000000000000000000000000000




	}


	void UBPsiReceiver::sendInput(u64 n, u64 theirInputSize, u64 secParam, block seed,
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

