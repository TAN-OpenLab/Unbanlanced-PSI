#include "OT_Tests.h"

#include "libOTe/TwoChooseOne/OTExtInterface.h"

#include "libOTe/Tools/Tools.h"
#include "libOTe/Tools/LinearCode.h"
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Log.h>

#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"

#include "libOTe/NChooseOne/Oos/OosNcoOtReceiver.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtSender.h"
#include "libOTe/NChooseOne/RR17/Rr17NcoOtReceiver.h"
#include "libOTe/NChooseOne/RR17/Rr17NcoOtSender.h"

#include "Common.h"
#include <thread>
#include <vector>
#include "NcoOT_Tests.h"
#include "libOTe/Tools/bch511.h"

#include "libOTe_Tests/testData/code128_BCH511.h"
#include "libOTe_Tests/testData/code256_BCH511.h"
#include "libOTe_Tests/testData/code384_BCH511.h"
#include "libOTe_Tests/testData/code640_BCH511.h"
#include "libOTe_Tests/testData/code1280_BCH511.h"

using namespace osuCrypto;




namespace tests_libOTe
{


    void testNco(
        NcoOtExtSender &sender,
        const u64 &numOTs,
        PRNG &prng0,
        Channel &sendChl,
        NcoOtExtReceiver &recv,
        PRNG &prng1,
        Channel &recvChl)
    {

        u64 stepSize = 33;
        std::vector<block> inputs(stepSize);
        setThreadName("Receiver");

        for (size_t j = 0; j < 10; j++)
        {
            // perform the init on each of the classes. should be performed concurrently
            auto thrd = std::thread([&]() {
                setThreadName("EchdSender");
                sender.init(numOTs, prng0, sendChl);
            });
            recv.init(numOTs, prng1, recvChl);
            thrd.join();

            std::vector<block> encoding1(stepSize), encoding2(stepSize);

            // Get the random OT messages
            for (u64 i = 0; i < numOTs; i += stepSize)
            {
                auto curStepSize = std::min<u64>(stepSize, numOTs - i);
                std::vector<u8> skips(curStepSize);

                prng0.get(inputs.data(), inputs.size());
                prng0.get((bool*)skips.data(), skips.size());

                for (u64 k = 0; k < curStepSize; ++k)
                {

                    // The receiver MUST encode before the sender. Here we are only calling encode(...) 
                    // for a single i. But the receiver can also encode many i, but should only make one 
                    // call to encode for any given value of i.
                    if (skips[k])
                    {
                        recv.zeroEncode(i + k);
                    }
                    else {
                        recv.encode(i + k, &inputs[k], (u8*)&encoding1[k], sizeof(block));
                    }
                }

                // This call will send to the other party the next "curStepSize " corrections to the sender.
                // If we had made more or less calls to encode above (for contigious i), then we should replace
                // curStepSize  with however many calls we made. In an extreme case, the reciever can perform
                // encode for i \in {0, ..., numOTs - 1}  and then call sendCorrection(recvChl, numOTs).
                recv.sendCorrection(recvChl, curStepSize);

                // receive the next curStepSize  correction values. This allows the sender to now call encode
                // on the next curStepSize  OTs.
                sender.recvCorrection(sendChl, curStepSize);

                for (u64 k = 0; k < curStepSize; ++k)
                {
                    // the sender can now call encode(i, ...) for k \in {0, ..., i}. 
                    // Lets encode the same input and then we should expect to
                    // get the same encoding.
                    sender.encode(i + k, &inputs[k], (u8*)&encoding2[k], sizeof(block));

                    // check that we do in fact get the same value
                    if (! skips[k] && neq(encoding1[k], encoding2[k]))
                        throw UnitTestFail();

                    // In addition to the sender being able to obtain the same value as the receiver,
                    // the sender can encode and other codeword. This should result in a different 
                    // encoding.
                    inputs[k] = prng0.get<block>();

                    sender.encode(i + k, &inputs[k], (u8*)&encoding2[k], sizeof(block));

                    if (eq(encoding1[k], encoding2[k]))
                        throw UnitTestFail();
                }
            }
        }


        //block input;
        //for (size_t j = 0; j < 2; j++)
        //{

        //    auto thrd = std::thread([&]() {
        //        sender.init(numOTs, prng0, sendChl);
        //    });

        //    recv.init(numOTs, prng1, recvChl);

        //    thrd.join();


        //    for (u64 i = 0; i < numOTs; ++i)
        //    {
        //        block input = prng0.get<block>();


        //        bool skip = prng0.get<bool>();

        //        block encoding1, encoding2;
        //        if (skip)
        //        {
        //            recv.zeroEncode(i);
        //        }
        //        else
        //        {
        //            recv.encode(i, &input, &encoding1);
        //        }

        //        recv.sendCorrection(recvChl, 1);
        //        sender.recvCorrection(sendChl, 1);

        //        sender.encode(i, &input, &encoding2);

        //        if (!skip && neq(encoding1, encoding2))
        //        {
        //            std::cout << " = failed " << i << std::endl;
        //            throw UnitTestFail();
        //        }

        //        input = prng0.get<block>();


        //        sender.encode(i, &input, &encoding2);

        //        if (!skip && eq(encoding1, encoding2))
        //        {
        //            std::cout << " != failed " << i << std::endl;
        //            throw UnitTestFail();
        //        }
        //    }

        //    thrd = std::thread([&]() {recv.check(recvChl, ZeroBlock); });
        //    try {

        //        sender.check(sendChl, ZeroBlock);
        //    }
        //    catch (...)
        //    {
        //        std::cout << " check failed " << std::endl;
        //        thrd.join();
        //        throw;
        //    }

        //    thrd.join();
        //}
    }

    void KkrtNcoOt_Test_Impl()
    {
        setThreadName("EchdSender");

        PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
        PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));

        // The total number that we wish to do
        u64 numOTs = 1030;

        KkrtNcoOtSender sender;
        KkrtNcoOtReceiver recv;

        // get up the parameters and get some information back. 
        //  1) false = semi-honest
        //  2) 40  =  statistical security param.
        //  3) numOTs = number of OTs that we will perform
        sender.configure(false, 40, 128);
        recv.configure(false, 40, 128);

        // the number of base OT that need to be done
        u64 baseCount = sender.getBaseOTCount();

        // Fake some base OTs
        std::vector<block> baseRecv(baseCount);
        std::vector<std::array<block, 2>> baseSend(baseCount);
        BitVector baseChoice(baseCount);
        baseChoice.randomize(prng0);
        prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
        for (u64 i = 0; i < baseCount; ++i)
        {
            baseRecv[i] = baseSend[i][baseChoice[i]];
        }

        // set up networking
        std::string name = "n";
        IOService ios;
        Endpoint ep0(ios, "localhost", 1212, EpMode::Server, name);
        Endpoint ep1(ios, "localhost", 1212, EpMode::Client, name);
        auto recvChl = ep1.addChannel(name, name);
        auto sendChl = ep0.addChannel(name, name);


        // set the base OTs
        sender.setBaseOts(baseRecv, baseChoice);
        recv.setBaseOts(baseSend);

        u64 stepSize = 10;
        std::vector<block> inputs(stepSize);

        for (size_t j = 0; j < 2; j++)
        {
            // perform the init on each of the classes. should be performed concurrently
            auto thrd = std::thread([&]() { sender.init(numOTs, prng0, sendChl); });
            recv.init(numOTs, prng1, recvChl);
            thrd.join();

            std::vector<block> encoding1(stepSize), encoding2(stepSize);

            // Get the random OT messages
            for (u64 i = 0; i < numOTs; i += stepSize)
            {

                prng0.get(inputs.data(), inputs.size());


                for (u64 k = 0; k < stepSize; ++k)
                {

                    // The receiver MUST encode before the sender. Here we are only calling encode(...) 
                    // for a single i. But the receiver can also encode many i, but should only make one 
                    // call to encode for any given value of i.
                    recv.encode(i + k, &inputs[k], (u8*)&encoding1[k], sizeof(block));
                }

                // This call will send to the other party the next "stepSize" corrections to the sender.
                // If we had made more or less calls to encode above (for contigious i), then we should replace
                // stepSize with however many calls we made. In an extreme case, the reciever can perform
                // encode for i \in {0, ..., numOTs - 1}  and then call sendCorrection(recvChl, numOTs).
                recv.sendCorrection(recvChl, stepSize);

                // receive the next stepSize correction values. This allows the sender to now call encode
                // on the next stepSize OTs.
                sender.recvCorrection(sendChl, stepSize);

                for (u64 k = 0; k < stepSize; ++k)
                {
                    // the sender can now call encode(i, ...) for k \in {0, ..., i}. 
                    // Lets encode the same input and then we should expect to
                    // get the same encoding.
                    sender.encode(i + k, &inputs[k], (u8*)&encoding2[k], sizeof(block));

                    // check that we do in fact get the same value
                    if (neq(encoding1[k], encoding2[k]))
                        throw UnitTestFail();

                    // In addition to the sender being able to obtain the same value as the receiver,
                    // the sender can encode and other codeword. This should result in a different 
                    // encoding.
                    inputs[k] = prng0.get<block>();

                    sender.encode(i + k, &inputs[k], (u8*)&encoding2[k], sizeof(block));

                    if (eq(encoding1[k], encoding2[k]))
                        throw UnitTestFail();
                }
            }
        }

        // Double check that we can call split and perform the same tests.
        auto recv2Ptr = recv.split();
        auto send2Ptr = sender.split();

        auto& recv2 = *recv2Ptr;
        auto& send2 = *send2Ptr;

        for (size_t j = 0; j < 2; j++)
        {
            auto thrd = std::thread([&]() {
                send2.init(numOTs, prng0, sendChl);
            });

            recv2.init(numOTs, prng1, recvChl);

            thrd.join();


            for (u64 i = 0; i < numOTs; ++i)
            {
                block input = prng0.get<block>();

                block encoding1, encoding2;
                recv2.encode(i, &input, &encoding1);

                recv2.sendCorrection(recvChl, 1);
                send2.recvCorrection(sendChl, 1);

                send2.encode(i, &input, &encoding2);

                if (neq(encoding1, encoding2))
                    throw UnitTestFail();

                input = prng0.get<block>();

                send2.encode(i, &input, &encoding2);

                if (eq(encoding1, encoding2))
                    throw UnitTestFail();
            }

        }

        sendChl.close();
        recvChl.close();

        ep0.stop();
        ep1.stop();
        ios.stop();
    }

    void OosNcoOt_Test_Impl()
    {
        setThreadName("EchdSender");

        PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
        PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));

        u64 numOTs = 128 * 2;


        std::string name = "n";
        IOService ios(0);
        Endpoint ep0(ios, "localhost", 1212, EpMode::Server, name);
        Endpoint ep1(ios, "localhost", 1212, EpMode::Client, name);
        auto recvChl = ep1.addChannel(name, name);
        auto sendChl = ep0.addChannel(name, name);


        LinearCode code;
        code.load(bch511_binary, sizeof(bch511_binary));

        OosNcoOtSender sender;
        OosNcoOtReceiver recv;

        sender.configure(true, 40, 50);
        recv.configure(true, 40, 50);
        u64 baseCount = sender.getBaseOTCount();
        u64 codeSize = (baseCount + 127) / 128;

        std::vector<block> baseRecv(baseCount);
        std::vector<std::array<block, 2>> baseSend(baseCount);
        BitVector baseChoice(baseCount);
        baseChoice.randomize(prng0);

        prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
        for (u64 i = 0; i < baseCount; ++i)
        {
            baseRecv[i] = baseSend[i][baseChoice[i]];
        }

        sender.setBaseOts(baseRecv, baseChoice);
        recv.setBaseOts(baseSend);

        testNco(sender, numOTs, prng0, sendChl, recv, prng1, recvChl);


        auto sender2 = sender.split();
        auto recv2 = recv.split();

        testNco(*sender2, numOTs, prng0, sendChl, *recv2, prng1, recvChl);

    }


    void Rr17NcoOt_Test_Impl()
    {

        setThreadName("EchdSender");

        PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
        PRNG prng1(_mm_set_epi32(4253465, 3434565, 234435, 23987025));

        u64 numOTs = 80;
        u64 inputSize = 40;

        Rr17NcoOtSender sender;
        Rr17NcoOtReceiver recv;
        u64  baseCount;
        sender.configure(true, 40, inputSize);
        recv.configure(true, 40, inputSize);

        baseCount = sender.getBaseOTCount();

        std::vector<block> baseRecv(baseCount);
        std::vector<std::array<block, 2>> baseSend(baseCount);
        BitVector baseChoice(baseCount);
        baseChoice.randomize(prng0);

        prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
        for (u64 i = 0; i < baseCount; ++i)
        {
            baseRecv[i] = baseSend[i][baseChoice[i]];
        }

        std::string name = "n";
        IOService ios(0);
        Endpoint ep0(ios, "localhost", 1212, EpMode::Server, name);
        Endpoint ep1(ios, "localhost", 1212, EpMode::Client, name);
        auto recvChl = ep1.addChannel(name, name);
        auto sendChl = ep0.addChannel(name, name);




        sender.setBaseOts(baseRecv, baseChoice);
        recv.setBaseOts(baseSend);

        testNco(sender, numOTs, prng0, sendChl, recv, prng1, recvChl);


        auto sender2 = sender.split();
        auto recv2 = recv.split();

        testNco(*sender2, numOTs, prng0, sendChl, *recv2, prng1, recvChl);

    }


    void LinearCode_Test_Impl()
    {
        LinearCode code;


        // load the data at bch511_binary
        code.load(bch511_binary, sizeof(bch511_binary));

        // You can also load it from text
        //code.loadTxtFile(std::string(SOLUTION_DIR) + "/libOTe/Tools/bch511.txt");

        // or binary file
        //code.loadBinFile(std::string(SOLUTION_DIR) + "/libOTe/Tools/bch511.bin");

        // You can also write it in any format
        //code.writeTextFile(std::string(SOLUTION_DIR) + "/libOTe/Tools/bch511.txt");
        //code.writeBinFile(std::string(SOLUTION_DIR) + "/libOTe/Tools/bch511.bin");
        //code.writeBinCppFile(std::string(SOLUTION_DIR) + "/libOTe/Tools/new_bch511.h", "bch511");


        if (code.plaintextBitSize() != 76)
            throw UnitTestFail("bad input size reported by code");


        if (code.codewordBitSize() != 511)
            throw UnitTestFail("bad out size reported by code");

        std::vector<block>
            plainText(code.plaintextBlkSize(), AllOneBlock),
            codeword(code.codewordBlkSize());

        code.encode(plainText, codeword);

        BitVector cw((u8*)codeword.data(), code.codewordBitSize());

        // expect all ones
        for (size_t i = 0; i < cw.size(); i++)
        {
            if (cw[i] == 0)
            {
                std::cout << cw << std::endl;
                std::cout << "expecting all ones" << std::endl;
                throw UnitTestFail();
            }
        }

        BitVector pt("1111111111111111111111111111111111111111111111111101111111111101111111111111");
        memset(plainText.data(), 0, plainText.size() * sizeof(block));
        memcpy(plainText.data(), pt.data(), pt.sizeBytes());


        code.encode(plainText, codeword);
        cw.resize(0);
        cw.append((u8*)codeword.data(), code.codewordBitSize());


        BitVector expected("1111111111111111111111111111111111111111111111111101111111111101111111111111101000010001110100011100010110011111110010011010001010000111111001101101110101100000100010010101000110011001111101111100100111000101110000101000000011000100011110011100001101100111111001001011010100010010110001010011000011111010101010010010011101001001100001100010100101001100111000010110011110011110001110001011111101010001101000101010110100011000000011010011110101011001100011111111101001101111001111111101000010000011010111100011100");

        if (cw != expected)
        {
            std::cout << cw << std::endl;
            std::cout << expected << std::endl;
            throw UnitTestFail();
        }

    }

    void LinearCode_subBlock_Test_Impl()
    {
        LinearCode code511, code128, code256, code384, code640, code1280;

        code511.load(bch511_binary, sizeof(bch511_binary));
        code128.load(code128_binary, sizeof(code128_binary));//loadTxtFile("C:/Users/peter/repo/libOTe/libOTe_Tests/testData/code128_BCH511.txt");
        code256.load(code256_binary, sizeof(code256_binary));//loadTxtFile("C:/Users/peter/repo/libOTe/libOTe_Tests/testData/code256_BCH511.txt");
        code384.load(code384_binary, sizeof(code384_binary));//loadTxtFile("C:/Users/peter/repo/libOTe/libOTe_Tests/testData/code384_BCH511.txt");
        code640.load(code640_binary, sizeof(code640_binary));//loadTxtFile("C:/Users/peter/repo/libOTe/libOTe_Tests/testData/code640_BCH511.txt");
        code1280.load(code1280_binary, sizeof(code1280_binary));//.loadTxtFile("C:/Users/peter/repo/libOTe/libOTe_Tests/testData/code1280_BCH511.txt");

        //code128.writeBinCppFile( "C:/Users/peter/repo/libOTe/libOTe_Tests/testData/code128_BCH511.h", "code128_binary");
        //code256.writeBinCppFile( "C:/Users/peter/repo/libOTe/libOTe_Tests/testData/code256_BCH511.h", "code256_binary");
        //code384.writeBinCppFile( "C:/Users/peter/repo/libOTe/libOTe_Tests/testData/code384_BCH511.h", "code384_binary");
        //code640.writeBinCppFile( "C:/Users/peter/repo/libOTe/libOTe_Tests/testData/code640_BCH511.h", "code640_binary");
        //code1280.writeBinCppFile("C:/Users/peter/repo/libOTe/libOTe_Tests/testData/code1280_BCH511.h", "code1280_binary");

        BitVector
            in(code511.plaintextBitSize()),
            out511(code511.codewordBitSize()),
            out128(code128.codewordBitSize()),
            out256(code256.codewordBitSize()),
            out384(code384.codewordBitSize()),
            out640(code640.codewordBitSize()),
            out1280(code1280.codewordBitSize());


        PRNG prng(ZeroBlock);

        for (u64 i = 0; i < 10; ++i)
        {

            in.randomize(prng);

            code511.encode(in.data(), out511.data());
            code128.encode(in.data(), out128.data());
            code256.encode(in.data(), out256.data());
            code384.encode(in.data(), out384.data());
            code640.encode(in.data(), out640.data());
            code1280.encode(in.data(), out1280.data());

            BitVector
                out511_128 = out511,
                out511_256 = out511,
                out511_384 = out511,
                out511_640 = out511,
                out511_1280;

            u8 zero = 0;
            out511_640.append(&zero, 1);
            out511_640.append(out128);

            out511_1280.append(out640);
            out511_1280.append(out640);

            out511_128.resize(128);
            out511_256.resize(256);
            out511_384.resize(384);

            if (out511_128 != out128)
            {
                std::cout << "out511 " << out511_128 << std::endl;
                std::cout << "out128 " << out128 << std::endl;
                throw UnitTestFail(LOCATION);
            }

            if (out511_256 != out256)
            {
                std::cout << "out511 " << out511_256 << std::endl;
                std::cout << "out256 " << out256 << std::endl;
                throw UnitTestFail(LOCATION);
            }

            if (out511_384 != out384)
            {
                std::cout << "out511 " << out511_384 << std::endl;
                std::cout << "out384 " << out384 << std::endl;
                throw UnitTestFail(LOCATION);
            }

            if (out511_640 != out640)
            {
                std::cout << "out511 " << out511_640 << std::endl;
                std::cout << "out640 " << out640 << std::endl;

                for (u64 j = 0; j < 640; ++j)
                {
                    if (out511_640[j] == out640[j])
                    {
                        std::cout << " ";
                    }
                    else
                    {
                        std::cout << "^" << j;
                    }
                }

                std::cout << std::endl;
                throw UnitTestFail(LOCATION);
            }

            if (out511_1280 != out1280)
            {
                std::cout << "out511  " << out511_1280 << std::endl;
                std::cout << "out1280 " << out1280 << std::endl;
                throw UnitTestFail(LOCATION);
            }
        }
    }

    void LinearCode_repetition_Test_Impl()
    {
        LinearCode code;
        std::stringstream ss;
        ss << "1 40\n1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1";
        code.loadTxtFile(ss);

        u8 bit = 1;
        BitVector dest(40);
        code.encode(&bit, dest.data());


        for (u64 i = 0; i < 40; ++i)
        {
            if (dest[i] != 1)
                throw UnitTestFail();
        }
    }

}