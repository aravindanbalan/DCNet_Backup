#include "ApplicationUtil.h"
#include "Utility.h"
#include "AnonymousRecv.h"

NS_LOG_COMPONENT_DEFINE ("WifiSimpleAdhocGrid");

void DisplayMessage(Ptr<Socket> socket);
void DCNET(Ptr<Socket> socket, int numRounds);

//**************************Anonymous receiver steps*********************

static void AnonymousReceiverStep1()
{
	//int sourceNode = 0;
	int stepId = 0;
	currentStep = stepId;
	std::string sourceMessage = "Hello";
	std::string sourceControl = INITIATE_MESSAGE;
	std::string sourceMessageId ="000-000-0001";
	//	SendMessageUsingDCNET(source,sourceNode, sourceControl, sourceMessageId,sourceMessage);	
}
	
static void AnonymousReceiverStep2()
{
	std::cout<<"In anonymous Receiver step 2\n";
	int receiveNode = 1;
	//std::string replyMessage = "hi";
	std::string replyControl= MESSAGE_SET;
	std::string replyMessageId;

	Ptr<Socket> replySource = Socket::CreateSocket (c.Get (receiveNode), tid);
	//check the step 1 output and process it

	replyMessageId = decode_binary(receiveNode, sharedMessage.str().c_str());

	//step2 - Node C wants to reply to the message by sending first the AES key

	SendMessageUsingDCNET(replySource,receiveNode, replyControl, replyMessageId,"");
	
}

static void AnonymousReceiverStep3()
{
	std::cout<<"In anonymous Receiver step 3\n";
	std::string replyMessage = "hi";
	
	//do it for all nodes - as all nodes try to decrypt with its AES keys
	decode_binary(0, sharedMessage.str().c_str());

}

static void procedureHandle(Ptr<Socket> socket)
{
	if(currentStep == 1)	//advance to next step 2
		AnonymousReceiverStep2();
	if(currentStep == 2)	//advance to next step 3
		AnonymousReceiverStep3();
	if(currentStep == 3)
	{
		//stop the simulation		
       		Simulator::Stop ();
	}
}

//**************************Anonymous receiver steps*********************

static void SendMessage (Ptr<Socket> socket, std::string message, int index, int dest)
{
    Ptr<Packet> sendPacket =
        Create<Packet> ((uint8_t*)message.c_str(),message.size());

    MyTag sendTag;
    sendTag.SetSimpleValue(index);
    sendPacket->AddPacketTag(sendTag);
    socket->Send (sendPacket);
    stage2SentPacketCount += 1;//increment sent packet counter for stage2
    socket->Close ();
}

void ReceiveMessage (Ptr<Socket> socket)
{
    Ptr<Packet> recPacket = socket->Recv();
    stage2RecvPacketCount += 1;//increment recv packet counter for stage2
    ApplicationUtil *appUtil = ApplicationUtil::getInstance();

    Ptr<Node> recvnode = socket->GetNode();
    int recNodeIndex = ApplicationUtil::getInstance()->getNodeFromMap(recvnode);

    uint8_t *buffer = new uint8_t[recPacket->GetSize()];

    std::string recMessage = std::string((char*)buffer);
    recMessage = recMessage.substr (0,messageLen-1);

    MyTag recTag;
    recPacket->PeekPacketTag(recTag);
    int srcNodeIndex =int(recTag.GetSimpleValue());
    std::ostringstream s;
    s<<srcNodeIndex;
    std::string ss(s.str());
    std::ostringstream s1;
    s1<<recNodeIndex;
    std::string ss1(s1.str());

    SecByteBlock key(SHA256::DIGESTSIZE);
    SHA256().CalculateDigest(key, appUtil->getSecretKeyFromGlobalMap(srcNodeIndex,recNodeIndex), appUtil->getSecretKeyFromGlobalMap(srcNodeIndex,recNodeIndex).size());

    //Decryption using the Shared secret key
    CFB_Mode<AES>::Decryption cfbDecryption(key, aesKeyLength, iv);
    cfbDecryption.ProcessData((byte*)recMessage.c_str(), (byte*)recMessage.c_str(), messageLen);

    // std::cout<<"message 4: "<<recMessage<<"\n";
//	NS_LOG_UNCOND ("Received message packet: Data: " +recMessage+"   TagID: "+ss + " to "+ss1+"\n");

    int value = atoi(recMessage.c_str());
//	std::cout<<"Value :"<<value<<"\n";
    //put in node's map

    appUtil->putSecretBitInGlobalMap(srcNodeIndex,recNodeIndex,value);
    appUtil->putSecretBitInGlobalMap(recNodeIndex,srcNodeIndex,value);

    randomBitCounter--;
    if(randomBitCounter == 0)
    {
	stage1EndTime.push_back(Simulator::Now());
	stage2StartTime.push_back(Simulator::Now());
        Simulator::ScheduleNow (&DisplayMessage,source);
    }
}


int randomBitGeneratorWithProb(double p)
{
    double rndDouble = (double)rand() / RAND_MAX;
    return rndDouble > p;
}

static void SimulatorLoop(Ptr<Socket> socket,TypeId tid, NodeContainer c, Ipv4InterfaceContainer i)
{
publicKeyCounter = (numNodes * numNodes) - numNodes;
    ApplicationUtil *appUtil = ApplicationUtil::getInstance();
    // Generate a random IV
    rnd.GenerateBlock(iv, AES::BLOCKSIZE);

    //sharing the random bit using dh secret key
    for (int index1 = 0; index1 < (int)numNodes; index1++)
    {

        for (int index2 = 0; index2 < (int)numNodes; index2++)
        {
            if(index1 < index2)
            {
                int randomBit = randomBitGeneratorWithProb(0.5);
             //   std::cout<<"Random bit : "<<randomBit<<" "<<index1<<" "<<index2<<"\n";

                //put random bit in both the maps - src and dest maps

                appUtil->putSecretBitInGlobalMap(index1,index2,randomBit);
                appUtil->putSecretBitInGlobalMap(index2,index1,randomBit);

                // Calculate a SHA-256 hash over the Diffie-Hellman session key
                SecByteBlock key(SHA256::DIGESTSIZE);
                SHA256().CalculateDigest(key, appUtil->getSecretKeyFromGlobalMap(index1,index2), appUtil->getSecretKeyFromGlobalMap(index1,index2).size());

                std::ostringstream ss;
                ss << randomBit;
                std::string message = ss.str();
                messageLen = (int)strlen(message.c_str()) + 1;

                // Encrypt

                CFB_Mode<AES>::Encryption cfbEncryption(key, aesKeyLength, iv);
                cfbEncryption.ProcessData((byte*)message.c_str(), (byte*)message.c_str(), messageLen);

                //Send the encrypted message
                Ptr<Socket> recvNodeSink = Socket::CreateSocket (c.Get (index2), tid);
                InetSocketAddress localSocket = InetSocketAddress (Ipv4Address::GetAny (), 9801);
                recvNodeSink->Bind (localSocket);
                recvNodeSink->SetRecvCallback (MakeCallback (&ReceiveMessage));

                InetSocketAddress remoteSocket = InetSocketAddress (i.GetAddress (index2, 0), 9801);
                Ptr<Socket> sourceNodeSocket = Socket::CreateSocket (c.Get (index1), tid);
                sourceNodeSocket->Connect (remoteSocket);
                //waitTime += 20.0;
                Simulator::ScheduleNow(&SendMessage, sourceNodeSocket,message,index1,index2);
            }
        }
    }


}

static void SendPublicKey (Ptr<Socket> socket, SecByteBlock pub, int index)
{
    Ptr<Packet> sendPacket = Create<Packet> ((uint8_t*)pub.BytePtr(),(uint8_t) pub.SizeInBytes());
//	std::cout<<"Debug : Inside dcnet send public key \n";
    MyTag sendTag;
    sendTag.SetSimpleValue(index);
    sendPacket->AddPacketTag(sendTag);

    socket->Send(sendPacket);
    stage1SentPacketCount += 1;//increment sent packet counter for stage1
    std::string sendData = hexStr(pub.BytePtr(),pub.SizeInBytes());

    socket->Close();
}

void ReceivePublicKey (Ptr<Socket> socket)
{
 //std::cout<<"Debug : Inside dcnet receive public key \n";
    Ptr<Node> recvnode = socket->GetNode();
    int recNodeIndex = ApplicationUtil::getInstance()->getNodeFromMap(recvnode);

    Ptr<Packet> recPacket = socket->Recv();
    stage1RecvPacketCount +=1; //increment received packet count for stage 1

//	std::cout<<"Node receiving: "<<recNodeIndex<<"\n";
    uint8_t *buffer = new uint8_t[recPacket->GetSize()];
    recPacket->CopyData(buffer,recPacket->GetSize());

    SecByteBlock pubKey((byte *)buffer,recPacket->GetSize());

    MyTag recTag;
    recPacket->PeekPacketTag(recTag);
    int tagVal =int(recTag.GetSimpleValue());
    std::ostringstream s;
    s<<tagVal;
    std::string ss(s.str());
    int srcNodeIndex = atoi(ss.c_str());
    std::string recvData = hexStr(pubKey.BytePtr(),pubKey.SizeInBytes());

//	std::cout<<"Node : "<<recNodeIndex<<"  from Node TagID: "<<ss<<"\n";

    DH dh;
    dh.AccessGroupParameters().Initialize(p, q, g);
    SecByteBlock sharedKey(ApplicationUtil::getInstance()->getDhAgreedLength());

    dh.Agree(sharedKey, ApplicationUtil::getInstance()->getPrivateKeyFromMap(recNodeIndex),pubKey);

    ApplicationUtil::getInstance()->putSecretKeyInGlobalMap(recNodeIndex,srcNodeIndex,sharedKey);

    publicKeyCounter--;
//	std::cout<<"Public key counter :"<< publicKeyCounter<< "\n";
    if(publicKeyCounter == 0)
    {
//	std::cout<<"Debug : calling simulator loop \n";
        Simulator::ScheduleNow (&SimulatorLoop, socket,tid,c,i);
    }


}

void generateKeys(int index, ApplicationUtil *appUtil)
{
    try {
        DH dh;
        AutoSeededRandomPool rnd;

        dh.AccessGroupParameters().Initialize(p, q, g);

        if(!dh.GetGroupParameters().ValidateGroup(rnd, 3))
            throw runtime_error("Failed to validate prime and generator");


        p = dh.GetGroupParameters().GetModulus();
        q = dh.GetGroupParameters().GetSubgroupOrder();
        g = dh.GetGroupParameters().GetGenerator();

        Integer v = ModularExponentiation(g, q, p);
        if(v != Integer::One())
            throw runtime_error("Failed to verify order of the subgroup");

        //////////////////////////////////////////////////////////////

        SecByteBlock priv(dh.PrivateKeyLength());
        SecByteBlock pub(dh.PublicKeyLength());
        dh.GenerateKeyPair(rnd, priv, pub);

        //////////////////////////////////////////////////////////////

        appUtil->putPrivateKeyInMap(index,priv);
        appUtil->putPublicKeyInMap(index,pub);
        appUtil->setDhAgreedLength(dh.AgreedValueLength());

        //	std::cout<<"Dh key length "<< index <<" : "<<dh.AgreedValueLength()<<"\n";
    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << "Crypto error : "<< e.what() << std::endl;
    }

    catch(const std::exception& e)
    {
        std::cerr << "Standard error : "<<e.what() << std::endl;
    }
}

//sending and receiving announcements
static void SendAnnouncement (Ptr<Socket> socket, int result, int index)
{	
	std::ostringstream ss;
	ss << result;
	std::string message = ss.str();
	Ptr<Packet> sendPacket =
	Create<Packet> ((uint8_t*)message.c_str(),message.size());
	//Ptr<Packet> sendPacket = Create<Packet> (result);
	
	MyTag sendTag;
	sendTag.SetSimpleValue(index);
	sendPacket->AddPacketTag(sendTag);

	socket->Send(sendPacket);
	
	
	//std::cout<<"Sending announcement for "<<index<<":"<<message<<"Packet count:"<<AnnouncementPacketCount<<"\n";
	socket->Close();
}

void ReceiveAnnouncement (Ptr<Socket> socket)
{
	AnnouncementPacketCount-=1;
	//std::cout<<"Hello\n";
	Ptr<Packet> recPacket = socket->Recv();	
	//stage2RecvPacketCount += 1;//increment recv packet counter for stage2
	ApplicationUtil *appUtil = ApplicationUtil::getInstance();
	//std::cout<<"Receiving announcement"<<"\n";
	Ptr<Node> recvnode = socket->GetNode();
	int recNodeIndex = ApplicationUtil::getInstance()->getNodeFromMap(recvnode);

	uint8_t *buffer = new uint8_t[recPacket->GetSize()];
	recPacket->CopyData(buffer,recPacket->GetSize());
	
	std::string recMessage = std::string((char*)buffer);
	recMessage = recMessage.substr (0,messageLen-1);

	MyTag recTag;
	recPacket->PeekPacketTag(recTag);
	int srcNodeIndex =int(recTag.GetSimpleValue());
	//std::cout<<"Putting announcement in map"<<"\n";
	appUtil->putAnnouncementInReceivedMap(recNodeIndex, srcNodeIndex, atoi(recMessage.c_str()));
	if(AnnouncementPacketCount==0)
	{
	//	std::cout<<"Hello\n";
		int x=0;
		//sharedMessage<<resultBit;
		//xoring outputs

		for(int index=0;index<(int)numNodes;index++)
		{
			 x ^= appUtil->getAnnouncement(index);			
		 		
		}
		
	

		sharedMessage<<x;		
		AnnouncementPacketCount = (numNodes * numNodes) - numNodes;
		publicKeyCounter = (numNodes * numNodes) - numNodes;
		randomBitCounter = (numNodes * (numNodes-1)/2);
		stage2EndTime.push_back(Simulator::Now());
		Simulator::ScheduleNow (&DCNET, source,rounds+1);
	}
}

void DisplayMessage(Ptr<Socket> socket)
{
    ApplicationUtil *appUtil = ApplicationUtil::getInstance();
    
    int bit = Message.at(rounds)-48 ;
	
	std::cout<<"Current Round : "<<rounds<<"\n";
    for(int index = 0; index < (int)numNodes ; index++)
    {

		int result = 0;
        map<int,int> NodeSecretBitMap = appUtil->getSecretBitSubMap(index);

        for (map<int,int>::iterator it=NodeSecretBitMap.begin(); it!=NodeSecretBitMap.end(); ++it)
        {

	//std::cout<<"Adj bits of node "<<index<<" : "<<(int)it->second<<"\n";
            //Exor the adjacent node bits stored in the map
            result ^= (int)it->second;
        }
        if(sender == index)	//exor result with message
        {
            result ^= bit;
        }
	
	//std::cout<<"Result for Node "<<index<<" is : "<<result<<" in round "<<rounds<<"\n";
		appUtil->putAnnouncementInGlobalMap(index, result);

	}
	/*	for(int index=0;index<(int)numNodes;index++)
		{
			int r=appUtil->getAnnouncement(index);
			//std::cout<<"Verifying node "<<index<<" announcement "<<r<<"\n";

		}
*/
    //sharedMessage<<result;
for (int index1 = 0; index1 < (int)numNodes; index1++)
	{
		  
		for (int index2 = 0; index2 < (int)numNodes; index2++)
		{
			if(index1 != index2)
			{
	
				Ptr<Socket> recvNodeSink = Socket::CreateSocket (c.Get (index2), tid);
				      InetSocketAddress localSocket = InetSocketAddress (Ipv4Address::GetAny (),9802);
				      recvNodeSink->Bind (localSocket);
				      recvNodeSink->SetRecvCallback (MakeCallback (&ReceiveAnnouncement));
									    				      
				      InetSocketAddress remoteSocket = InetSocketAddress (i.GetAddress (index2, 0), 9802);
				Ptr<Socket> sourceNodeSocket = Socket::CreateSocket (c.Get (index1), tid);
				      sourceNodeSocket->Connect (remoteSocket);


	Simulator::ScheduleNow (&SendAnnouncement, sourceNodeSocket,appUtil->getAnnouncement(index1), index1);
				
			}	
		}
	}
}

void DisplayMeasurements()
{
	
    std::cout<<"Message length:"<<MessageLength<<"\n";	
    //std::cout<<"Shared Message after "<<MessageLength<<" rounds is : "<<sharedMessage.str()<<"\n";
    std::cout<<"Sent Packet Count Stage 1: "<<stage1SentPacketCount<<"\n";
    std::cout<<"Sent Packet Count Stage 2: "<<stage2SentPacketCount<<"\n";
    std::cout<<"Sent Recv Count Stage 1: "<<stage1RecvPacketCount<<"\n";
    std::cout<<"Sent Recv Count Stage 2: "<<stage2RecvPacketCount<<"\n";

    stage1Latency = (stage1EndTime.front().GetSeconds() - stage1StartTime.front().GetSeconds());
    std::cout<<"Stage 1 latency: "<<stage1Latency<<"\n";

    stage2Latency = (stage2EndTime.front().GetSeconds() - stage2StartTime.front().GetSeconds());
    std::cout<<"Stage 2 latency: "<<stage2Latency<<"\n";

    totalLatency = (stage1Latency + stage2Latency);
   // std::cout<<"goodPut: "<<goodPut<<"\n";

totalTimeEnd = Simulator::Now();
totalRunningTime = totalTimeEnd.GetSeconds() - totalTimeStart.GetSeconds();
std::cout<<"Total time taken : "<<totalRunningTime<<" seconds\n";

ApplicationUtil *appUtil = ApplicationUtil::getInstance();
//output to csv

	if(option == 1)
		appUtil->writeOutputToFile((char*)"NumNodesvsMeasurements.csv",option,numNodes,MessageLength,totalLatency,totalRunningTime);	
	else if(option == 2)
		appUtil->writeOutputToFile((char*)"MsgLengthvsMeasurements.csv",option,numNodes,MessageLength,totalLatency,totalRunningTime);	
 

}

void DCNET(Ptr<Socket> socket, int numRounds)
{
    //numRounds++;
	//std::cout<<"Debug : Inside dcnet\n";
	 stage1StartTime.push_back(Simulator::Now());
    
        ApplicationUtil *appUtil = ApplicationUtil::getInstance();

    if(numRounds < MessageLength)
    {
        rounds = numRounds;

        //Symmetric key generation
        for(int ind =0 ; ind < (int)numNodes; ind++)
        {
            SecByteBlock priv, pub;
            generateKeys(ind,appUtil);
        }

        //send the public key to everyone
        for (int index1 = 0; index1 < (int)numNodes; index1++)
        {

            for (int index2 = 0; index2 < (int)numNodes; index2++)
            {
                if(index1 != index2)
                {
		//	std::cout<<"Debug : Inside dcnet  1\n";
                    Ptr<Socket> recvNodeSink = Socket::CreateSocket (c.Get (index2), tid);
                    InetSocketAddress localSocket = InetSocketAddress (Ipv4Address::GetAny (),9803);
                    recvNodeSink->Bind (localSocket);
                    recvNodeSink->SetRecvCallback (MakeCallback (&ReceivePublicKey));
                  //  std::cout<<"before\n";
                    InetSocketAddress remoteSocket = InetSocketAddress (i.GetAddress (index2, 0), 9803);
                    Ptr<Socket> sourceNodeSocket = Socket::CreateSocket (c.Get (index1), tid);
                    sourceNodeSocket->Connect (remoteSocket);
                    Simulator::Schedule (Seconds(index1/1000000.0),&SendPublicKey, sourceNodeSocket,appUtil->getPublicKeyFromMap(index1),index1);

                  //  std::cout<<"after\n";
                }
            }
        }
    }
    else
    {
//	std::cout<<"Debug : Inside dcnet else part\n";
       // stage2EndTime.erase(stage2EndTime.begin());
       // stage2EndTime.push_back(Simulator::Now());
        DisplayMeasurements();
	currentStep++;
	//this method handles the anonymous receiver steps
	procedureHandle(socket);	
    }
}

void DumpPrivateKey( const CryptoPP::RSAES_OAEP_SHA_Decryptor& key )
{
   std::cout << "n: " << key.GetTrapdoorFunction().GetModulus();
   std::cout << std::endl;

   std::cout << "d: " << key.GetTrapdoorFunction().GetPrivateExponent();
   std::cout << std::endl;
   std::cout << "e: " << key.GetTrapdoorFunction().GetPublicExponent();
   std::cout << std::endl;

   std::cout << "p: " << key.GetTrapdoorFunction().GetPrime1();
   std::cout << std::endl;
   std::cout << "q: " << key.GetTrapdoorFunction().GetPrime2();
   std::cout << std::endl;
}

void DumpPublicKey( const CryptoPP::RSAES_OAEP_SHA_Encryptor& key )
{
   std::cout << "n: " << key.GetTrapdoorFunction().GetModulus();
   std::cout << std::endl;

   ////////////////////////////////////////////////////////////////
   // Not in a Public Key...
   // std::cout << "d: " << key.GetTrapdoorFunction().GetPrivateExponent();
   // std::cout << std::endl;
   std::cout << "e: " << key.GetTrapdoorFunction().GetPublicExponent();
   std::cout << std::endl;

   ////////////////////////////////////////////////////////////////
   // Not in a Public Key...
   // std::cout << "p: " << key.GetTrapdoorFunction().GetPrime1();
   // std::cout << std::endl;
   // std::cout << "q: " << key.GetTrapdoorFunction().GetPrime2();
   // std::cout << std::endl;
}

void GenerateKeyPairForNode(int nodeIndex)
{
//	params.GenerateRandomWithKeySize(rnd, 512);
	RSA::PrivateKey privKey;
	privKey.Initialize(n, e, d);

	RSA::PublicKey pubKey;
	pubKey.Initialize(n, e);

	ApplicationUtil *appUtil = ApplicationUtil::getInstance();

	appUtil->putShortLivedPublicKeyInMap(nodeIndex, publicKey);
	appUtil->putShortLivedPrivateKeyInMap(nodeIndex, privateKey);

	//std::string publiKey = "305A300D06092A864886F70D01010105000349003046024100BEDD8D4C5BB0E964C496225638823E6397CB6CA33D1B9B609B7DFE4F27C58CC5600607867564C8283E99341D5851669C4606C0A671C241416DA8F80868E29813020111";

	if(nodeIndex==0)
	{
	AutoSeededRandomPool prng;
	
	
	Integer n("0xbeaadb3d839f3b5f"), e("0x11"), d("0x21a5ae37b9959db9");

	RSA::PrivateKey privKey;
	privKey.Initialize(n, e, d);

	RSA::PublicKey pubKey;
	pubKey.Initialize(n, e);

	/////////////////////////////////////////////////////////

	std::string pubKeyString1, encodedPub1;

	pubKey.Save(CryptoPP::StringSink(pubKeyString1).Ref());

	StringSource( pubKeyString1, true,
		    new HexEncoder(
			new StringSink( encodedPub1 )
		    ) // HexEncoder
		);

	std::cout<<"Key : "<< encodedPub1<<"\n";
	std::string message, recovered;
	Integer m, c, r;
	
	message = "secret";
	std::cout << "message: " << message << "\n";
	
	// Treat the message as a big endian array
	m = Integer((const byte *)message.data(), message.size());
	std::cout << "m: " << hex << m << "\n";

	// Encrypt
	c = pubKey.ApplyFunction(m);
	std::cout << "c: " << hex << c << "\n";

	// Decrypt
	r = privKey.CalculateInverse(prng, c);
	std::cout << "r: " << hex << r << "\n";

	// Round trip the message
	size_t req = r.MinEncodedSize();
	recovered.resize(req);
	r.Encode((byte *)recovered.data(), recovered.size());

	std::cout << "recovered: " << recovered << "\n";


	RSA::PublicKey pubKey1;
	pubKey1.Initialize(n, e);

	std::string pubKeyString2, encodedpub2;

	pubKey1.Save(CryptoPP::StringSink(pubKeyString2).Ref());

	StringSource( pubKeyString2, true,
		    new HexEncoder(
			new StringSink( encodedpub2 )
		    ) // HexEncoder
		);
	std::cout<<"Key : "<< encodedpub2<<"\n";
	}

}	

int main (int argc, char *argv[])
{

    NS_LOG_UNCOND("Inside Main");

    ApplicationUtil *appUtil = ApplicationUtil::getInstance();

    CommandLine cmd;
	
    std::cout<<"argc : "<<argc<<"\n";

    cmd.AddValue ("numNodes", "Number of Nodes", numNodes);
    cmd.AddValue ("message", "Actual Message", Message);
    cmd.AddValue ("option", "Changing numnodes or messagelength", option);	  
    //cmd.AddValue ("sender", "Sender of the message (actually anonymous)", sender);

    cmd.Parse (argc, argv);
    // Convert to time object
    //Time interPacketInterval = Seconds (interval);

    // disable fragmentation for frames below 2200 bytes
    Config::SetDefault ("ns3::WifiRemoteStationManager::FragmentationThreshold", StringValue ("2200"));
    // turn off RTS/CTS for frames below 2200 bytes
    Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold", StringValue ("2200"));
    // Fix non-unicast data rate to be the same as that of unicast
    Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode",
                        StringValue (phyMode));


    c.Create (numNodes);
    for(int nodeind = 0; nodeind < numNodes; nodeind++)
    {
	GenerateKeyPairForNode(nodeind);
        appUtil->putNodeInMap(c.Get(nodeind),nodeind);
    }
    // The below set of helpers will help us to put together the wifi NICs we want
    WifiHelper wifi;
    if (verbose)
    {
        wifi.EnableLogComponents ();  // Turn on all Wifi logging
    }

    YansWifiPhyHelper wifiPhy =  YansWifiPhyHelper::Default ();
    // set it to zero; otherwise, gain will be added
    wifiPhy.Set ("RxGain", DoubleValue (0) );
    // ns-3 supports RadioTap and Prism tracing extensions for 802.11b
    wifiPhy.SetPcapDataLinkType (YansWifiPhyHelper::DLT_IEEE802_11_RADIO);

    YansWifiChannelHelper wifiChannel;
    wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss ("ns3::FriisPropagationLossModel");
    wifiPhy.SetChannel (wifiChannel.Create ());

    // Add a non-QoS upper mac, and disable rate control
    NqosWifiMacHelper wifiMac = NqosWifiMacHelper::Default ();
    wifi.SetStandard (WIFI_PHY_STANDARD_80211a);
    wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                  "DataMode",StringValue (phyMode),
                                  "ControlMode",StringValue (phyMode));






    // Set it to adhoc mode
    wifiMac.SetType ("ns3::AdhocWifiMac");
    NetDeviceContainer devices = wifi.Install (wifiPhy, wifiMac, c);


    MobilityHelper mobility;
    mobility.SetPositionAllocator ("ns3::GridPositionAllocator",
                                   "MinX", DoubleValue (0.0),
                                   "MinY", DoubleValue (0.0),
                                   "DeltaX", DoubleValue (distance),
                                   "DeltaY", DoubleValue (distance),
                                   "GridWidth", UintegerValue (20),
                                   "LayoutType", StringValue ("RowFirst"));
    mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
    mobility.Install (c);


    Ipv4StaticRoutingHelper staticRouting;

    Ipv4ListRoutingHelper list;
    list.Add (staticRouting, 0);



    InternetStackHelper internet;
    internet.SetRoutingHelper (list); // has effect on the next Install ()
    internet.Install (c);

    Ipv4AddressHelper ipv4;
    NS_LOG_INFO ("Assign IP Addresses.");
    ipv4.SetBase ("10.1.1.0", "255.255.255.0");
    i = ipv4.Assign (devices);

    tid = TypeId::LookupByName ("ns3::UdpSocketFactory");


    AnnouncementPacketCount = (numNodes * numNodes) - numNodes;
    publicKeyCounter = (numNodes * numNodes) - numNodes;
    randomBitCounter = (numNodes * (numNodes-1)/2);


  //  std::cout<<"Actual Message : "<<Message<<"\n";
 //   MessageLength = (int)strlen(Message.c_str()) ;
  //  std::cout<<"Message length:"<<MessageLength<<"\n";
    source = Socket::CreateSocket (c.Get (0), tid);
   // DCNET(source, 0);


//****************************anonymous receiver part*******************************************

// Generate a random IV and a common IV
AESrnd.GenerateBlock(AESiv, AES::BLOCKSIZE);


//step 1 - Node A sends Message to all nodes using DCNet

AnonymousReceiverStep1();


//**********************************************************************************************

    if (tracing == true)
    {
        AsciiTraceHelper ascii;
        wifiPhy.EnableAsciiAll (ascii.CreateFileStream ("wifi-simple-adhoc-grid.tr"));
        wifiPhy.EnablePcap ("wifi-simple-adhoc-grid", devices);
        // Trace routing tables
        Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper> ("wifi-simple-adhoc-grid.routes", std::ios::out);


        // To do-- enable an IP-level trace that shows forwarding events only
    }

    //Simulator::Stop (Seconds (3000.0));
    Simulator::Run ();
Simulator::Destroy ();
    

    return 0;
}
