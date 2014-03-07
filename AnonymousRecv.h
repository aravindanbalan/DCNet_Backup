void DCNET(Ptr<Socket> socket, int numRounds);

static void SendMessageUsingDCNET (Ptr<Socket> socket,int senderNode, std::string sourceControl, std::string sourceMessageId, std::string sourceMessage)
{
	ApplicationUtil *appUtil = ApplicationUtil::getInstance();
	sender = senderNode;
	if(sourceControl == INITIATE_MESSAGE)
	{
		
		std::cout<<"Inside Anonymous receiver code\n";
		
	
		//Message = message;

		std::string senderPublicKey, encodedPublicKey;
	    	appUtil->getShortLivedPublicKeyFromMap(senderNode).Save(CryptoPP::StringSink(senderPublicKey).Ref());

	
		StringSource( senderPublicKey, true,
		    new HexEncoder(
			new StringSink( encodedPublicKey )
		    ) // HexEncoder
		);

		std::cout<<"Public key of node A : "<<encodedPublicKey<<"\n";

		Message = encoded_message_initiate(sourceControl, sourceMessageId, sourceMessage, encodedPublicKey );

		MessageLength = (int)strlen(Message.c_str()) ;
		totalTimeStart = Simulator::Now();  	
		DCNET(socket, 0); //- working
		std::cout<<"Message in binary format\n";
		//std::cout<<Message;
		//decode_binary(Message.c_str());  - correctly working
		//decode_binary(sharedMessage.str().c_str()); - is also working

	}

	if(sourceControl == MESSAGE_SET)
	{
		
		// Generate a random key	
		AESrnd.GenerateBlock( AESkey, AESkey.size() );
		std::string AESKey_String = hexStr(AESkey.BytePtr(), AESkey.SizeInBytes());


		std::string sendPublicKey, encodedPublicKey;
		//node A public key
		appUtil->getShortLivedPublicKeyforMsgIdFromMap(senderNode,atoi(sourceMessageId.c_str())).Save(CryptoPP::StringSink(sendPublicKey).Ref());

		StringSource( sendPublicKey, true,
		    new HexEncoder(
			new StringSink( encodedPublicKey )
		    ) // HexEncoder
		);

		Message = encoded_message_set(sourceControl, sourceMessageId, AESKey_String, encodedPublicKey);
		MessageLength = (int)strlen(Message.c_str()) ;		
	}
}
