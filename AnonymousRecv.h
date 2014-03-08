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
	    	senderPublicKey = appUtil->getShortLivedPublicKeyFromMap(senderNode);
		
	
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
		//std::cout<<"Message in binary format\n";
		//std::cout<<Message;
		//decode_binary(Message.c_str());  - correctly working
		//decode_binary(sharedMessage.str().c_str()); - is also working

	}

	if(sourceControl == MESSAGE_SET)
	{
		
		// Generate a random key	
		AESrnd.GenerateBlock( AESkey, AESkey.size() );
		std::string AESKey_String = hexStr(AESkey.BytePtr(), AESkey.SizeInBytes());
		appUtil->putAESKeyInMap(senderNode,AESkey);
		std::cout<<"************Actual sent AES key : "<<AESKey_String<<"\n";
		std::string sendPublicKey, encodedPublicKey;
		//node A public key
		sendPublicKey = appUtil->getShortLivedPublicKeyforMsgIdFromMap(senderNode,atoi(sourceMessageId.c_str()));
	
/*	StringSource( sendPublicKey, true,
		    new HexEncoder(
			new StringSink( encodedPublicKey )
		    ) // HexEncoder
		);
*/
	      std::cout<<"***************Sent message id : "<<sourceMessageId<<"\n";
		Message = encoded_message_set(sourceControl, sourceMessageId, AESKey_String, sendPublicKey);
		MessageLength = (int)strlen(Message.c_str()) ;	
		std::cout<<"message : "<<Message<<"\n";
		sharedMessage.str("");
		DCNET(socket, 0);	
		
				
	}
	if(sourceControl == MESSAGE_REPLY)
	{
		
	}
}
