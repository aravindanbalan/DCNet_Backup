void DCNET(Ptr<Socket> socket, int numRounds);

static void SendMessageUsingDCNET (Ptr<Socket> socket,int senderNode, std::string sourceControl, std::string sourceMessageId, std::string sourceMessage)
{
	ApplicationUtil *appUtil = ApplicationUtil::getInstance();
	sender = senderNode;
	if(sourceControl == INITIATE_MESSAGE)
	{
		std::string senderPublicKey, encodedPublicKey;
	    	senderPublicKey = appUtil->getShortLivedPublicKeyFromMap(senderNode);
	
		StringSource( senderPublicKey, true,
		    new HexEncoder(
			new StringSink( encodedPublicKey )
		    ) // HexEncoder
		);

		Message = encoded_message_initiate(sourceControl, sourceMessageId, sourceMessage, encodedPublicKey );
		MessageLength = (int)strlen(Message.c_str()) ;
		totalTimeStart = Simulator::Now();  	
		DCNET(socket, 0);
	}
	if(sourceControl == MESSAGE_SET)
	{	 
		// Generate a random key	
		AESrnd.GenerateBlock( AESkey, AESkey.size());
		// Generate a random IV
		AESrnd.GenerateBlock(AESiv, AES::BLOCKSIZE);

		std::string AESKey_String = hexStr(AESkey.BytePtr(), AESkey.SizeInBytes());
		appUtil->putUsedAESKeyInMap(senderNode,AESkey);
		std::string sendPublicKey, encodedPublicKey;
		//node A public key
		sendPublicKey = appUtil->getShortLivedPublicKeyforMsgIdFromMap(senderNode,atoi(sourceMessageId.c_str()));
	
		Message = encoded_message_set(sourceControl, sourceMessageId, AESKey_String, sendPublicKey);
		MessageLength = (int)strlen(Message.c_str()) ;	
		
		sharedMessage.str("");
		DCNET(socket, 0);				
	}
	if(sourceControl == MESSAGE_REPLY)
	{
		SecByteBlock senderAESKey = appUtil->getReceivedAESKeyForMsgId(senderNode, sourceMessageId);
		Message = encoded_message_reply(sourceControl, sourceMessageId, sourceMessage, senderAESKey);
		MessageLength = (int)strlen(Message.c_str()) ;	
		
		sharedMessage.str("");
		DCNET(socket, 0);
	}
}
