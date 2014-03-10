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
		//put in sentAESkey for msg id map
		appUtil->putSentAESKeyForMsgIdInMap(senderNode, sourceMessageId, AESkey);

		std::string sendPublicKey, encodedPublicKey;
		//node A public key
		sendPublicKey = appUtil->getShortLivedPublicKeyforMsgIdFromMap(senderNode,sourceMessageId);
	
		Message = encoded_message_set(sourceControl, sourceMessageId, AESKey_String, sendPublicKey);
		MessageLength = (int)strlen(Message.c_str()) ;	
		
		sharedMessage.str("");
		DCNET(socket, 0);				
	}
	if(sourceControl == MESSAGE_REPLY)
	{
		SecByteBlock reply_senderAESKey = appUtil->getSentAESKeyForMsgId(senderNode, sourceMessageId);
		Message = encoded_message_reply(sourceControl, sourceMessageId, sourceMessage, reply_senderAESKey);
		MessageLength = (int)strlen(Message.c_str()) ;	
		
		sharedMessage.str("");
		DCNET(socket, 0);
	}
}
