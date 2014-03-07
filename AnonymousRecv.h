static void anonymousReceiver (Ptr<Socket> socket,int senderNode, std::string sourceControl, std::string sourceMessageId, std::string sourceMessage)
{
	ApplicationUtil *appUtil = ApplicationUtil::getInstance();
	std::cout<<"Inside Anonymous receiver code\n";
	sender = senderNode;

	MessageLength = (int)strlen(sourceMessage.c_str()) ;
    	std::cout<<"Message length:"<<MessageLength<<"\n";
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
	//DCNET(socket, 0);
	std::cout<<"Message in binary format\n";
	//std::cout<<Message;
	//decode_binary(Message.c_str());  - correctly working
}
