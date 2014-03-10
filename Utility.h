#define MAX_MESSAGE_ID_LENGTH 12
#define MESSAGE_TYPE_LENGTH 3
#define MESSAGE_END       "zzzzz"
#define MESSAGE_END_LENGTH  5
#define INITIATE_MESSAGE "MSG"
#define MESSAGE_SET      "SET"
#define MESSAGE_REPLY     "REP"

std::vector<char> convert_to_ascii(const char*);   //function for converting ASCII to Binary
std::vector<char> convert_to_binary(const char*);   //function for converting Binary to ASCII
std::vector<char>  get_message(std::string control,std::string msgid, std::string message,std::string publickey) ;
std::string decode_binary(int recvNode, const char *input);
std::string decrypt_message(int recvNode, std::string input);
std::string encrypt_message_public_key(std::string input, std::string publicKey);
std::string encoded_message_initiate(std::string control,std::string msgid,std::string message,std::string key) ;
void submit_initiate_message(void);
std::string  encoded_message_set(std::string control,std::string msgid,std::string key, std::string publicKey) ;
std::string  encoded_message_reply(std::string control,std::string msgid, std::string message,std::string key) ;

std::string cipher,encoded;
std::string recovered;

std::string process_input_to_cipher(std::string message, RSA::PublicKey pubKey)
{
	Integer m, c;
	std::vector<std::string> messageVector;
	int done = 1;
	while(done)
	{
		std::string temp;
		if(message.length() > 8)
			temp = message.substr(0,8);
		else 
			temp = message.substr(0);
		messageVector.push_back(temp);
		if((message.length() - 8) > 8)
			message = message.substr(8);
		else
		{
			done = 0;
			message = message.substr(8);
			messageVector.push_back(message);
		}
	}
	
	std::ostringstream appendedCipherText;
	std::vector<std::string>::iterator itr;
	for ( itr = messageVector.begin(); itr != messageVector.end(); ++itr )
	{		
		std::string tempmessage = *(itr);
		// Treat the message as a big endian array
	
		m = Integer((const byte *)tempmessage.data(), tempmessage.size());

		//convert m to str and try converting back
	
		c = pubKey.ApplyFunction(m);
		std::ostringstream s;
	    	s<<c;
	    	std::string ss(s.str());
		appendedCipherText<<c;
	}
	std::string cipherText = appendedCipherText.str();
	return cipherText;
}

std::string process_cipher_to_plainText(std::string cipherText, RSA::PrivateKey privKey)
{
	std::vector<std::string> cipherTextVector;
	int complete = 1;
	std::string tempStr ;
	while(complete)
	{  
		std::size_t found = cipherText.find(".");
		if (found!=std::string::npos)
		{		
			tempStr = cipherText.substr(0,found+1);
			cipherText = cipherText.substr(found+1);
			cipherTextVector.push_back(tempStr);
		}
		else
		{
			complete = 0;		
			tempStr = cipherText;
		}
	}

	std::vector<std::string>::iterator itr2;
	std::ostringstream plainTextStream;
	std::string plainText;
	for ( itr2 = cipherTextVector.begin(); itr2 != cipherTextVector.end(); ++itr2 )
	{
		std::string text = *(itr2);
		Integer cint (text.c_str()), r;	
		r = privKey.CalculateInverse(rnd, cint);

		size_t req = r.MinEncodedSize();
		recovered.resize(req);
		r.Encode((byte *)recovered.data(), recovered.size());
		plainTextStream<<recovered;
	}
	plainText = plainTextStream.str();
	return plainText;
}

std::string decrypt_message_private_key(int recvNode, std::string cipherText)
{
	std::string plainText = "";
	ApplicationUtil *appUtil = ApplicationUtil::getInstance();
	std::string priv = appUtil->getShortLivedPrivateKeyFromMap(recvNode);

	RSA::PrivateKey privKey = process_privateKey(priv);
	plainText = process_cipher_to_plainText(cipherText,privKey);
	return plainText ; //need to be impelemented using AES decryption key
}

std::string encrypt_message_public_key(std::string input, std::string publicKey)
{
	CryptoPP::RSA::PublicKey pub;
	pub = process_publicKey(publicKey);
	std::string cipher;
	cipher = process_input_to_cipher(input, pub);
	return cipher; 
}

std::string encrypt_with_aes_key(std::string message, SecByteBlock AESkey)
{
	CFB_Mode<AES>::Encryption cfbEncryption;
	cfbEncryption.SetKeyWithIV( AESkey, AESkey.size(), AESiv );

	StringSource( message, true, 
        new StreamTransformationFilter( cfbEncryption,
            new StringSink( cipher )
        ) // StreamTransformationFilter      
        );
	
	StringSource( cipher, true,
	    new HexEncoder(
		new StringSink( encoded )
	    ) // HexEncoder
	); // StringSource

	 return encoded; 
}

std::string  encoded_message_set(std::string control,std::string msgid,std::string key, std::string publicKey) 
{   
	std::string encoded_message;
	encoded_message=msgid+key;		
	encoded_message=control + encrypt_message_public_key(encoded_message, publicKey);
	std::vector<char> binary= convert_to_binary(encoded_message.c_str());
	std::string binaryresult(binary.begin(),binary.end()); 
	return binaryresult;
}
std::string  encoded_message_reply(std::string control,std::string msgid, std::string message,SecByteBlock key) 
{   
	std::string encoded_message;
	encoded_message=msgid+message;
    	encoded_message=control + encrypt_with_aes_key(encoded_message, key);

    	std::vector<char> binary= convert_to_binary(encoded_message.c_str());
	std::string binaryresult(binary.begin(),binary.end()); 
    	return binaryresult;
}

std::string encoded_message_initiate(std::string control,std::string msgid,std::string message,std::string public_key) 
{   
	std::string encoded_message;
	if(message=="") 
		encoded_message=control+msgid;
    	else 
		encoded_message=control+msgid+message+MESSAGE_END;
    	if(public_key!="") 
		encoded_message= encoded_message+public_key;
    	std::vector<char> binary= convert_to_binary(encoded_message.c_str());
	std::string binaryresult(binary.begin(),binary.end()); 
    	return binaryresult;
}

std::string decrypt_message_AES(std::string input, SecByteBlock AESkey)
{
	CFB_Mode<AES>::Decryption cfbDecryption;
	cfbDecryption.SetKeyWithIV( AESkey, AESkey.size(), AESiv );
	std::string decodedcipher;
	StringSource( input, true,
	    new HexDecoder(
		new StringSink( decodedcipher )
	    ) // HexDecoder
	);
	
	StringSource( decodedcipher, true, 
		new StreamTransformationFilter( cfbDecryption,
		    new StringSink( recovered )
		) // StreamTransformationFilter
	    );

	//temp fix - as the decrypted plain text has some junk characters in teh front - TODO assuming messagae format to be 000-ddd-1111 
	std::size_t found = recovered.find('-');
	std::cout<<"Found : "<<recovered << "   : " <<found <<"\n";
	if (found!=std::string::npos)
	{
		recovered = recovered.substr(found - 3);
	}	
	return recovered; 
}

std::string decode_binary(int recvNode, const char *input)
{
	std::vector<char> ascii= convert_to_ascii(input);
    	std::string asciiresult(ascii.begin(),ascii.end());
   	return decrypt_message(recvNode, asciiresult);
}

//Brute force method - iterate thru each used AES key and try to decrypt
std::string process_Decrypted_Message(int recvNode, std::string cipherText)
{
	ApplicationUtil *appUtil = ApplicationUtil::getInstance();
	std::string messageid;
	std::vector<SecByteBlock> usedAESKeyVector = appUtil->getUsedAESKeyVector(recvNode);
	std::vector<SecByteBlock>::iterator itr;
	std::string receivedPlainText = "";
	for ( itr = usedAESKeyVector.begin(); itr != usedAESKeyVector.end(); ++itr )
	{
		SecByteBlock currentKey = *(itr);
		std::cout<<"Received cipher text :"<< cipherText<<"\n";
		receivedPlainText = decrypt_message_AES(cipherText, currentKey);		
		std::cout<<"Received Plain text :"<< receivedPlainText<<"\n";
		if(receivedPlainText.length() < MAX_MESSAGE_ID_LENGTH )
			continue;
		messageid= receivedPlainText.substr(0, MAX_MESSAGE_ID_LENGTH);
	std::cout<<"Msg id :"<< messageid<<"\n";
		std::size_t found = messageid.find('-');
		if (found!=std::string::npos)
    			return receivedPlainText;
	}
	return receivedPlainText;
}

std::string decrypt_message(int recvNode, std::string input)
{
	std::string messageid;
	ApplicationUtil *appUtil = ApplicationUtil::getInstance();
	std::string message_type= input.substr(0,MESSAGE_TYPE_LENGTH);
	std::cout<<"Input : "<<input<<"\n";
	if(message_type==MESSAGE_REPLY) 
	{
		// first decrypt the data with all used AES keys and then get the msg id and Message
		std::cout<<"Inside reply message "<<MESSAGE_TYPE_LENGTH<<"   "<<input.length()<<"\n";
		std::string decrypted_message=  process_Decrypted_Message(recvNode, input.substr(MESSAGE_TYPE_LENGTH));
        	messageid= decrypted_message.substr(0, MAX_MESSAGE_ID_LENGTH);
		
		unsigned found= decrypted_message.find(MESSAGE_END);
		std::string message= decrypted_message.substr(MAX_MESSAGE_ID_LENGTH,found-MAX_MESSAGE_ID_LENGTH);
		std::cout<<"Node "<<recvNode<<" received reply Message \""<<message<<"\"\n";
    	}
        else if(message_type==MESSAGE_SET) 
	{
		std::string message_id_aes_key= decrypt_message_private_key(recvNode, input.substr(MESSAGE_TYPE_LENGTH));
		messageid = message_id_aes_key.substr(0, MAX_MESSAGE_ID_LENGTH);
	        std::string aes_key= message_id_aes_key.substr(MAX_MESSAGE_ID_LENGTH);
		
		//not able to convert from aes string format to secbyteblock. Temporary fix using global AESkey variable- TODO
		SecByteBlock aesKey = AESkey;
		appUtil->putReceivedAESKeyForMsgIdInMap(recvNode,messageid, aesKey);
		std::cout<<"Node "<<recvNode<<" received AES key\n";
	 }
	else 
	{         
		messageid= input.substr(3, MAX_MESSAGE_ID_LENGTH);
		//now find the delimter of message
		unsigned found= input.find(MESSAGE_END);
		std::string message= input.substr(MAX_MESSAGE_ID_LENGTH+3,found-MAX_MESSAGE_ID_LENGTH-MESSAGE_TYPE_LENGTH);
	    	std::string public_key= input.substr(found+MESSAGE_END_LENGTH);
	    	//store public key in map 
		std::cout<<"Node "<<recvNode<<" received actual Message \""<<message<<"\"\n";
		std::string decodedPublic_Key;
		StringSource( public_key, true,
		    new HexDecoder(
			new StringSink( decodedPublic_Key )
		    ) // HexDecoder
		);
		appUtil->putShortLivedPublicKeyforMsgIdInMap(recvNode, atoi(messageid.c_str()),decodedPublic_Key);
	}

	return messageid;
}
std::vector<char> convert_to_binary(const char* input) 
{
	int ascii;           
	int length = strlen(input);        
   	std::vector<char> ascii_binary; 
   	for(int x = 0; x < length; x++) {
		ascii = input[x];        		
		char* binary_reverse = new char [9];     
		int y = 0;   
		while(ascii != 1) {   
			if(ascii % 2 == 0) binary_reverse[y] = '0';  
            else if(ascii % 2 == 1) binary_reverse[y] = '1';   
			ascii /= 2;   
			y++;   
		}
		if(ascii == 1) { 
			binary_reverse[y] = '1';
            y++;
		}
		if(y < 8) { 
			for(; y < 8; y++) {
				binary_reverse[y] = '0';
			}
		}
	    for(int z = 0; z < 8; z++) {
			ascii_binary.push_back(binary_reverse[7 - z] );
		}
        delete [] binary_reverse;    
	}
    return ascii_binary ;
}

std::vector<char> convert_to_ascii(const char* input)
{
	int length = strlen(input);    
	std::vector<char> binary_ascii;
	int binary[8];    
	int asciiNum = 0;      
	char ascii;      
	std::cout << " ";
	int z = 0;  
	for(int x = 0; x < length / 8; x++) {   
		for(int a = 0; a < 8; a++) {     
			binary[a] = (int) input[z] - 48;     
			z++;
		}
		int power[8];    
		int counter = 7;        
		for(int x = 0; x < 8; x++) {
			power[x] = counter;      
			counter--;    
		}
		for(int y = 0; y < 8; y++) {
			double a = binary[y];    
			double b = power[y];    
			asciiNum += a* pow(2, b);  
		}
		ascii = asciiNum;   
		asciiNum = 0;    
		binary_ascii.push_back(ascii);
    }
	return binary_ascii;
}
