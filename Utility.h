
#define MAX_MESSAGE_ID_LENGTH 12
#define MESSAGE_TYPE_LENGTH 3
#define MESSAGE_END       "zzzzz"
#define MESSAGE_END_LENGTH  5
#define INITIATE_MESSAGE "MSG"
#define MESSAGE_SET      "SET"
#define MESSAGE_REPLY     "REP"



SecByteBlock AESkey(0x00, AES::DEFAULT_KEYLENGTH);
byte AESiv[AES::BLOCKSIZE];
AutoSeededRandomPool AESrnd;
std::vector<char> convert_to_ascii(const char*);   //function for converting ASCII to Binary
std::vector<char> convert_to_binary(const char*);   //function for converting Binary to ASCII
std::vector<char>  get_message(std::string control,std::string msgid, std::string message,std::string publickey) ;
int decode_binary(int recvNode, const char *input);
int decrypt_message(int recvNode, std::string input);
std::string encrypt_message_public_key(std::string input, std::string publicKey);
std::string encoded_message_initiate(std::string control,std::string msgid,std::string message,std::string key) ;
void submit_initiate_message(void);
std::string  encoded_message_set(std::string control,std::string msgid,std::string key, std::string publicKey) ;
std::string  encoded_message_reply(std::string control,std::string msgid, std::string message,std::string key) ;
int msgL =0;
std::string cipher,encoded;
std::string recovered;


std::string encrypt_message_public_key(std::string input, std::string publicKey)
{
	return input ; //need to be impelemented using AES decryption key
}

std::string submit_initiate_message(std::string key, std::string control, std::string messageid, std::string message)
{
//	std::string key=                                                                         "ab359aa76a6773ed7a93b214db0c25d0160817b8a893c001c761e198a3694509ebe8"
//"7a5313e0349d95083e5412c9fc815bfd61f95ddece43376550fdc624e92ff38a415783b9726120"
//"4e05d65731bba1ccff0e84c8cd2097b75feca1029261ae19a389a2e15d2939314b184aef707b82"
//"eb94412065181d23e04bf065f4ac413fh";
//	std::string control=INITIATE_MESSAGE;
  //  std::string messageid="000-000-0001";
 //   std::string message="Hello I am working on Encrypting and decrypting data. Do you like this. I do. This is very interesting project and perhaps you can submit it to conference";
    
    //std::cout<< "Length : "<<binaryresult.length()<<"\n";
    //std::cout << "binary representation of a std::string :" << binaryresult << "\n";

	std::string binaryresult = encoded_message_initiate(control,messageid,message,key);   // now you get a message and send this message using DCNET
  //  decode_binary(binaryresult.c_str());
	return binaryresult;   
}

void submit_set_message(void)
{
	std::string control=MESSAGE_SET;
    std::string messageid="000-000-0001";
    std::string key="B374A26A71490437AA024E4FADD5B497FDFF1A8EA6FF12F6FB65AF2720B59CCF";
    std::string message = "";
  //  std::string binaryresult=encoded_message_set(control,messageid,key);   // now you get a message and send this message using DCNET
  //  decode_binary(binaryresult.c_str());  
}

void submit_reply_message(void)
{
	std::string control=MESSAGE_REPLY;
    std::string messageid="000-000-0001";
    std::string key="";
    std::string message = "Now I am communicating privately with some node and nobody can infer this message";
    std::string binaryresult=encoded_message_reply(control,messageid,message,key);   // now you get a message and send this message using DCNET
	//std::cout<<"****Binary result  : "<<binaryresult<<"\n";
   // decode_binary(binaryresult.c_str());  
}

/*
int main(void)
{
    
	submit_initiate_message();
	std::cout<<"\n";
    submit_set_message();
std::cout<<"\n";
    submit_reply_message(); 
   
    return 0;
}

*/
std::string encrypt_with_aes_key(std::string message)
{
	// Generate a random key	
	AESrnd.GenerateBlock( AESkey, AESkey.size() );
	// Generate a random IV
	AESrnd.GenerateBlock(AESiv, AES::BLOCKSIZE);

	 

	msgL = message.length() + 1;

	CFB_Mode<AES>::Encryption cfbEncryption;
	cfbEncryption.SetKeyWithIV( AESkey, AESkey.size(), AESiv );
	//cfbEncryption.ProcessData((byte*)message.c_str(), (byte*)message.c_str(), msgL);
	
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
//::cout << "****************Hex encoded text: " << encoded <<"\n\n";

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
std::string  encoded_message_reply(std::string control,std::string msgid, std::string message,std::string key) 
{   
	std::string encoded_message;
	encoded_message=msgid+message;
    encoded_message=control + encrypt_with_aes_key(encoded_message);
	//std::cout <<"***********Total Encoded message : "<<encoded_message<<"\n\n";

    std::vector<char> binary= convert_to_binary(encoded_message.c_str());
	std::string binaryresult(binary.begin(),binary.end()); 
    return binaryresult;
}

std::string encoded_message_initiate(std::string control,std::string msgid,std::string message,std::string public_key) 
{   
	std::string encoded_message;
	if(message=="") encoded_message=control+msgid;
    else encoded_message=control+msgid+message+MESSAGE_END;
    if(public_key!="") encoded_message= encoded_message+public_key;
    std::vector<char> binary= convert_to_binary(encoded_message.c_str());
	std::string binaryresult(binary.begin(),binary.end()); 
    return binaryresult;
}

std::string decrypt_message_AES(std::string input)
{
	
	CFB_Mode<AES>::Decryption cfbDecryption;
	cfbDecryption.SetKeyWithIV( AESkey, AESkey.size(), AESiv );
	//cfbDecryption.ProcessData((byte*)input.c_str(), (byte*)input.c_str(), msgL);
//std::cout<<"*************input before hex decoding : "<< input<<"\n\n";
	std::string decodedcipher;
	StringSource( input, true,
	    new HexDecoder(
		new StringSink( decodedcipher )
	    ) // HexDecoder
	);
//std::cout<<"*************input after hex decoding : "<< input<<"\n\n";

	StringSource( decodedcipher, true, 
		new StreamTransformationFilter( cfbDecryption,
		    new StringSink( recovered )
		) // StreamTransformationFilter
	    );

	return recovered; 
}


std::string decrypt_message_private_key(std::string input)
{
	return input ; //need to be impelemented using AES decryption key
}

int decode_binary(int recvNode, const char *input)
{
	std::vector<char> ascii= convert_to_ascii(input);
    std::string asciiresult(ascii.begin(),ascii.end());

	//std::cout<<"************ascii : "<<asciiresult.c_str()<<"\n\n";
   return decrypt_message(recvNode, asciiresult);
}

int decrypt_message(int recvNode, std::string input)
{
	std::string messageid;
	std::string message_type= input.substr(0,MESSAGE_TYPE_LENGTH);
    std::cout <<"message_type: " << message_type << "\n";
	if(message_type==MESSAGE_REPLY) {
		// first decrypt the data with AES and then get the msg id and Message
		std::string decrypted_message=  decrypt_message_AES(input.substr(MESSAGE_TYPE_LENGTH));
   //     std::cout << "sending to decrypt the input with aes key " << "\n";
    //    std::cout << "successfully decrypting with my aes key" << "\n";
     //   std::cout << "got message id and message" << "\n";
        messageid= decrypted_message.substr(0, MAX_MESSAGE_ID_LENGTH);
		std::cout <<"message_id: " << messageid<<"\n";
		unsigned found= decrypted_message.find(MESSAGE_END);
		std::string message= decrypted_message.substr(MAX_MESSAGE_ID_LENGTH,found-MAX_MESSAGE_ID_LENGTH);
        std::cout <<"message is:"<< message <<"\n";
    }
    else {
        if(message_type==MESSAGE_SET) {
	//		std::cout << "sending to decrypt the input with private key " << "\n";
        //    std::cout << "successfully decrypting with my private key" << "\n";
         //   std::cout << "got message id and aes key" << "\n";
       		std::string message_id_aes_key= decrypt_message_private_key(input.substr(MESSAGE_TYPE_LENGTH));
            //now get the aes key and messageid and store it the way app wants
           
			messageid= message_id_aes_key.substr(0, MAX_MESSAGE_ID_LENGTH);
			std::cout <<"message_id: " << messageid<<"\n";
            std::string aes_key= message_id_aes_key.substr(MAX_MESSAGE_ID_LENGTH);
			std::cout << "aes_key is: " << aes_key << "\n";

		SecByteBlock aesKey((byte *)aes_key.c_str(),aes_key.size());
		

        }
        else {
         
		    //decoding first message
			messageid= input.substr(3, MAX_MESSAGE_ID_LENGTH);
			std::cout <<"message_id: " << messageid << "\n";
			//now find the delimter of message
			unsigned found= input.find(MESSAGE_END);
			std::string message= input.substr(MAX_MESSAGE_ID_LENGTH+3,found-MAX_MESSAGE_ID_LENGTH-MESSAGE_TYPE_LENGTH);
            std::cout <<"message is:"<< message <<"\n";
		    std::string public_key= input.substr(found+MESSAGE_END_LENGTH);
		    std::cout << "public key is: " << public_key <<"\n";

			//store public key in map 
		ApplicationUtil *appUtil = ApplicationUtil::getInstance();
		std::string decodedPublic_Key;
		StringSource( public_key, true,
		    new HexDecoder(
			new StringSink( decodedPublic_Key )
		    ) // HexDecoder
		);
		
		//assuming that this is working from str to publickey class object    
		CryptoPP::RSA::PublicKey pub;
    		pub.Load(const_cast<BufferedTransformation &>(*(CryptoPP::StringSource(decodedPublic_Key, true).AttachedTransformation())));	
			
		//put in msgid-Publickey map
		appUtil->putShortLivedPublicKeyforMsgIdInMap(recvNode, atoi(messageid.c_str()),pub);
		}
    }

	return atoi(messageid.c_str());
  
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
