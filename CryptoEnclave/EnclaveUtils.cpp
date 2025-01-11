#include "EnclaveUtils.h"
#include "CryptoEnclave_t.h"

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "../common/data_type.h"
#include <bitset>

void printf( const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

void print_bytes(uint8_t *ptr, uint32_t len) {
  for (uint32_t i = 0; i < len; i++) {
    printf("%x", *(ptr + i));
  }

  printf("\n");
}


int  cmp(const uint8_t *value1, const uint8_t *value2, uint32_t len){
    for (uint32_t i = 0; i < len; i++) {
        if (*(value1+i) != *(value2+i)) {
        return -1;
        }
    }

    return 0;
}

void  clear(uint8_t *dest, uint32_t len){
    for (uint32_t i = 0; i < len; i++) {
        *(dest + i) = 0;
    }
}

std::vector<std::string>  wordTokenize(char *content,int content_length){
    char delim[] = ",";//" ,.-";
    std::vector<std::string> result;

    char *content_cpy = (char*)malloc(content_length);
    memcpy(content_cpy,content,content_length);

    char *token = strtok(content_cpy,delim);
    while (token != NULL )
    {
            result.push_back(token); 
            token =  strtok(NULL,delim);
    }

    free(token);
    free(content_cpy);
    //the last , will be counted
    //result.erase(result.end()-1);

    return result;
}


//void to_bytes( const AVLIndexNode& object, unsigned char* des){
//    const unsigned char* begin = reinterpret_cast<const unsigned char*>(std::addressof(object));
//    memcpy(des, begin, sizeof(AVLIndexNode));
//}

//void from_bytes(const unsigned char* res, AVLIndexNode& object){
//    unsigned char* begin_object = reinterpret_cast<unsigned char*> (std::addressof(object));
//    memcpy(begin_object,res,sizeof(AVLIndexNode));
//}


//PRF
void prf_F_improve(const void *key,const void *plaintext,size_t plaintext_len, entryKey *k ){

    //k->content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + plaintext_len; //important- has to be size_t
	//k->content = (char *) malloc(k->content_length);
	enc_aes_gcm(key,plaintext,plaintext_len,k->content,k->content_length);

}

void prf_Enc_improve(const void *key,const void *plaintext,size_t plaintext_len, entryValue *v){

    //v->message_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + plaintext_len; //important- has to be size_t
	//v->message = (char *) malloc(v->message_length);
	enc_aes_gcm(key,plaintext,plaintext_len,v->message,v->message_length);
}


void prf_Dec_Improve(const void *key,const void *ciphertext,size_t ciphertext_len, entryValue *value ){


    //value->message_length = ciphertext_len - AESGCM_MAC_SIZE - AESGCM_IV_SIZE;
	//value->message = (char *) malloc(value->message_length);
    dec_aes_gcm(key,ciphertext,ciphertext_len,value->message,value->message_length);
}

void enc_aes_gcm(const void *key, const void *plaintext, size_t plaintext_len, void *ciphertext, size_t ciphertext_len)
{
  uint8_t p_dst[ciphertext_len] = {0};

  //p_dst = mac + iv + cipher
	sgx_rijndael128GCM_encrypt(
    (sgx_aes_gcm_128bit_key_t*)key,
		(uint8_t *) plaintext, plaintext_len,
		p_dst + AESGCM_MAC_SIZE + AESGCM_IV_SIZE, //where  the cipher should be stored
		(uint8_t *)gcm_iv, AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) p_dst);	//the tag should be the first 16 bytes and auto dumped out

  memcpy(p_dst + AESGCM_MAC_SIZE, gcm_iv, AESGCM_IV_SIZE);

  //copy tag+iv+cipher to ciphertext
  memcpy(ciphertext,p_dst,ciphertext_len);

}

void dec_aes_gcm(const void *key, const void *ciphertext, size_t ciphertext_len, void *plaintext, size_t plaintext_len){
    
    uint8_t p_dst[plaintext_len] = {0};

	sgx_status_t ret = sgx_rijndael128GCM_decrypt(
		(sgx_aes_gcm_128bit_key_t*)key,
		(uint8_t *) (ciphertext + AESGCM_MAC_SIZE + AESGCM_IV_SIZE), plaintext_len,
		p_dst,
		(uint8_t *)gcm_iv, AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) ciphertext); //get the first 16 bit tag to verify

	memcpy(plaintext, p_dst, plaintext_len);

}

//generating 128bit output digest
int hash_SHA128(const void *key, const void *msg, int msg_len, void *value){
    
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_rijndael128_cmac_msg(
            (sgx_cmac_128bit_key_t *)key,
            (const uint8_t*)msg,
            msg_len,
            (sgx_cmac_128bit_tag_t*)value);
     
    if (ret == SGX_SUCCESS) {
        return 1;
    }
    else {
        printf("[*] hash error line 87: %d\n", ret);
        return 0;
    }  
}

//make sure the key is 16 bytes and appended to the digest
int hash_SHA128_key(const void *key, int key_len, const void *msg, int msg_len, void *value){
    
    int result;
    result = hash_SHA128(key,msg,msg_len,value);
    if (result==1) {
        memcpy(value+ENTRY_HASH_KEY_LEN_128,key,key_len);
        return 1;
    } else{
        printf("[*] hash error line 163: %d\n", result);
        return 0;
    }
}


uint32_t u8_to_u32(const uint8_t* bytes) {
  // Every uint32_t consists of 4 bytes, therefore we can shift each uint8_t
  // to an appropriate location.
  // u32   ff  ff  ff  ff
  // u8[]  0   1   2   3
  uint32_t u32 = (bytes[0] << 24) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3];
  return u32;
}

// We pass an output array in the arguments because we can not return arrays
void u32_to_u8(const uint32_t u32, uint8_t* u8) { //Big endian
  // To extract each byte, we can mask them using bitwise AND (&)
  // then shift them right to the first byte.
  u8[0] = (u32 & 0xff000000) >> 24;
  u8[1] = (u32 & 0x00ff0000) >> 16;
  u8[2] = (u32 & 0x0000ff00) >> 8;
  u8[3] = u32 & 0x000000ff;
}


uint32_t genHashBlockId(std::string c_id, int v_id, int dataset_size){

    std::string str_v_id  = std::to_string(v_id);
    int p_id_len = c_id.length()  + str_v_id.length() ;
    char* p_id = (char*) malloc(p_id_len);
    memcpy(p_id, c_id.c_str(),c_id.length());
    memcpy(p_id + c_id.length(), str_v_id.c_str(),str_v_id.length());
    uint32_t hash_bid =  SpookyHash::Hash32(p_id, p_id_len, v_id) % dataset_size;
    // printf("%d", (int)hash_bid);
    // print_bytes((uint8_t*)(hash_bid),4);
    free(p_id);

    return hash_bid;
}


void hash_SHA_BlockSize(const void *key, const uint32_t  counter, char * k_enc){

    char k_temp[ENTRY_HASH_KEY_LEN_128]; 

    for(int k_index = 0; k_index < VIDEO_BLOCK_SIZE/ENTRY_HASH_KEY_LEN_128; k_index++){
        std::string c_str = std::to_string(counter) + std::to_string(k_index);
        char const *c_char = c_str.c_str();
        hash_SHA128(key,c_char,c_str.length(),&k_temp);
        memcpy(&k_enc[k_index*ENTRY_HASH_KEY_LEN_128],k_temp,ENTRY_HASH_KEY_LEN_128);
    }

}

void tag_gen_key_counter(const void *key,const uint32_t counter,  char *tag1, char *tag2){

    //message to be encrypted for CE1
    std::string m_key = std::to_string(counter) + std::to_string(1); 
    hash_SHA128(key, m_key.c_str(),m_key.length(),tag1);

    //message to be encrypted for CE2
    m_key = std::to_string(counter) + std::to_string(2); 
    hash_SHA128(key, m_key.c_str(),m_key.length(),tag2);    

}

void tag_gen_key_counter_oblivBatch(const void *key,const uint32_t counter,  char *tag){
    
    std::string m_key = std::to_string(counter); 
    hash_SHA128(key, m_key.c_str(),m_key.length(),tag);
}

void block_enc_xor_counter(const unsigned char * masterK,  const std::string key,  const uint32_t counter, const char* plaintext, char *ciphertext){
    
    //if wanted to double check again onetime padding xor
    //meta_enc_block re_Test;
    //block_enc_xor_counter(masterK, m_key, counter, m_e_Blocks[id_offset].enc_content, re_Test.enc_content);

    //test purpose
    //meta_enc_block re_Test;
    //block_enc_xor_counter(masterK, m_key, counter, m_e_Blocks[id_offset].enc_content, re_Test.enc_content);
    //if(memcmp(tmp_block_content,re_Test.enc_content,VIDEO_BLOCK_SIZE)==0){
    //printf("\nINSIDE-r=%d, l=%d,bu=%d,o=%d matched\n",r,m_e_Blocks[batch_index].path, m_e_Blocks[batch_index].bu,m_e_Blocks[batch_index].offset);
    //} else{
        //printf("\nINSIDE-r=%d, l=%d,bu=%d,o=%d not matched\n",r,m_e_Blocks[batch_index].path, m_e_Blocks[batch_index].bu,m_e_Blocks[batch_index].offset);
    //}
    //end test

    char k_enc[VIDEO_BLOCK_SIZE]; 

    entryKey k_1;
    k_1.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + key.size(); 
	k_1.content = (char *) malloc(k_1.content_length);
    enc_aes_gcm(masterK,key.c_str(),key.size(),k_1.content,k_1.content_length);

    //part2: gen k_temp=H(K_1,c||0,....), where k_enc is the contact of {k_temp} 
    //then let enc_block =  k_enc \xor tmp_block_content
    //iterate to concat key
        
    hash_SHA_BlockSize(k_1.content,counter,k_enc);

    //for(int k_index = 0; k_index < VIDEO_BLOCK_SIZE/ENTRY_HASH_KEY_LEN_128; k_index++){
    //    std::string c_str = std::to_string(counter) + std::to_string(k_index);
    //    char const *c_char = c_str.c_str();
    //    hash_SHA128(k_1.content,c_char,c_str.length(),&k_temp);
    //    memcpy(&k_enc[k_index*ENTRY_HASH_KEY_LEN_128],k_temp,ENTRY_HASH_KEY_LEN_128);
    //}

    free(k_1.content);

    for(int byte_index = 0 ; byte_index < VIDEO_BLOCK_SIZE; byte_index++){
        ciphertext[byte_index] = (char) (k_enc[byte_index] ^ plaintext[byte_index]);
    }
      
}


void dump_tags_testing(const metaRangeRet_p1 * obj1, const metaRangeRet_p2 * obj2){
    
    printf("\nInside\n");
    printf("obj1: tag1\n");
    print_bytes((uint8_t *)obj1->tag1,ENTRY_HASH_KEY_LEN_128);
    printf("obj1: tag2 \n");
    print_bytes((uint8_t *)obj1->tag2,ENTRY_HASH_KEY_LEN_128); 

    printf("obj1: k_part1\n");
    print_bytes((uint8_t *)obj1->k_part1,VIDEO_BLOCK_SIZE);


    printf("obj2: k_part2 \n"); 
    print_bytes((uint8_t *)obj2->tag2,ENTRY_HASH_KEY_LEN_128);
    printf("\nobj2: rIndex %d, stashPos %d\n", obj2->oramIndex, obj2->s);
    
}

int dpf_getsize(const uint8_t *k){
    uint8_t n = k[0];
    // the key length = n - log (lambda/log |G|) (lambda = 128, |G| = 2)
    int length = n - 7;
    return 18 * (length + 1) + 16; 
}

 void inner_product_bit(const  unsigned char *content, const bool t, unsigned char *m , int len_size){
    
    /***
    unsigned long temp;
    for(int i=0; i < len_size; i++){
        std::bitset<8> b(content[i]);
        for(int j=0; j < 8; j++)
            b.set(j, b[j] & t);
        
        temp = b.to_ulong(); 
        m[i] = static_cast<unsigned char>( temp );
    }
    ***/

    if(t==0) {
        memset( m, (unsigned char )t, len_size);
    }else{
        memcpy(m,content,len_size);
    }
 }

 //void xor_bit( unsigned char *a, unsigned char *b ){
//
 //}

void dpf_gen_serialise(int oramIndex, int index, 
                        int *key_arr, unsigned int *rounds, 
                        uint8_t* p1, uint8_t* p2)
{
    // generate a key
    AES_KEY user_key;

    long long randFactor1, randFactor2;
    sgx_read_rand((unsigned char *) &randFactor1, 8);
    sgx_read_rand((unsigned char *) &randFactor2, 8);

    block key_block = make_block(randFactor1, randFactor2); //by bid and counter

    AES_set_encrypt_key(key_block, &user_key);

    uint8_t* k1;
    uint8_t* k2;
    // put f(index) = 1 into key
    dpf_gen(index, 8, &user_key, k1, k2);

    //export the aes key for prg
    AES_export_encrypt_key(&user_key,key_arr,rounds);
    
    //export the share key of fss
    memcpy(p1,k1,DPF_PARTY_KEY);
    memcpy(p2,k2,DPF_PARTY_KEY);

/* 
    unsigned char content1[ENC_KEY_SIZE] = {0};
    unsigned char content2[ENC_KEY_SIZE] = {0};
    unsigned char content3[ENC_KEY_SIZE] = {0};
    unsigned char content4[ENC_KEY_SIZE] = {0};


    sgx_read_rand(content1, ENC_KEY_SIZE);
    sgx_read_rand(content2, ENC_KEY_SIZE);
    sgx_read_rand(content3, ENC_KEY_SIZE);
    sgx_read_rand(content4, ENC_KEY_SIZE);

    //CE1
    bool t11= dpf_evaluate_index(key_arr,*rounds,p1,index);
    unsigned char * m11 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content1, t11, m11,ENC_KEY_SIZE);

    bool t12= dpf_evaluate_index(key_arr,*rounds,p1,90);
    unsigned char * m12 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content2, t12, m12, ENC_KEY_SIZE);

    bool t13= dpf_evaluate_index(key_arr,*rounds,p1,100);
    unsigned char * m13 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content3, t13, m13, ENC_KEY_SIZE);

    bool t14= dpf_evaluate_index(key_arr,*rounds,p1,110);
    unsigned char * m14 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content4, t14, m14, ENC_KEY_SIZE);


    unsigned char * m1_final = (unsigned char *)malloc(ENC_KEY_SIZE);
    for(int i=0; i < ENC_KEY_SIZE; i++){
        m1_final[i] = (unsigned char) ((m11[i] ^ m12[i])  ^ (m13[i] ^ m14[i]));
    }

    //CE2
    bool t21= dpf_evaluate_index(key_arr,*rounds,p2,index); 
    unsigned char * m21 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content1, t21,m21, ENC_KEY_SIZE);

    bool t22= dpf_evaluate_index(key_arr,*rounds,p2,90); 
    unsigned char * m22 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content2,t22, m22, ENC_KEY_SIZE);

    bool t23= dpf_evaluate_index(key_arr,*rounds,p2,100); 
    unsigned char * m23 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content3,t23, m23, ENC_KEY_SIZE);

    bool t24= dpf_evaluate_index(key_arr,*rounds,p2,110); 
    unsigned char * m24 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content4,t24, m24, ENC_KEY_SIZE);

    unsigned char * m2_final = (unsigned char *)malloc(ENC_KEY_SIZE);
    for(int i=0; i < ENC_KEY_SIZE; i++){
        m2_final[i] = (unsigned char) ( (m21[i] ^ m22[i]) ^ (m23[i] ^ m24[i]));
    }

    //xor m1_final and m2_final
    //compare to the original block 
    unsigned char * mm_final = (unsigned char *)malloc(ENC_KEY_SIZE);    
    for(int i=0; i < ENC_KEY_SIZE; i++){
        mm_final[i] =  (unsigned char) ( m1_final[i] ^ m2_final[i]);
    }


    printf("--|%d-%d->",index,(t11!=t21));

    printf("%d|", memcmp(content1,mm_final,ENC_KEY_SIZE)); //byte array compare
    
    free(m11); free(m12); free(m13); free(m14);

    free(m21); free(m22); free(m23); free(m24);

    free(m1_final);  free(m2_final);
    free(mm_final); */

    free(k1);
    free(k2);
    
}


bool dpf_evaluate_index(const int *key_arr_prg, unsigned int rounds_prg, const uint8_t* p, int index){
    AES_KEY user_key;

    AES_import_encrypt_key(&user_key,key_arr_prg,rounds_prg);

    return dpf_eval_tag(&user_key,p,index);

}


void _output_bit_to_bit(uint64_t input){
    for(int i = 0; i < 64; i++)
    {
        if( (1ll << i) & input)
            printf("1");
	else
	    printf("0");
    }
}

void dpf_cb(block input) { //convert to 2 64 integers
    uint64_t *val = (uint64_t *) &input;

	//printf("%016lx%016lx\n", val[0], val[1]);
    printf("-");
	_output_bit_to_bit(val[0]);
	_output_bit_to_bit(val[1]);
	printf("-");
}

void dpf_auto_test(int index){

    AES_KEY user_key;

    long long keyvalue1, keyvalue2;

    keyvalue1 = index *13;
    keyvalue2 = index * 7;

    block key_block = make_block(keyvalue1, keyvalue2);

    AES_set_encrypt_key(key_block, &user_key);

    // put f(index) = 1 into keys
    uint8_t* k1;
    uint8_t* k2;

    dpf_gen(index, 8, &user_key, k1, k2); // to be 2^8 choices as security parameter //120, 26946, 26943 works

    bool n1 = dpf_eval_tag(&user_key,k1,index);
    bool n2 = dpf_eval_tag(&user_key,k2,index);   
    printf("--|%d-%d|",index,(n1!=n2));


}

void dpf_block_test(int oramindex, int index){

    // generate a key
    AES_KEY user_key, user_key1;

    long long keyvalue1, keyvalue2 ;
    keyvalue1 = index *13;
    keyvalue2 = index * 7;

    block key_block = make_block(keyvalue1, keyvalue2);

    AES_set_encrypt_key(key_block, &user_key);

    uint8_t* k1;
    uint8_t* k2;

    // put f(index) = 1 into keys
    dpf_gen(index, 8, &user_key, k1, k2);

    //int key_size = dpf_getsize(k1);
    //printf("DPF Key Size: %d\n", key_size);

    //test (de)-serialise the AES_KEY user_key
    int key_arr[DPF_USER_KEY_PRG];
    unsigned int round;
    AES_export_encrypt_key(&user_key,key_arr,&round);
    AES_import_encrypt_key(&user_key1,key_arr,round);
        
    //test (de)-serialise the k1 and k2
    uint8_t k1s[DPF_PARTY_KEY], k2s[DPF_PARTY_KEY]; 
    memcpy(k1s,k1,DPF_PARTY_KEY); 
    memcpy(k2s,k2,DPF_PARTY_KEY); 

    unsigned char content1[ENC_KEY_SIZE] = {0};
    unsigned char content2[ENC_KEY_SIZE] = {0};
    unsigned char content3[ENC_KEY_SIZE] = {0};
    unsigned char content4[ENC_KEY_SIZE] = {0};

    sgx_read_rand(content1, ENC_KEY_SIZE);
    sgx_read_rand(content2, ENC_KEY_SIZE);
    sgx_read_rand(content3, ENC_KEY_SIZE);
    sgx_read_rand(content4, ENC_KEY_SIZE);


    //CE1
    bool t11=  dpf_eval_tag(&user_key1,k1s,index);
    unsigned char * m11 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content1, t11, m11,ENC_KEY_SIZE);

    bool t12= dpf_eval_tag(&user_key1,k1s,690); 
    unsigned char * m12 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content2, t12, m12, ENC_KEY_SIZE);

    bool t13= dpf_eval_tag(&user_key1,k1s,691);
    unsigned char * m13 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content3, t13, m13, ENC_KEY_SIZE);

    bool t14= dpf_eval_tag(&user_key1,k1s,692);
    unsigned char * m14 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content4, t14, m14, ENC_KEY_SIZE);


    unsigned char * m1_final = (unsigned char *)malloc(ENC_KEY_SIZE);
    for(int i=0; i < ENC_KEY_SIZE; i++){
        m1_final[i] = ( m11[i] ^ m12[i] ) ^ (m13[i] ^ m14[i]);
    }

    //CE2
    bool t21= dpf_eval_tag(&user_key1,k2s,index);
    unsigned char * m21 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content1, t21,m21, ENC_KEY_SIZE);

    bool t22= dpf_eval_tag(&user_key1,k2s,690);
    unsigned char * m22 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content2,t22, m22, ENC_KEY_SIZE);

    bool t23= dpf_eval_tag(&user_key1,k2s,691);
    unsigned char * m23 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content3,t23, m23, ENC_KEY_SIZE);

    bool t24= dpf_eval_tag(&user_key1,k2s,692);
    unsigned char * m24 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content4,t24, m24, ENC_KEY_SIZE);

    unsigned char * m2_final = (unsigned char *)malloc(ENC_KEY_SIZE);
    for(int i=0; i < ENC_KEY_SIZE; i++){
        m2_final[i] = ( m21[i] ^ m22[i] ) ^ (m23[i] ^ m24[i]);
    }

    //xor m1_final and m2_final
    //compare to the original block 
    unsigned char * mm_final = (unsigned char *)malloc(ENC_KEY_SIZE);    
    for(int i=0; i < ENC_KEY_SIZE; i++){
        mm_final[i] = (unsigned char)( m1_final[i] ^ m2_final[i] );
    }

    if(oramindex==0 && index==1){
        printf("\ntestnew -boolean\n");
        printf("\n%d-%d- result %d\n",t11,t21, t11!=t21); //then xor the above two block size
        printf("\n%d-%d- result %d\n",t12,t22, t12!=t22); //then xor the above two block size
        printf("\n%d-%d- result %d\n",t13,t23, t13!=t23); //then xor the above two block size
        printf("\n%d-%d- result %d\n",t14,t24, t14!=t24); //then xor the above two block size
    }
    
    printf("--|%d-%d->",index,(t11!=t21));

    printf("%d|", memcmp(content1,mm_final,ENC_KEY_SIZE)); //byte array compare
    
    free(m11); free(m12); free(m13); free(m14);

    free(m21); free(m22); free(m23); free(m24);

    free(m1_final);  free(m2_final);
    free(mm_final);


}


void dpf_deserialised_test(const int oramIndex, const int * aes_k_p1, const unsigned int round_p1, const uint8_t *ks_p1,
                            int index,
                            const int * aes_k_p2, const unsigned int round_p2, const uint8_t *ks_p2){

    
    AES_KEY user_key, user_key1;                            
    AES_import_encrypt_key(&user_key,aes_k_p1,round_p1);

    AES_import_encrypt_key(&user_key1,aes_k_p2,round_p2);   

    if(oramIndex==0 && index==1){
        printf("deserialised-round value p1 %d\n", round_p1);
        printf("\n");
        print_bytes((uint8_t*)aes_k_p1,44);
        printf("\n");
        print_bytes((uint8_t*)ks_p1,52);
        printf("\n");
        printf("deserialised-round value p2 %d\n", round_p2);
        printf("\n");
        print_bytes((uint8_t*)aes_k_p2,44);
        printf("\n");
        print_bytes((uint8_t*)ks_p2,52);
        printf("\n");
    }


    unsigned char content1[ENC_KEY_SIZE] = {0};
    unsigned char content2[ENC_KEY_SIZE] = {0};
    unsigned char content3[ENC_KEY_SIZE] = {0};
    unsigned char content4[ENC_KEY_SIZE] = {0};


    sgx_read_rand(content1, ENC_KEY_SIZE);
    sgx_read_rand(content2, ENC_KEY_SIZE);
    sgx_read_rand(content3, ENC_KEY_SIZE);
    sgx_read_rand(content4, ENC_KEY_SIZE);

    //CE1
    bool t11= dpf_eval_tag(&user_key,ks_p1,index);
    unsigned char * m11 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content1, t11, m11,ENC_KEY_SIZE);

    bool t12= dpf_eval_tag(&user_key,ks_p1,90);
    unsigned char * m12 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content2, t12, m12, ENC_KEY_SIZE);

    bool t13= dpf_eval_tag(&user_key,ks_p1,100);
    unsigned char * m13 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content3, t13, m13, ENC_KEY_SIZE);

    bool t14= dpf_eval_tag(&user_key,ks_p1,110);
    unsigned char * m14 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content4, t14, m14, ENC_KEY_SIZE);


    unsigned char * m1_final = (unsigned char *)malloc(ENC_KEY_SIZE);
    for(int i=0; i < ENC_KEY_SIZE; i++){
        m1_final[i] = (unsigned char)  (( m11[i] ^ m12[i] ) ^ (m13[i] ^ m14[i]));
    }


    //CE2
    bool t21= dpf_eval_tag(&user_key1,ks_p2,index);
    unsigned char * m21 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content1, t21,m21, ENC_KEY_SIZE);

    bool t22= dpf_eval_tag(&user_key1,ks_p2,90);
    unsigned char * m22 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content2,t22, m22, ENC_KEY_SIZE);

    bool t23= dpf_eval_tag(&user_key1,ks_p2,100);
    unsigned char * m23 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content3,t23, m23, ENC_KEY_SIZE);

    bool t24= dpf_eval_tag(&user_key1,ks_p2,110);
    unsigned char * m24 = (unsigned char *)malloc(ENC_KEY_SIZE);
    inner_product_bit(content4,t24, m24, ENC_KEY_SIZE);

    unsigned char * m2_final = (unsigned char *)malloc(ENC_KEY_SIZE);
    for(int i=0; i < ENC_KEY_SIZE; i++){
        m2_final[i] = (unsigned char)  (( m21[i] ^ m22[i] ) ^ (m23[i] ^ m24[i]));
    }

    //xor m1_final and m2_final
    //compare to the original block 
    unsigned char * mm_final = (unsigned char *)malloc(ENC_KEY_SIZE);    
    for(int i=0; i < ENC_KEY_SIZE; i++){
        mm_final[i] = (unsigned char) ( m1_final[i] ^ m2_final[i] );
    }


    printf("--|%d-%d->",index,(t11!=t21));

    printf("%d|", memcmp(content1,mm_final,ENC_KEY_SIZE)); //byte array compare
    
    free(m11); free(m12); free(m13); free(m14);

    free(m21); free(m22); free(m23); free(m24);

    free(m1_final);  free(m2_final);
    free(mm_final);
}



void swap(uint32_t *a, uint32_t *b){
    int temp = *a;
    *a = *b;
    *b = temp;
}

void permute(uint32_t *arr, int size){
    int i, j;
    uint32_t rand;
    for(i = size-1; i> 0; i--){

        RAND_bytes((uint8_t*) &rand, sizeof(uint32_t));
        j = rand % (i+1);
        swap(&arr[i],&arr[j]);
    }
}


uint32_t findIndexOfValue(uint32_t *permute,  uint32_t size, uint32_t value){
    for(uint32_t i=0; i < size; i++){
        if(permute[i] == value) {
            return i;
        }
    }

    printf("Wrong permutation, value %d", value);
    return 0;

}


