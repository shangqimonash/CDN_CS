#include "Client.h"

#include <string>
//#include <string.h> // memset(KF, 0, sizeof(KF));
#include "stdio.h"
#include <stdlib.h>
#include <fstream>
#include <iostream>
#include <sstream> //std::stringstream
#include <vector>
#include <algorithm> // for std::find
#include <iterator> // for std::begin, std::end
#include <cstring> 
#include <openssl/rand.h>
#include <algorithm>
#include <cmath>

#include <fstream>
    using std::ofstream;
    using std::cout;
    using std::endl;


Client::Client(){
    file_reading_counter=0;
    RAND_bytes(KF,ENC_KEY_SIZE);
}


void Client::CreateRawDoc(int id, int rangeSize){

    char *letters = (char*)"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int num_of_letters = strlen(letters);
    
    char* dummyBlockHolder = (char*) malloc(VIDEO_BLOCK_SIZE);

    for(int rIndex=0 ; rIndex < rangeSize ; rIndex++){
       
        //store into the file with text format, and filename=id#range_rIndex
        int fileSize = ((int) pow(2,rIndex) * VIDEO_BLOCK_SIZE) + 1 ;

        char* rangeContent = (char*) malloc(fileSize);

         //create pow(2,rIndex) numbers of blocks for each range
        for(int j= 0 ; j < (int) pow(2,rIndex) ; j++){

            //each block is the size of VIDEO_BLOCK_SIZE with dummy repeatedly character
            int n = rand() % num_of_letters;
            std::fill_n(dummyBlockHolder, VIDEO_BLOCK_SIZE, letters[n]);
            memcpy(rangeContent + (j*VIDEO_BLOCK_SIZE), dummyBlockHolder,VIDEO_BLOCK_SIZE);
        }

        rangeContent[fileSize-1] = '\0';
        ofstream stream;

        std::string fileName;
        fileName = std::to_string(id);

        stream.open( raw_video_dir + fileName + "#r" + std::to_string(rIndex)); 
        stream << rangeContent << endl;
        
        stream.close();
        free(rangeContent);
    }

    free(dummyBlockHolder);
}

void Client::ReadRawDoc(int id, Content *content,int rangeIndex){ 

    std::ifstream inFile;
    std::stringstream strStream;


    std::string fileNamePath;
    fileNamePath = raw_video_dir + std::to_string(id) +"#r" + std::to_string(rangeIndex);
    //printf("\nPath %s\n", fileNamePath.c_str());

    //read the file content
    inFile.open(fileNamePath); 
    strStream << inFile.rdbuf();
    inFile.close();

    /** convert document content to char* and record length */
    std::string str = strStream.str();
    int plaintext_len;
    plaintext_len = str.length()-1; //not count #\0

    //printf("\nLength size %d\n", plaintext_len);

    content->content = (char*)malloc(plaintext_len);
    memcpy(content->content, str.c_str(),plaintext_len);

    content->content_length = plaintext_len;

    strStream.clear();

}
