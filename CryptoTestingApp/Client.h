/***
 * Demonstrate Client
 * maintain a current Kf
 * read documents in a given directory and give one by one to App.cpp with <fileId, array of words>
 * develop utility to enc and dec file with a given key kf
 * issue a random update operation (op,in) to App
 * issue a random keyword search
 */
#ifndef CLIENT_H
#define CLIENT_H

#include "../common/data_type.h"
#include "../common/config.h"
#include "Utils.h"
#include <vector>

class Client{
    public:
        Client();
        void CreateRawDoc(int vid, int rangeSize);
        void ReadRawDoc(int vid, Content *fetch_data,int rangeIndex);

    private:
        unsigned char KF[ENC_KEY_SIZE];
        int file_reading_counter;
};
 
#endif