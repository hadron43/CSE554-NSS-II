#include <bits/stdc++.h>
#include <pthread.h>
using namespace std;

#include "crypto.cpp"

int main(int argc, char* argv[]) {
    string passphrase, enc_message, hmac, iv;
    char c;

    cout << "Enter passphrase: ";
    cin >> passphrase;

    ifstream fin("enc", ios::in | ios::binary);

    char buff[1024];
    memset(buff, 0, sizeof(buff));
    int ind = 0;
    while(!fin.eof()) {
        fin.get(c);
        if(fin.eof())
            break;
        buff[ind ++] = c;
    }

    fin.close();

    int i = 0;
    while(i < IV_SIZE)
        iv += buff[i++];
    while(i < IV_SIZE + HMAC_SIZE)
        hmac += buff[i++];
    while(i < ind)
        enc_message += buff[i++];

    cout << "buff: " << buff << "$" << endl
        << "key: " << passphrase << endl
        << "iv: " << iv << endl
        << "hmac: " << hmac << endl
        << "mes: " << enc_message << endl;
    // cout << "iv: " << iv << "$" << endl;

    initialize(passphrase, iv, true);

    verify_hmac(enc_message, hmac);
    decrypt(enc_message);

    destruct_final();
}