#include <bits/stdc++.h>
#include <pthread.h>
using namespace std;

#include "crypto.cpp"

void process_packet(string packet, string psk) {
    string iv, hmac, enc_message;
    int i = 0;
    while(i < IV_SIZE)
        iv += packet[i++];
    while(i < IV_SIZE + HMAC_SIZE)
        hmac += packet[i++];
    while(i < packet.length())
        enc_message += packet[i++];

    // cout << "iv: " << iv << "$" << endl;

    initialize(psk, iv, true);

    // cout << "iv: " << ::iv << "$" << endl;

    verify_hmac(enc_message, hmac);
    decrypt(enc_message);
}

int main(int argc, char* argv[]) {
    string passphrase, message, enc_message, hmac;

    cout << "Enter passphrase: ";
    cin >> passphrase;
    cout << "Enter message: ";
    cin >> message;
    initialize(passphrase, true);

    enc_message = encrypt(message);
    hmac = calculate_hmac(enc_message);

    string packet = get_iv() + hmac + enc_message;
    cout << "packet: " << packet << endl;
    ofstream fout("enc");
    fout.write(packet.c_str(), packet.length());
    fout.close();

    destruct_final();
}