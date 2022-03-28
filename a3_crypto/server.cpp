#include <bits/stdc++.h>
#include <pthread.h>
#include <semaphore.h>
using namespace std;

#include "crypto.cpp"

int fd[2];
char *filepath = nullptr, *port = nullptr, *static_key = nullptr;

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

void translate_func() {
    // read from buffer, decrypt it, store into file
    ofstream fout;
    string psk = static_key;

    fout.open(filepath);
    if(!fout) {
        perror("open");
        return;
    }

    int ind = 0;
    char c;
    char packet[MAX_MESSAGE_SIZE];
    int count = read(fd[0], packet, MAX_MESSAGE_SIZE);

    close(fd[0]);

    string iv, hmac, enc_message;
    int i = 0;
    while(i < IV_SIZE)
        iv += packet[i++];
    while(i < IV_SIZE + HMAC_SIZE)
        hmac += packet[i++];
    while(i < count)
        enc_message += packet[i++];

    initialize(psk, iv, true);
    if(!verify_hmac(enc_message, hmac)) {
        cerr << "HMAC Failed!" << endl;
        fout.close();
        return;
    }
    string message = decrypt(enc_message);

    fout.write(message.c_str(), message.length());
    fout.close();
}

void recv_func() {
    // send message from enc_shared_buff
    dup2(fd[1], STDOUT_FILENO);
    execl("/bin/nc", "", "-l", port, NULL);
    perror("execl");
}

int main(int argc, char* argv[]) {
    if(argc < 4) {
        cerr << "usage: ./server <key> <filepath> <port>\n";
        exit(-1);
    }
    static_key = argv[1];
    filepath = argv[2];
    port = argv[3];

    pipe(fd);
    if(fork() == 0) {
        translate_func();
    }
    else {
        recv_func();
    }

    close(fd[0]);
    close(fd[1]);
}
