#include <bits/stdc++.h>
#include <pthread.h>
#include <semaphore.h>
using namespace std;

#include "crypto.cpp"

int fd[2];
char *filepath = nullptr, *ip = nullptr, *port = nullptr, *static_key = nullptr;

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

void read_func() {
    // read file into buffer, encrypt it, store into enc_shared_buff
    ifstream fin;
    string psk = static_key;

    fin.open(filepath);
    if(!fin) {
        perror("open");
        return;
    }

    int ind = 0;
    char c;
    string buff;
    while(!fin.eof()) {
        fin.get(c);
        if(fin.eof())
            break;
        buff += c;
    }

    fin.close();

    initialize(psk);
    string enc_message = encrypt(buff);
    string hmac = calculate_hmac(enc_message);
    string packet = get_iv() + hmac + enc_message;
    destruct_final();

    write(fd[1], packet.c_str(), packet.length());
}

void send_func() {
    // send message from enc_shared_buff
    dup2(fd[0], STDIN_FILENO);
    execl("/bin/nc", "", ip, port, NULL);
    perror("execl");
}

int main(int argc, char* argv[]) {
    if(argc < 5) {
        cerr << "usage: ./client <key> <filepath> <ip> <port>\n";
        exit(-1);
    }
    static_key = argv[1];
    filepath = argv[2];
    ip = argv[3];
    port = argv[4];

    pipe(fd);
    if(fork() == 0) {
        read_func();
    }
    else {
        send_func();
    }

    close(fd[0]);
    close(fd[1]);
}
