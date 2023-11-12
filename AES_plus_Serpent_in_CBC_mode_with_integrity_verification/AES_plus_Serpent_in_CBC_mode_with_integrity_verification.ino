/*
AES_plus_Serpent_in_CBC_mode_for_microcontrollers
Written by Maxim Bortnikov
GitHub repository https://github.com/Northstrix/AES_plus_Serpent_in_CBC_mode_for_microcontrollers
I didn't develop the libraries utilized by these sketches. I took them from the following repositories:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/intrbiz/arduino-crypto
These libraries are the properties of their respective owners.
*/

#include "aes.h"
#include "Crypto.h"
#include "serpent.h"

String string_for_data;
String decrypted_tag;
byte tmp_st[8];
int decract;
char array_for_CBC_mode[16];
uint8_t back_AES_key[32];
uint8_t back_serp_key[32];
int m;
uint32_t AES_key_bit[3] = {128, 192, 256};

byte hmackey[] = {"440yjmR9DJj3zF46lqR976IH4e4789pr00pzc430leIrBc06h0C7qZEgoD9z2i7SOXAnVw25xUu2X62hv1n203jh6WMKSfT01dbbZIum9Vf8IG4mjiYfzEo56R8Nd1rRlZ98Jcqb84TQz"};

uint8_t AES_key[32] = {
0x70,0xee,0xac,0x3f,
0xeb,0x1d,0x92,0xb3,
0xdb,0xb2,0x75,0x0b,
0xc0,0xe5,0x77,0x7d,
0xc0,0x80,0x10,0x2b,
0xb8,0x05,0x01,0xf7,
0x50,0x6b,0xfa,0xb9,
0x6c,0xf2,0xd0,0x6e
};

uint8_t serp_key[32] = {
0x01,0x02,0x03,0x04,
0x10,0x11,0x12,0x13,
0x50,0x51,0x52,0x53,
0x7a,0x7b,0x7c,0x7d,
0xa0,0xa1,0xa2,0xa3,
0xbb,0xcc,0xdd,0xee,
0xfc,0xfd,0xfe,0xff,
0x00,0xff,0x00,0xff
};

void back_serp_k() {
  for (int i = 0; i < 32; i++) {
    back_serp_key[i] = serp_key[i];
  }
}

void rest_serp_k() {
  for (int i = 0; i < 32; i++) {
    serp_key[i] = back_serp_key[i];
  }
}

void back_AES_k() {
  for (int i = 0; i < 32; i++) {
    back_AES_key[i] = AES_key[i];
  }
}

void rest_AES_k() {
  for (int i = 0; i < 32; i++) {
    AES_key[i] = back_AES_key[i];
  }
}

void incr_AES_key() {
  if (AES_key[0] == 255) {
    AES_key[0] = 0;
    if (AES_key[1] == 255) {
      AES_key[1] = 0;
      if (AES_key[2] == 255) {
        AES_key[2] = 0;
        if (AES_key[3] == 255) {
          AES_key[3] = 0;
          if (AES_key[4] == 255) {
            AES_key[4] = 0;
            if (AES_key[5] == 255) {
              AES_key[5] = 0;
              if (AES_key[6] == 255) {
                AES_key[6] = 0;
                if (AES_key[7] == 255) {
                  AES_key[7] = 0;
                  if (AES_key[8] == 255) {
                    AES_key[8] = 0;
                    if (AES_key[9] == 255) {
                      AES_key[9] = 0;
                      if (AES_key[10] == 255) {
                        AES_key[10] = 0;
                        if (AES_key[11] == 255) {
                          AES_key[11] = 0;
                          if (AES_key[12] == 255) {
                            AES_key[12] = 0;
                            if (AES_key[13] == 255) {
                              AES_key[13] = 0;
                              if (AES_key[14] == 255) {
                                AES_key[14] = 0;
                                if (AES_key[15] == 255) {
                                  AES_key[15] = 0;
                                } else {
                                  AES_key[15]++;
                                }
                              } else {
                                AES_key[14]++;
                              }
                            } else {
                              AES_key[13]++;
                            }
                          } else {
                            AES_key[12]++;
                          }
                        } else {
                          AES_key[11]++;
                        }
                      } else {
                        AES_key[10]++;
                      }
                    } else {
                      AES_key[9]++;
                    }
                  } else {
                    AES_key[8]++;
                  }
                } else {
                  AES_key[7]++;
                }
              } else {
                AES_key[6]++;
              }
            } else {
              AES_key[5]++;
            }
          } else {
            AES_key[4]++;
          }
        } else {
          AES_key[3]++;
        }
      } else {
        AES_key[2]++;
      }
    } else {
      AES_key[1]++;
    }
  } else {
    AES_key[0]++;
  }
}

void incr_serp_key() {
  if (serp_key[15] == 255) {
    serp_key[15] = 0;
    if (serp_key[14] == 255) {
      serp_key[14] = 0;
      if (serp_key[13] == 255) {
        serp_key[13] = 0;
        if (serp_key[12] == 255) {
          serp_key[12] = 0;
          if (serp_key[11] == 255) {
            serp_key[11] = 0;
            if (serp_key[10] == 255) {
              serp_key[10] = 0;
              if (serp_key[9] == 255) {
                serp_key[9] = 0;
                if (serp_key[8] == 255) {
                  serp_key[8] = 0;
                  if (serp_key[7] == 255) {
                    serp_key[7] = 0;
                    if (serp_key[6] == 255) {
                      serp_key[6] = 0;
                      if (serp_key[5] == 255) {
                        serp_key[5] = 0;
                        if (serp_key[4] == 255) {
                          serp_key[4] = 0;
                          if (serp_key[3] == 255) {
                            serp_key[3] = 0;
                            if (serp_key[2] == 255) {
                              serp_key[2] = 0;
                              if (serp_key[1] == 255) {
                                serp_key[1] = 0;
                                if (serp_key[0] == 255) {
                                  serp_key[0] = 0;
                                } else {
                                  serp_key[0]++;
                                }
                              } else {
                                serp_key[1]++;
                              }
                            } else {
                              serp_key[2]++;
                            }
                          } else {
                            serp_key[3]++;
                          }
                        } else {
                          serp_key[4]++;
                        }
                      } else {
                        serp_key[5]++;
                      }
                    } else {
                      serp_key[6]++;
                    }
                  } else {
                    serp_key[7]++;
                  }
                } else {
                  serp_key[8]++;
                }
              } else {
                serp_key[9]++;
              }
            } else {
              serp_key[10]++;
            }
          } else {
            serp_key[11]++;
          }
        } else {
          serp_key[12]++;
        }
      } else {
        serp_key[13]++;
      }
    } else {
      serp_key[14]++;
    }
  } else {
    serp_key[15]++;
  }
}

size_t hex2bin(void * bin) {
  size_t len, i;
  int x;
  uint8_t * p = (uint8_t * ) bin;
  for (i = 0; i < 32; i++) {
    p[i] = (uint8_t) serp_key[i];
  }
  return 32;
}

int getNum(char ch) {
  int num = 0;
  if (ch >= '0' && ch <= '9') {
    num = ch - 0x30;
  } else {
    switch (ch) {
    case 'A':
    case 'a':
      num = 10;
      break;
    case 'B':
    case 'b':
      num = 11;
      break;
    case 'C':
    case 'c':
      num = 12;
      break;
    case 'D':
    case 'd':
      num = 13;
      break;
    case 'E':
    case 'e':
      num = 14;
      break;
    case 'F':
    case 'f':
      num = 15;
      break;
    default:
      num = 0;
    }
  }
  return num;
}

char getChar(int num) {
  char ch;
  if (num >= 0 && num <= 9) {
    ch = char(num + 48);
  } else {
    switch (num) {
    case 10:
      ch = 'a';
      break;
    case 11:
      ch = 'b';
      break;
    case 12:
      ch = 'c';
      break;
    case 13:
      ch = 'd';
      break;
    case 14:
      ch = 'e';
      break;
    case 15:
      ch = 'f';
      break;
    }
  }
  return ch;
}

void back_keys() {
  back_AES_k();
  back_serp_k();
}

void rest_keys() {
  rest_AES_k();
  rest_serp_k();
}

void clear_variables() {
  string_for_data = "";
  decrypted_tag = "";
  decract = 0;
}

void split_by_sixteen_for_encryption(char plntxt[], int k, int str_len) {
  int res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };

  for (int i = 0; i < 16; i++) {
    if (i + k > str_len - 1)
      break;
    res[i] = plntxt[i + k];
  }

  for (int i = 0; i < 16; i++) {
    res[i] ^= array_for_CBC_mode[i];
  }
  
  encrypt_with_aes_plus_serpent(res);
}

void encrypt_iv_for_tdes_aes_blwfsh_serp(int iv[]) {
  for (int i = 0; i < 16; i++){
    array_for_CBC_mode[i] = iv[i];
  }
  
  encrypt_with_aes_plus_serpent(iv);
}

void encrypt_with_aes_plus_serpent(int pltxt[]) {
  uint8_t text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 16; i++){
    text[i] = pltxt[i];
  }
  uint8_t cipher_text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  aes_context ctx;
  set_aes_key( & ctx, AES_key, AES_key_bit[m]);
  aes_encrypt_block( & ctx, cipher_text, text);
  /*
  for (int i=0; i<16; i++) {
    if(cipher_text[i]<16)
      Serial.print("0");
    Serial.print(cipher_text[i],HEX);
  }
  Serial.println();
  */
  incr_AES_key();
  int pass_to_serp[16];
  for (int i = 0; i < 16; i++){
    pass_to_serp[i] = cipher_text[i];
  }
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t * p;

  for (b = 0; b < 1; b++) {
    hex2bin(key);

    // set key
    memset( & skey, 0, sizeof(skey));
    p = (uint32_t * ) & skey.x[0][0];

    serpent_setkey( & skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for (int i = 0; i < 16; i++) {
      ct2.b[i] = pass_to_serp[i];
    }
    serpent_encrypt(ct2.b, & skey, SERPENT_ENCRYPT);
    incr_serp_key();
    /*
    for (int i = 0; i < 16; i++) {
      if (ct2.b[i] < 16)
        Serial.print("0");
      Serial.print(ct2.b[i], HEX);
    }
    */
    for (int i = 0; i < 16; i++) {
     if (decract > 0){
        if (i < 16){
          array_for_CBC_mode[i] = int(ct2.b[i]);
        }  
     }
     if (ct2.b[i] < 16)
        string_for_data += "0";
      string_for_data += String(ct2.b[i], HEX);
    }
    decract++;
  }
}

void split_for_decryption(char ct[], int ct_len, int p) {
  int br = false;
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  byte prev_res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 32; i += 2) {
    if (i + p > ct_len - 1) {
      br = true;
      break;
    }
    if (i == 0) {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i] = 0;
    } else {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i / 2] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i / 2] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i / 2] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i / 2] = 0;
    }
  }

  for (int i = 0; i < 32; i += 2) {
    if (i + p - 32 > ct_len - 1) {
      br = true;
      break;
    }
    if (i == 0) {
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i] = 16 * getNum(ct[i + p - 32]) + getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i] = 16 * getNum(ct[i + p - 32]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i] = getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i] = 0;
    } else {
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i / 2] = 16 * getNum(ct[i + p - 32]) + getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i / 2] = 16 * getNum(ct[i + p - 32]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i / 2] = getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i / 2] = 0;
    }
  }
  
  if (br == false) {
    if(decract > 16){
      for (int i = 0; i < 16; i++){
        array_for_CBC_mode[i] = prev_res[i];
      }
    }
    uint8_t ct1[32], pt1[32], key[64];
    int plen, clen, i, j;
    serpent_key skey;
    serpent_blk ct2;
    uint32_t * p;

    for (i = 0; i < 1; i++) {
      hex2bin(key);

      // set key
      memset( & skey, 0, sizeof(skey));
      p = (uint32_t * ) & skey.x[0][0];

      serpent_setkey( & skey, key);
      //Serial.printf ("\nkey=");

      for (j = 0; j < sizeof(skey) / sizeof(serpent_subkey_t) * 4; j++) {
        if ((j % 8) == 0) putchar('\n');
        //Serial.printf ("%08X ", p[j]);
      }

      for (int i = 0; i < 16; i++)
        ct2.b[i] = res[i];
      /*
      Serial.printf ("\n\n");
      for(int i = 0; i<16; i++){
      Serial.printf("%x", ct2.b[i]);
      Serial.printf(" ");
      */
    }
    //Serial.printf("\n");
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);
    incr_serp_key();
    uint8_t ret_text[16];
    uint8_t cipher_text[16];
    for (int i = 0; i < 16; i++){
      cipher_text[i] = ct2.b[i];
    }
    aes_context ctx;
    set_aes_key( & ctx, AES_key, AES_key_bit[m]);
    aes_decrypt_block( & ctx, ret_text, cipher_text);
    incr_AES_key();
    if (decract > 2) {
      for (int i = 0; i < 16; i++){
        ret_text[i] ^= array_for_CBC_mode[i];
      }

      if (decract > 22){
        for (i = 0; i < 16; i++) {
          if (ret_text[i] > 0)
            string_for_data += char(ret_text[i]);
        }
      }
      else{
        for (i = 0; i < 16; i++) {
          if (ret_text[i] < 0x10)
            decrypted_tag += "0";
          decrypted_tag += String(ret_text[i], HEX);
        } 
      }
      /*
      Serial.println("\n");
      Serial.print("decract = ");
      Serial.println(decract);
      Serial.print("String = ");
      for (int i = 0; i < 16; i++){
        if (ret_text[i] > 0)
          Serial.print(char(ret_text[i]));
      }
      Serial.println("\n");
      */
    }

    if (decract == -1){
      for (i = 0; i < 16; i++) {
        array_for_CBC_mode[i] = int(ret_text[i]);
      }
    }
    decract++;
  }
}

bool verify_integrity() {
  int str_lentg = string_for_data.length() + 1;
  char char_arraytg[str_lentg];
  string_for_data.toCharArray(char_arraytg, str_lentg);
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(char_arraytg);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  String res_hash;

  for (byte i = 0; i < SHA256HMAC_SIZE; i++) {
    if (authCode[i] < 0x10)
      res_hash += "0";
    res_hash += String(authCode[i], HEX);
  }
  /*
  Serial.println(string_for_data);
  Serial.println(decrypted_tag);
  Serial.println(res_hash);
  */
  return decrypted_tag.equals(res_hash);
}

void encrypt_string_with_aes_plus_serpent_in_cbc(String input, int iv[]) {
  back_keys();
  clear_variables();
  encrypt_iv_for_tdes_aes_blwfsh_serp(iv);
  encrypt_hash_with_aes_plus_serpent_in_cbc(input);
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  int p = 0;
  while (str_len > p + 1) {
    split_by_sixteen_for_encryption(input_arr, p, str_len);
    p += 16;
  }
  rest_keys();
}

void encrypt_hash_with_aes_plus_serpent_in_cbc(String input){
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  hmac.doUpdate(input_arr);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  int p = 0;
  char hmacchar[32];
  for (int i = 0; i < 32; i++) {
    hmacchar[i] = char(authCode[i]);
  }

  for (int i = 0; i < 2; i++) {
    split_by_sixteen_for_encryption(hmacchar, p, 100);
    p += 16;
  }
}

void decrypt_string_with_aes_plus_serpent_in_cbc(String ct) { // Function for decryption. Takes ciphertext as an input.
  back_keys();
  clear_variables();
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  decract = -1;
  while (ct_len > ext) {
    split_for_decryption(ct_array, ct_len, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();
}

void encrypt_serpent_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    Serial.println("\nPaste the string you want to encrypt here:");
    while (!Serial.available()) {
    }
    String plt = Serial.readString();
    int iv[16]; // Initialization vector
    for (int i = 0; i < 16; i++){
      iv[i] = random(256); // Fill iv array with random numbers. I suggest you use a more secure method of random number generation!!!
    }
    encrypt_string_with_aes_plus_serpent_in_cbc(plt, iv); // Function for encryption. Takes the plaintext and iv as the input.
    Serial.println("\nCiphertext");
    Serial.println(string_for_data);
    clear_variables();
    return;
  }
}

void decrypt_serpent_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    Serial.println("\nPaste the ciphertext here:");
    while (!Serial.available()) {
    }
    String ct = Serial.readString();
    decrypt_string_with_aes_plus_serpent_in_cbc(ct);
    Serial.println("Plaintext:");
    Serial.println(string_for_data);
    bool plt_integr = verify_integrity();
    if (plt_integr == true)
      Serial.println("Integrity verified successfully!");
    else
      Serial.println("Integrity Verification failed!!!");
    clear_variables();
    return;
  }
}

void setup() {
  Serial.begin(115200);
  m = 2; // Set AES to 256-bit mode
}

void loop() {
  Serial.println();
  Serial.println("What do you want to do?");
  Serial.println("1.Encrypt string in CBC Mode");
  Serial.println("2.Decrypt string in CBC Mode");
  Serial.println("3.Set encryption algorithm to AES-128 + Serpent in CBC mode");
  Serial.println("4.Set encryption algorithm to AES-192 + Serpent in CBC mode");
  Serial.println("5.Set encryption algorithm to AES-256 + Serpent in CBC mode");
  while (!Serial.available()) {}
  int x = Serial.parseInt();
  if (x == 1)
    encrypt_serpent_from_Serial();
  if (x == 2)
    decrypt_serpent_from_Serial();
  if (x == 3)
    m = 0;
  if (x == 4)
    m = 1;
  if (x == 5)
    m = 2;
}
