# AES_plus_Blowfish_in_CBC_mode
The AES_plus_Serpent_in_CBC_mode_for_microcontrollers repository contains code that enables you to encrypt your data using a combination of AES and Serpent encryption algorithms in CBC mode. In addition to that, the code in this repository enables you to verify the data integrity, thanks to the HMAC-SHA256.

## Copyright/Ownership/Licenses

Attention! I didn't develop the libraries utilized by these sketches. I took them from the following repositories:
</br>
</br>
https://github.com/zhouyangchao/AES
</br>
https://github.com/peterferrie/serpent
</br>
https://github.com/intrbiz/arduino-crypto
</br>
</br>
All libraries are the properties of their respective owners.
</br>
Licenses from the used libraries are inside of the "LICENSES" directory.
</br>
*Note that the library with the implementation of AES was slightly modified to make it compatible with the STM32F407VET6.

## Compatibility

The code was successfully tested on the following boards:
- STM32F407VET6
- Teensy 4.1
- ESP32
- ESP8266


## Usage

You should only pay attention to two parts:
</br>
Encryption keys:
```
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
```
Code that does the job:
```
  Serial.println("\nEncryption/Decryption Test");
  String plaintext = "That string is encrypted using a combination of the AES and Serpent encryption algorithms in cipher block chaining mode. The integrity of that string is verified with the help of the HMAC-SHA256.";
  int iv[16]; // Initialization vector
  for (int i = 0; i < 16; i++){
    iv[i] = random(256); // Fill iv array with random numbers. I suggest you use a more secure method of random number generation!!!
  }
  encrypt_string_with_aes_plus_serpent_in_cbc(plaintext, iv); // Function for encryption. Takes the plaintext and iv as the input.
  Serial.println("\nCiphertext");
  Serial.println(string_for_data);
  String ciphertext = string_for_data; // Back the ciphertext up
  decrypt_string_with_aes_plus_serpent_in_cbc(ciphertext); // Decrypt data
  Serial.println("Plaintext:");
  Serial.println(string_for_data);
  bool plaintext_integr = verify_integrity(); // Check the integrity of the newly decrypted data
  if (plaintext_integr == true)
    Serial.println("Integrity verified successfully!");
  else
    Serial.println("Integrity Verification failed!!!");
```
You can ignore the other parts of the code.

![image text](https://github.com/Northstrix/AES_plus_Serpent_in_CBC_mode_for_microcontrollers/blob/master/Pictures/Test.png?raw=true)

## Visual representation of the encryption and decryption processes
![image text](https://github.com/Northstrix/AES_plus_Serpent_in_CBC_mode_for_microcontrollers/blob/master/Pictures/How%20plaintext%20is%20passed%20to%20encryption%20algorithm.png)
![image text](https://github.com/Northstrix/AES_plus_Serpent_in_CBC_mode_for_microcontrollers/blob/master/Pictures/Encryption%20with%20AES%20and%20Serpent%20in%20CBC.drawio.png)
