#include "crypt_decrypt.h"
#include <zlib.h>
#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <random>

#define HINT 52
BOOL GZIPdecompress(const BYTE* inPayload, size_t inSize,
					BYTE* outPayload, size_t *outSize			
) {
	z_stream zs;
	size_t totalWritten = 0;
	memset(&zs, 0, sizeof(zs));

	if (inflateInit2(&zs, 15 + 32) != Z_OK) {
		printf("inflateInit2 failed!\n"); return FALSE;
	}
	
	zs.next_in = (Bytef*)inPayload;
	zs.avail_in = (uInt)inSize;

	int ret;
	BYTE outerbuf[32768];
	do {
	zs.next_out = outerbuf;
	zs.avail_out = sizeof(outerbuf);
	ret = inflate(&zs, Z_NO_FLUSH);
	
	size_t produced = sizeof(outerbuf) - zs.avail_out;
	if (totalWritten + produced > *outSize) {inflateEnd(&zs); printf("To write is too big!\n"); return FALSE;}
	memcpy(outPayload + totalWritten, outerbuf, produced);
	totalWritten += produced;
	} while (ret != Z_STREAM_END);

	if (ret != Z_OK && ret != Z_STREAM_END) {inflateEnd(&zs); return FALSE;}

	*outSize = zs.total_out;
	inflateEnd(&zs);
	printf("Decompression succeeded!\n");
	return TRUE;
}
BOOL GZIPcompress(const BYTE* inPayload, size_t inSize,
				 BYTE* outPayload, size_t *outSize) {
	z_stream zs;
	memset(&zs, 0, sizeof(zs));

	if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
		printf("deflateInit2 failed!\n"); return FALSE;
	}

	zs.next_in = (Bytef*)inPayload;
	zs.avail_in = (uInt)inSize;
	zs.next_out = outPayload;
	zs.avail_out = (uInt)*outSize;

	int ret = deflate(&zs, Z_FINISH);
	
	if (ret != Z_STREAM_END) {
		deflateEnd(&zs);
		return FALSE;
	}
	*outSize = zs.total_out;
	deflateEnd(&zs);
	printf("Compression succeeded!\n");
	return TRUE;
}

BOOL readFile(
    const WCHAR* inPath,
    BYTE** outPayload,
    size_t* outFileSize
) {
    FILE* fl = NULL;

    if (_wfopen_s(&fl, inPath, L"rb") != 0 || !fl) {printf("File didn't open!\n"); return FALSE;}
    fseek(fl, 0, SEEK_END);
	long size = ftell(fl);
    fseek(fl, 0, SEEK_SET);

    if (size <= 0) {fclose(fl); printf("fileSize is too small!\n"); return FALSE;}

    BYTE* buffer = (BYTE*)malloc((size_t)size);
    if (!buffer) {fclose(fl); return FALSE;}

    if (fread(buffer, 1, (size_t)size, fl) != (size_t)size) {free(buffer); fclose(fl); printf("Read Buffer is failed!\n"); return FALSE;}

    fclose(fl);

    *outPayload  = buffer;
    *outFileSize = (size_t)size;
    return TRUE;
}

std::string generateKey() {
	BYTE key[32];

	std::random_device rd;
	std::mt19937 mt(rd());
	std::uniform_int_distribution<> dist(1, 255);

	for (size_t i = 0; i < 32; ++i) {
		key[i] = static_cast<BYTE>(dist(mt));
	}
	key[0] = HINT;
 	return std::string(reinterpret_cast<char*>(key), 32);
}

BYTE* encryptXORKey(std::string key, size_t *encryptedKeySize) {
	BYTE* enckey = (BYTE*)malloc(1 + key.size());
	std::random_device rd;
	std::mt19937 mt(rd());
	std::uniform_int_distribution<> dist(1, 255);

	BYTE magicbyte = (BYTE)dist(mt);
	printf("ENCRYPT MAGIC BYTE = 0x%X\n", magicbyte);
	enckey[0] = HINT;
	for(size_t i = 0; i < key.size(); i++) {
		enckey[i + 1] = key[i] ^ (BYTE)(magicbyte + i);
	}

	*encryptedKeySize = 1 + key.size();
	return enckey;
}

std::string decryptXORKey(BYTE* encryptedKey, size_t encryptedKeySize) {
	BYTE* decryptedKey = (BYTE*)malloc(encryptedKeySize - 1);
	BYTE magicbyte = encryptedKey[0] ^ encryptedKey[1];
	printf("DECRYPT MAGIC BYTE = 0x%X\n", magicbyte);
	for (size_t i = 0; i < encryptedKeySize - 1; ++i) {
		decryptedKey[i] = encryptedKey[i + 1] ^ (BYTE)(magicbyte + i);
	}
	return std::string(reinterpret_cast<char*>(decryptedKey), encryptedKeySize - 1);
}
int main()
{

	int argc = 0;
	WCHAR** argv;

	std::string password = generateKey();
	BYTE* payload;
	size_t fileSize;
	BYTE* compressedPayload;
	size_t outFileSize;
	BYTE* encryptedPayload;
	size_t encryptedSize;
	BYTE* encryptedKey;
	size_t encryptedKeySize;

	argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argc == 2) 
	{
			for(size_t i = 0; i < 32; ++i) {
				if (i % 4 == 0) {printf("\n");}
				printf("0x%2X ", password[i]);
			}
			if (readFile(argv[1], &payload, &fileSize)) {
			outFileSize = compressBound(fileSize) + 18;
			compressedPayload = (BYTE*)malloc(outFileSize);
			if (GZIPcompress(payload, fileSize, compressedPayload, &outFileSize)) {
				printf("GZIP compression succeeded!\n");
				if (outFileSize > compressBound(fileSize) + 18) {printf("outFileSize is too big!\n"); return 1;}
				size_t maxEncryptedSize = outFileSize + AESGCM::IV_LEN + AESGCM::SALT_LEN + AESGCM::TAG_LEN;

				BYTE* encryptedKey = encryptXORKey(password, &encryptedKeySize);
				if (encryptedKeySize > 0) {
				encryptedPayload = (BYTE*)malloc(encryptedKeySize + maxEncryptedSize);
				memcpy(encryptedPayload, encryptedKey, encryptedKeySize);
				if (AESGCM::aesEncryptPayload(compressedPayload, outFileSize, encryptedPayload + encryptedKeySize, &encryptedSize, password)) {
					FILE* writer = NULL;
					const WCHAR* pathwrite = L"D:\\!! MSVC Projects\\aes_cryptor\\asjdasdgahdg.bin";
					_wfopen_s(&writer, pathwrite, L"wb");
					size_t r = fwrite(encryptedPayload, 1, encryptedKeySize + encryptedSize, writer);
					printf("%d bytes were read\n");
					printf("Encrypted successfully!\nStarting decryption!\n");
					fclose(writer);


					BYTE* decryptedCompressedPayload = (BYTE*)malloc(maxEncryptedSize);
					size_t decryptedSize;
					std::string extractedKey = decryptXORKey(encryptedPayload, encryptedKeySize);
					
					for(size_t i = 0; i < 32; ++i) {
						if (i % 4 == 0) {printf("\n");}
						printf("0x%2X ", password[i]);
						if (i == 0) {printf(" - Hint\n");}
					}
					for (size_t i = 0; i < 32; ++i) {
						if (password[i] != extractedKey[i]) {printf("Extracted key is broken %d", i); return 0;}
					}

					if(AESGCM::aesDecryptPayload(encryptedPayload + encryptedKeySize, encryptedSize, decryptedCompressedPayload, &decryptedSize, extractedKey)) {
						size_t mallocsize = 0;
						memcpy(&mallocsize, decryptedCompressedPayload + decryptedSize - 4, 4);
						if (mallocsize > 0) {
							BYTE* clearPayload = (BYTE*)malloc(mallocsize);
							size_t clearPayloadSize = mallocsize;
							if(GZIPdecompress(decryptedCompressedPayload, decryptedSize, clearPayload, &clearPayloadSize)) {
								FILE* writer2 = NULL;
								const WCHAR* decryptedPath = L"D:\\!! MSVC Projects\\aes_cryptor\\decrypted.bin";
								_wfopen_s(&writer2, decryptedPath, L"wb");
								size_t wr = fwrite(clearPayload, 1, clearPayloadSize, writer2);
								printf("%d decrypted bytes had been written");
								fclose(writer2);
								return 0;
							} else {printf("GZIP decompression failed!\n"); free(payload); free(compressedPayload); free(encryptedPayload); free(decryptedCompressedPayload); free(clearPayload); return 1;}
						}
					} else {printf("AES Decryption is failed!\n"); free(payload); free(compressedPayload); free(encryptedPayload); free(decryptedCompressedPayload); return 1;}
				} else {printf("AES Encryption is failed!\n"); free(payload); free(compressedPayload); free(encryptedPayload); return 1;} 
			}
				
			} else {printf("GZIP compression failed!\n"); free(payload); free(compressedPayload); return 1;}
		}
	} else { printf("Not enought elements!\n"); return 1; }
	return 0;
}


