

all: decrypt_fw_samsung

decrypt_fw_samsung: decrypt_fw_samsung.c
	gcc -g -o decrypt_fw_samsung decrypt_fw_samsung.c -lcrypto

clean:
	rm -rf decrypt_fw_samsung decrypt_fw_samsung.o *.pyc

