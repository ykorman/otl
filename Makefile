
all: otl pam_otl.so

RANDH = /usr/include/openssl/rand.h
PAMH = /usr/include/security/pam_modules.h

otl: otl.c otl.h $(RANDH)
	gcc -Werror -c $< -lcrypto

pam_otl.so: pam_otl.o $(PAMH)
	gcc -shared -o $@ $< -lpam

pam_otl.o: pam_otl.c otl.h
	gcc -fPIC -c $<

$(RANDH):
	@echo "otl requires openssl-devel."
	@exit 1

$(PAMH):
	@echo "otl requires pam-devel."
	@exit 1

clean:
	@rm -vf otl pam_otl.o pam_otl.so
