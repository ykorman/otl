
all: otl pam_otl.so

PAMH = /usr/include/security/pam_modules.h
SODIUMH = /usr/include/sodium.h

otl: otl.c otl.h $(SODIUMH)
	gcc -Werror -o $@ $< -lsodium

pam_otl.so: pam_otl.o $(PAMH)
	gcc -shared -o $@ $< -lpam

pam_otl.o: pam_otl.c otl.h
	gcc -fPIC -c $<

$(SODIUMH):
	@echo "otl requires libsodium-devel."
	@exit 1

$(PAMH):
	@echo "otl requires pam-devel."
	@exit 1

clean:
	@rm -vf otl pam_otl.o pam_otl.so
