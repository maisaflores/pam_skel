pam_skel.o: pam_skel.c
	gcc -fPIC -fno-stack-protector -c pam_skel.c

install: pam_skel.o
	ld -x --shared -o /lib64/security/pam_skel.so pam_skel.o

uninstall:
	rm -f /lib64/security/pam_skel.so
	@echo -e "\n\n      Remove any entry related to this module in /etc/pam.d/ files,\n      otherwise you're not going to be able to login.\n\n"
debug:
	gcc -E -fPIC -fno-stack-protector -c pam_skel.c
clean:
	rm -rf *.o
