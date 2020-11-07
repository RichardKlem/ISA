.PHONY: all run prog cleanall
SOURCES= sslsniff.cpp my_string.cpp my_getnameinfo.cpp my_dns_cache.cpp my_tls.cpp sslsniff.h my_string.h my_getnameinfo.h my_dns_cache.h my_tls.h

all: $(SOURCES)
	g++ -Wextra -Wall -pedantic -o sslsniff sslsniff.cpp my_string.cpp my_getnameinfo.cpp my_dns_cache.cpp my_tls.cpp -lpcap

ifeq (run,$(firstword $(MAKECMDGOALS)))
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  $(eval $(RUN_ARGS):;@:)
endif

run:
	sudo ./sslsniff $(RUN_ARGS)

cleanall:
	rm  sslsniff
