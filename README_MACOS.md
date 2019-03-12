Extra steps to compile for macOS [yan - 11.03.2019]

    # brew install curl
    # brew install autoconf
    # brew install automake
    # mkdir m4
    # cp /usr/local/Cellar/curl/{your_version}/share/aclocal/libcurl.m4 ./m4
    
fix Makefile.am (add `ACLOCAL_AMFLAGS = -I m4`)

    minerd_LDFLAGS = $(PTHREAD_FLAGS)
    minerd_LDADD = @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@
    minerd_CPPFLAGS = @LIBCURL_CPPFLAGS@
    ACLOCAL_AMFLAGS = -I m4        # <- here
    
fix autogen.sh (add `-I m4` to `aclocal`)

    aclocal -I m4        # <- here
    autoheader
    automake --gnu --add-missing --copy
    autoconf
    
Then you can build it normally

    ./autogen.sh
    ./nomacro.pl
    ./configure CFLAGS="-O3"
    make

Followed this guide: https://medium.com/@racooma/cpu-mining-for-2018-f543910b7373
