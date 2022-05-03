CARGO=cargo
DEBUGDIR=$(CURDIR)/target/debug
RELEASEDIR=$(CURDIR)/target/release
CARGO_HOME=$(CURDIR)/.cargo
TARGET=ip

all: debug release

debug:
	CARGO_HOME=$(CARGO_HOME) $(CARGO) build
	cp $(DEBUGDIR)/$(TARGET) ./node-dbg

release:
	CARGO_HOME=$(CARGO_HOME) $(CARGO) build --release
	cp $(RELEASEDIR)/$(TARGET) ./node

clean:
	$(CARGO) clean
	rm -f ./node*
	rm -f ./out/*

.PHONY: all debug release clean
