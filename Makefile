CARGO=cargo
TARGETDIR=./target/debug
TARGET=ip

all: build

build:
	CARGO_HOME=.cargo $(CARGO) build
	cp $(TARGETDIR)/$(TARGET) ./node

clean:
	$(CARGO) clean
	rm -f ./node
