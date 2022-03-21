CARGO=cargo
TARGETDIR=./target/debug
TARGET=ip

build:
	$(CARGO) build
	cp $(TARGETDIR)/$(TARGET) ./node

clean:
	$(CARGO) clean
	rm -f ./node
