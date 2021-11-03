java_run: lib
	javac Musig2.java && java -Djava.library.path=target/debug/ Musig2

.PHONY: lib

javah:
	javah Musig2

lib:
	cargo build
