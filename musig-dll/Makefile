java_run: lib
	javac Musig.java && java -Djava.library.path=target/debug/ Musig

.PHONY: lib

javah:
	javah Musig

lib:
	cargo build
