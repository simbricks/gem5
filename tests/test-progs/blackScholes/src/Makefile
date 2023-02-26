all: bs64-static bs64-dynamic bs32-static

bs64-static: bs.c dockcross-x64
	./dockcross-x64 bash -c '$$CC bs.c -o bs64-static -static -lm'

bs64-dynamic: bs.c dockcross-x64
	./dockcross-x64 bash -c '$$CC bs.c -o bs64-dynamic -lm'

bs32-static: bs.c dockcross-x86
	./dockcross-x86 bash -c '$$CC bs.c -o bs32-static -static -lm'

dockcross-x64:
	docker run --rm dockcross/linux-x64 > ./dockcross-x64
	chmod +x ./dockcross-x64

dockcross-x86:
	docker run --rm dockcross/linux-x86 > ./dockcross-x86
	chmod +x ./dockcross-x86

clean:
	rm -f dockcross-* bs64-static bs64-dynamic bs32-static
