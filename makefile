all:
	g++ -std=c++17 -s -O2 waf.c AES.c logger.c -o waf -static

# Windows 交叉编译（需要 clang + LLVM 混淆插件）
cross:
	clang --target=x86_64-linux-gnu -s waf.c AES.c logger.c -o waf -ID:\Linux\x86_64\gcc\include -LD:\Linux\x86_64\gcc\lib -BD:\Linux\x86_64\gcc\lib -fuse-ld=lld -Xclang -fpass-plugin=./LLVMHello.dll -static

clean:
	rm -f waf *.o
