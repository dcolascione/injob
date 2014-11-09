CPPFLAGS=-Wall -Werror -Wno-unused

### NOTE NOTE NOTE NOTE We need -lcygwin before -lntdll because ntdll,
### were it listed first, would override key functions (like swprintf)
### provided by Cygwin, leading to mysterious crashes.

injob: injob.c
	$(CC) $(CPPFLAGS)  -Os -g -o $@ $^ -lcygwin -lntdll

clean:
	rm -f injob.exe
