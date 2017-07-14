CC = gcc
test:test.c
		$(CC) -Wall -o test test.c -I /home/dell/ytk_project/ -lNtYtk -L /home/dell/ytk_project/ -Wl,-rpath=/home/dell/ytk_project/ -lcurl -lcrypt
clean:
		-rm *.o

#  -Wall 把所有错误信息和警告信息打印出来
#  -o 生成目标文件
#  -I 头文件路径
#  -l 动态库名字，比如：libHttp.so, 那么名字就是Http，注意要去掉lib和.so
#  -L 动态库路径
#  -w1,-rpath=把动态库路径写入可执行文件里，避免运行程序时出现找不到动态库
#  -lcurl 链接libcurl库
#  -lcrypt 链接libcrypt库
