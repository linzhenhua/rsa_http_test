#ifndef NT_YTK_H
#define NT_YTK_H 

//rsa加密相关头文件
#include <openssl/rsa.h>   //用于rsa加密
#include <openssl/pem.h>   //用于pem格式
#include <openssl/err.h>   //用于rsa显示错误
#include <openssl/sha.h>   //用于sha1数字摘要

//http协议相关头文件
#include <curl/curl.h>    //用于libcurl定义

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* 函数说明：libcurl接收数据时的回调函数，libcurl要求函数用这种格式，否则报错
 * pszBuffer：接收到的数据所在缓冲区 
 * nBuffSize：数据片长度
 * nMemb：数据片数量
 * pszData：用户自定义的指针
 * 返回值：数据长度非0：成功，0：失败
 * */
size_t GetData(void *pszBuff, size_t nBuffSize, size_t nMemb, void *pszData);  

/*
 * 函数说明：发送json格式的报文
 * 输入参数1：发送到的地址
 * 输入参数2：发送的数据
 * 输出参数：返回的内容
 * 返回值:1：成功，0：失败
 * */
int SendDataByJson(const char *pszURL, const char *pszSnedData, char *pszRetData);

/*
 * 输入参数1：发送到的地址
 * 输入参数2：发送的数据
 * 输出参数：返回的内容
 * 返回值:1：成功，0：失败
 * */
int SendData(const char *pszURL, const char *pszSnedData, char *pszRetData);

typedef struct AE{
	char a;
	unsigned char b;
}AE;

static AE ae[] = {
	{'0',0x00}, {'1',0x01}, {'2',0x02}, {'3',0x03}, {'4',0x04}, {'5',0x05},
	{'6',0x06}, {'7',0x07}, {'8',0x08}, {'9',0x09}, 
	{'A',0x0A}, {'B',0x0B}, {'C',0x0C}, {'D',0x0D}, {'E',0x0E}, {'F',0x0F},
	{'a',0x0a}, {'b',0x0b}, {'c',0x0c}, {'d',0x0d}, {'e',0x0e}, {'f',0x0f}
};

static AE ea[] = {
	{'0',0x00}, {'1',0x01}, {'2',0x02}, {'3',0x03}, {'4',0x04}, {'5',0x05},
	{'6',0x06}, {'7',0x07}, {'8',0x08}, {'9',0x09}, 
	{'A',0x0A}, {'B',0x0B}, {'C',0x0C}, {'D',0x0D}, {'E',0x0E}, {'F',0x0F},
	{'A',0x0a}, {'B',0x0b}, {'C',0x0c}, {'D',0x0d}, {'E',0x0e}, {'F',0x0f}
};

char ebccharasc( unsigned char codeE );

unsigned char asccharebc( char codeA );

void AscToEbc(char *pszData, int nLen);

void EbcToAsc(char *pszEbc, char *pszAsc, int nLen);

/*
 * 函数说明：在调用动态库时需先调用此函数以初始化数据
 * 输入参数：无
 * 返回值：无
 * */
void InitRsaErrData();

/*
 * 输入参数1：待加密的数据（最长是117个字节的EBC码）
 * 输入参数2：待加密的数据的长度
 * 输入参数3：带绝对路径的公钥文件名
 * 输出参数4：加密后的数据(16进制的256位字符串表示)
 * 返回值：1：加密成功，0：加密失败 
 * */
int RsaEncrypt(const unsigned char *puszData, const int nDataLen, 
		const char *pszPublicKeyPath, char *pszHexData);
		
/*
 * 输入参数1：待解密的数据(以16进制字符串表示)
 * 输入参数2：带绝对路径的私钥文件名
 * 输出参数3：解密后的数据
 * 输出参数4：解密后数据的长度
 * 返回值：1：解密成功，0：解密失败 
 * */
int RsaDecrypt(const char *pszHexData, const char *pszPrivateKeyPath, 
		char *puszDecryptData, int *pnDecryptDataLen);
		
/*
 * 输入参数1：待签名的数据(字符串和16进制字符串)
 * 输入参数2：带绝对路径的私钥文件名
 * 输出参数3：签名后的数据(以16进制字符串表示)
 * 输出参数4：签名后的数据长度
 * 返回值：1：成功，0：失败
 * */
int RsaSign(const unsigned char *pszData, const char *pszPrivateKeyPath, 
		char *pszHexSignData, unsigned int *pnHexSignDataLen);
		
/*
 * 参数1：待验证的数据(以16进制字符串表示)
 * 参数2：待验证的数据的长度
 * 参数3：原始的数据
 * 参数2：带绝对路径的公钥文件名
 * 返回值：1：验证签名成功，0：验证签名失败
 * */
int RsaVerify(const char *pszHexSignData, const unsigned int nHexSignDataLen, 
        const unsigned char *pszVerifyData, const char * pszPublicKeyPath);

//记录日志基本要求：时间，错误文件，错误行号，错误函数名，错误码，错误信息
/*
 * 参数1：错误码
 * 参数2：错误信息
 * 返回值：无
 * */
void _ytk_log(const int error_code, const char *error, 
        const char *file_name, int line, const char *func);

#define ytk_log(error_code, error) \
    _ytk_log(error_code, error, __FILE__, __LINE__, __FUNCTION__)

#endif //end of NT_YTK_H


