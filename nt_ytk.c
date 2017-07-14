#include "nt_ytk.h"

unsigned char asccharebc( char codeA )
{
	int i = 0;
	
	for( i = 0; i < sizeof(ae) / sizeof(AE); i++ )
	{
		if( ae[i].a == codeA )
			return( ae[i].b );
	}
	return( ae[0].b );
}

char ebccharasc( unsigned char codeE )
{
	int i = 0;
	for( i = 0; i < sizeof(ea) / sizeof(AE); i++ )
	{
		if( ea[i].b == codeE )
			return( ea[i].a );
	}
	return( ea[0].a );
}

void AscToEbc(char *pszData, int nLen)
{
	int  nPos, i;
	char cHalf;
    char * pszTemp;

	//动态申请内存
    pszTemp = (char *)malloc(nLen+2); 
    if(NULL == pszTemp)
    {
        return;
    }
	memset( pszTemp, 0, nLen+2 );
	
	//不为2的整数倍时前补字符0
	if( nLen % 2 != 0 )
	{
		memcpy( &pszTemp[1], pszData, nLen );
		pszTemp[0] = '0';
		nLen++;
	}
	else
		memcpy( pszTemp, pszData, nLen );

	//逐个字节进行转化和移位
	for( i = 0, nPos = 0; i < nLen; i++ )
	{
		//判断是奇数位还是偶数位
		if( i % 2 == 0 )
		{
			cHalf = 0;
			cHalf = asccharebc( pszTemp[i] );
			cHalf = cHalf << 4;
		}
		else
		{
			pszData[nPos] = cHalf | ( asccharebc( pszTemp[i] ) & 0x0f );
			nPos++;
		}
	}
	//后面赋值结束符0
	pszData[nPos] = 0;

	//释放动态申请的内存
	free(pszTemp);
	pszTemp = NULL;
}

void EbcToAsc(char *pszEbc, char *pszAsc, int nLen)
{
	int i;
	unsigned char ucAscii;
	for( i = 0; i < nLen; i++ )
	{
		ucAscii = ( pszEbc[i] >> 4 ) & 0x0f;
		pszAsc[2*i] = ebccharasc( ucAscii );
		ucAscii = pszEbc[i] & 0x0f;
		pszAsc[2*i+1] = ebccharasc( ucAscii );
	}
}

/*
 * 函数说明：在调用openssl动态库时需先调用此函数以初始化错误数据
 * 输入参数：无
 * 返回值：无
 * */
void InitRsaErrData()
{
    //载入openssl的人类可读的错误信息
    ERR_load_ERR_strings();
    ERR_load_crypto_strings();

    ytk_log(0, "载入RSA错误信息成功");
}

/*
 * 输入参数1：待加密的数据（最长是117个字节的EBC码）
 * 输入参数2：待加密的数据的长度
 * 输入参数3：带绝对路径的公钥文件名
 * 输出参数4：加密后的数据(16进制的256位字符串表示)
 * 返回值：1：加密成功，0：加密失败 
 * */
int RsaEncrypt(const unsigned char *puszData, const int nDataLen, 
		const char *pszPublicKeyPath, char *pszHexData)
{
    unsigned char *pszEncryptData ;     //保存RSA加密后的数据
    RSA *pszRsaData;          			//保存读取公钥的数据
    FILE *pszFile;		      			//保存文件指针
    int nRsaLen;			  			//读取pem文件的数据的长度
    int nRetLen = 0;          			//公钥加密后的返回值
    
    //打开以16进制字符串保存的公钥文件
    if( NULL == ( pszFile = fopen(pszPublicKeyPath, "r") ) )
    {
        ytk_log(errno, "打开文件失败");

        return 0;
    }
    else
    {
        ytk_log(0, "打开文件成功");
    }

    //读取公钥文件
    if( NULL == ( pszRsaData = PEM_read_RSA_PUBKEY(pszFile, NULL, NULL, NULL) ) )
    {
        char chErrorMsg[1024] = {0};
        unsigned long ulErrorCode;

        ulErrorCode = ERR_get_error();
        ERR_error_string(ulErrorCode, chErrorMsg); 

        ytk_log((int)ulErrorCode, chErrorMsg);

        fclose(pszFile);

        return 0;
    }
    else
    {
        ytk_log(0, "读取公钥文件成功");
        fclose(pszFile);
    }
    
    //加密过程
    nRsaLen = RSA_size(pszRsaData);
    //申请内存，记得外部调用函数释放
    pszEncryptData = (char *)malloc(nRsaLen+1);
    if(NULL == pszEncryptData)   
    {
        ytk_log(0, "分配内存失败");

        RSA_free(pszRsaData);
        pszRsaData = NULL;

        return 0;
    }
    memset(pszEncryptData, 0, nRsaLen+1);

    //添加一个参数来表示待加密数据puszData的长度，然后判断长度不能超过rsa_len-11
	//超过则函数执行失败
	//如果有超长数据要加密，只能分段加密
	if( nDataLen > nRsaLen - 11 )
	{
        ytk_log(0, "分配内存失败");

        RSA_free(pszRsaData);
        pszRsaData = NULL;
        free(pszEncryptData);
        pszEncryptData = NULL;
		
		return 0;
	}
    //使用RSA/ECB/PKCS1Padding填充方式
    //明文数据的长度不能超过过128-11=117字节
    if( ( nRetLen = RSA_public_encrypt(nRsaLen-11, puszData, pszEncryptData, 
                pszRsaData, RSA_PKCS1_PADDING) ) < 0 )
    {
        char chErrorMsg[1024] = {0};
        unsigned long ulErrorCode;

        ulErrorCode = ERR_get_error();
        ERR_error_string(ulErrorCode, chErrorMsg); 

        ytk_log((int)ulErrorCode, chErrorMsg);

        RSA_free(pszRsaData);
        pszRsaData = NULL;
        free(pszEncryptData);
        pszEncryptData = NULL;

        return 0;
    }
    else
    {
        ytk_log(0, "加密成功");
    }
    
    //字符串转换为16进制字符串
    EbcToAsc(pszEncryptData, pszHexData, nRetLen);

    free(pszEncryptData);
    pszEncryptData = NULL;
    //释放rsa内存
    RSA_free(pszRsaData);
    pszRsaData = NULL;

    return 1;
}

/*
 * 输入参数1：待解密的数据(以16进制字符串表示)
 * 输入参数2：带绝对路径的私钥文件名
 * 输出参数3：解密后的数据
 * 输出参数4：解密后数据的长度
 * 返回值：1：解密成功，0：解密失败 
 * */
int RsaDecrypt(const char *pszHexData, const char *pszPrivateKeyPath, 
		char *puszDecryptData, int *pnDecryptDataLen)
{
    unsigned char *pszRsaDecryptData;   //保存rsa解密后的数据
    RSA *pszRsaData;		   			//保存读取私钥的数据
    FILE *pszFile;			   			//保存文件指针
    int nRsaLen;               			//读取pem文件的数据的长度
    unsigned char szTemp[1024] = {0};   //解密后的数据
    
    //打开私钥文件
    if( NULL == ( pszFile = fopen(pszPrivateKeyPath, "r") ) )
    {
        ytk_log(errno, "打开文件失败");

        return 0;
    }
    else
    {
        ytk_log(0, "打开文件成功");
    }

    //读取私钥文件
    if( NULL == ( pszRsaData = PEM_read_RSAPrivateKey(pszFile, NULL, NULL, NULL) ) )
    {
        char chErrorMsg[1024] = {0};
        unsigned long ulErrorCode;

        ulErrorCode = ERR_get_error();
        ERR_error_string(ulErrorCode, chErrorMsg); 

        ytk_log((int)ulErrorCode, chErrorMsg);

        fclose(pszFile);

        return 0;
    }
    else
    {
        fclose(pszFile);
        ytk_log(0, "读取私钥文件成功");
    }

    //解密过程
    nRsaLen = RSA_size(pszRsaData);

    //申请内存
    pszRsaDecryptData = (char *)malloc(nRsaLen+1);
    if(NULL == pszRsaDecryptData)
    {
        ytk_log(0, "分配内存失败");

        RSA_free(pszRsaData);
        pszRsaData = NULL;

        return 0;
    }
    memset(pszRsaDecryptData, 0, nRsaLen+1);

	//把16进制字符串转换为EBC码
    memcpy(szTemp, pszHexData, strlen(pszHexData));
    AscToEbc(szTemp, strlen(szTemp));

    *pnDecryptDataLen = RSA_private_decrypt(nRsaLen, szTemp, pszRsaDecryptData, 
                pszRsaData, RSA_PKCS1_PADDING); 
    if( -1 == *pnDecryptDataLen )
    {
        char chErrorMsg[1024] = {0};
        unsigned long ulErrorCode;

        ulErrorCode = ERR_get_error();
        ERR_error_string(ulErrorCode, chErrorMsg); 

        ytk_log((int)ulErrorCode, chErrorMsg);

        RSA_free(pszRsaData);
        pszRsaData = NULL;
        free(pszRsaDecryptData);
        pszRsaDecryptData = NULL;

        return 0;
    }
    else
    {
        memcpy(puszDecryptData, pszRsaDecryptData, *pnDecryptDataLen);
        puszDecryptData[*pnDecryptDataLen] = 0;
        ytk_log(0, "解密成功");
    }

    //释放rsa内存
    RSA_free(pszRsaData);
    pszRsaData = NULL;
    free(pszRsaDecryptData);
    pszRsaDecryptData = NULL;

    return 1;
}

/*
 * 输入参数1：待签名的数据(字符串和16进制字符串)
 * 输入参数2：带绝对路径的私钥文件名
 * 输出参数3：签名后的数据(以16进制字符串表示)
 * 输出参数4：签名后的数据长度
 * 返回值：1：成功，0：失败
 * */
int RsaSign(const unsigned char *pszData, const char *pszPrivateKeyPath, 
		char *pszHexSignData, unsigned int *pnHexSignDataLen)
{
    RSA *pszRsaData;			//保存读取私钥的数据
    FILE *pszFile;				//保存文件指针
    char *pszSignData;			//签名后的数据
    unsigned int nRsaLen;		//读取pem文件的数据的长度
    unsigned char md[20] = {0}; //SHA1数据摘要

    //打开私钥文件
    if( NULL == ( pszFile = fopen(pszPrivateKeyPath, "r") ) )
    {
        ytk_log(errno, "打开文件失败");

        return 0;
    }
    else
    {
        ytk_log(0, "打开文件成功");
    }

    //读取私钥文件
    if( NULL == ( pszRsaData = PEM_read_RSAPrivateKey(pszFile, NULL, NULL, NULL) ) )
    {
        char chErrorMsg[1024] = {0};
        unsigned long ulErrorCode;

        ulErrorCode = ERR_get_error();
        ERR_error_string(ulErrorCode, chErrorMsg); 

        ytk_log((int)ulErrorCode, chErrorMsg);

        fclose(pszFile);

        return 0;
    }
    else
    {
        fclose(pszFile);
        ytk_log(0, "读取私钥文件成功");
    }

    nRsaLen = RSA_size(pszRsaData);
    pszSignData = (char *)malloc(nRsaLen+1);
    if(NULL == pszSignData)
    {
        ytk_log(0, "分配内存失败");
        RSA_free(pszRsaData);
        pszRsaData = NULL;

        return 0;
    }
    memset(pszSignData, 0, nRsaLen+1);

    //做SHA1数字摘要
    SHA1(pszData, strlen(pszData), md);

    //签名
    if( 0 == RSA_sign(NID_sha1, md, 20, pszSignData, pnHexSignDataLen, pszRsaData) )
    {
        char chErrorMsg[1024] = {0};
        unsigned long ulErrorCode;

        ulErrorCode = ERR_get_error();
        ERR_error_string(ulErrorCode, chErrorMsg); 

        ytk_log((int)ulErrorCode, chErrorMsg);

        RSA_free(pszRsaData);
        pszRsaData = NULL;
        free(pszSignData);
        pszSignData = NULL;

        return 0;
    }
    else
    {
        ytk_log(0, "签名成功");
    }

	//test begin
	//printf("%s\n", pszSignData);
	//test end
	
    //字符串（EBC码）转16进制字符串
    EbcToAsc(pszSignData, pszHexSignData, *pnHexSignDataLen);

    free(pszSignData);
    pszSignData = NULL;
    RSA_free(pszRsaData);
    pszRsaData = NULL;

    return 1;
}

/*
 * 参数1：待验证的数据(以16进制字符串表示)
 * 参数2：待验证的数据的长度
 * 参数3：原始的数据
 * 参数2：带绝对路径的公钥文件名
 * 返回值：1：验证签名成功，0：验证签名失败
 * */
int RsaVerify(const char *pszHexSignData, const unsigned int nHexSignDataLen, 
        const unsigned char *pszVerifyData, const char * pszPublicKeyPath)
{
    RSA *pszRsaData;
    FILE *pszFile;
    char szTemp[1024] = {0};
    unsigned long ulVerifyDataLen;
    unsigned char md[20] = {0};

    //打开公钥文件
    if( NULL == ( pszFile = fopen(pszPublicKeyPath, "r") ) )
    {
        ytk_log(errno, "打开文件失败");

        return 0;
    }
    else
    {
        ytk_log(0, "打开文件成功");
    }

    //读取公钥文件
    if( NULL == ( pszRsaData = PEM_read_RSA_PUBKEY(pszFile, NULL, NULL, NULL) ) )
    {
        char chErrorMsg[1024] = {0};
        unsigned long ulErrorCode;

        ulErrorCode = ERR_get_error();
        ERR_error_string(ulErrorCode, chErrorMsg); 

        ytk_log((int)ulErrorCode, chErrorMsg);

        fclose(pszFile);

        return 0;
    }
    else
    {
        ytk_log(0, "读取公钥文件成功");
        fclose(pszFile);
    }

    //把16进制编码字符解码
    memcpy(szTemp, pszHexSignData, strlen(pszHexSignData) ); 
    AscToEbc(szTemp, strlen(szTemp));

    //对原始数据做SHA1
    ulVerifyDataLen = (unsigned long)strlen(pszVerifyData);
    SHA1(pszVerifyData, ulVerifyDataLen, md);
    //验证签名
    if( 0 == RSA_verify(NID_sha1, md, 20, szTemp, nHexSignDataLen, pszRsaData) )
    {
        char chErrorMsg[1024] = {0};
        unsigned long ulErrorCode;

        ulErrorCode = ERR_get_error();
        ERR_error_string(ulErrorCode, chErrorMsg); 

        ytk_log((int)ulErrorCode, chErrorMsg);
        
        RSA_free(pszRsaData);
        pszRsaData = NULL;

        return 0;
    }
    else
    {
        ytk_log(0, "验证签名成功");
    }

    RSA_free(pszRsaData);
    pszRsaData = NULL;
    
    return 1;
}

/* 函数说明：libcurl接收数据时的回调函数，libcurl要求函数用这种格式，否则报错
 * pszBuff：接收到的数据所在缓冲区 
 * nBuffSize：数据片长度(单位大小)
 * nMemb：数据片数量
 * pszData：用户自定义的指针
 * 返回值：获取的数据的长度：成功，0：失败
 * */
size_t GetData(void *pszBuff, size_t nBuffSize, size_t nMemb, void *pszData)  
{  
    if( NULL == pszBuff || NULL == pszData )
    {
        ytk_log(0, "服务器没有返回内容");

        return 0;
    }

    memcpy(pszData, pszBuff, nBuffSize*nMemb);
    ytk_log(1, "服务器返回内容成功");

    //test begin
    //ytk_log(1, pszData);
    //printf("nMemb: %d\n", nMemb);
    //test end

    return nMemb;
} 

/*
 * 函数说明：发送json格式的报文
 * 输入参数1：发送到的地址
 * 输入参数2：发送的数据
 * 输出参数：返回的内容
 * 返回值:1：成功，0：失败
 * */
int SendDataByJson(const char *pszURL, const char *pszSnedData, char *pszRetData)
{
    CURL *pCurl;                            //curl的结构体，指向建立起来的curl
    CURLcode nRet;                          //定义nRet来保存curl/http的请求的返回码

    struct curl_slist* pHeaders = NULL;     //定义curl的头部结构体

    //全局初始化
    nRet = curl_global_init(CURL_GLOBAL_ALL);
    if( CURLE_OK != nRet )
    {
        ytk_log((int)nRet, curl_easy_strerror(nRet));

        return 0;
    }

    /* get a curl handle */
    pCurl = curl_easy_init();
    if( NULL == pCurl )
    {
        curl_global_cleanup();

        ytk_log(0, "curl_easy_init()执行失败");

        return 0;
    }

    //curl要发送的报文添加头部   begin=====================================================
    //表示本地curl接受报文为json
    pHeaders = curl_slist_append(pHeaders, "Accept:application/json");

    //请求我们发送的报文为json，注意这里一定要说明自己发送的信息为json类型的，
    //否则对方使用的应用层函数，可能无法正确的识别解析
    pHeaders = curl_slist_append(pHeaders, "Content-Type:application/json");

    //表示我们发送的报文的编码格式为ut-8类型的格式
    pHeaders = curl_slist_append(pHeaders, "charset:utf-8");

    //curl结构体添加刚刚组好的头部
    curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, pHeaders);
    //curl要发送的报文添加头部   end======================================================

    //curl结构体中设置要发送请求的url
    curl_easy_setopt(pCurl, CURLOPT_URL, pszURL);

    //设置curl的发送时间为60S，过了60S就超时
    curl_easy_setopt(pCurl, CURLOPT_TIMEOUT, 60);

    //设置curl为post发送方式
    curl_easy_setopt(pCurl, CURLOPT_POST, 1);

    //curl结构体中设置要发送的数据
    curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, pszSnedData);

    //curl结构体定义一个回调函数处理url返回的数据
    curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, GetData);

    //curl结构体定义一个值，传给回调函数处理
    curl_easy_setopt(pCurl, CURLOPT_WRITEDATA, pszRetData);

    //执行
    nRet = curl_easy_perform(pCurl);
    if( CURLE_OK != nRet )
    {
		ytk_log((int)nRet, curl_easy_strerror(nRet));
        
        curl_slist_free_all(pHeaders);
        curl_easy_cleanup(pCurl);
        curl_global_cleanup();

        return 0;
    }

    ytk_log(1, "SendDataByJson()执行成功");

    curl_slist_free_all(pHeaders);
    curl_easy_cleanup(pCurl);
    curl_global_cleanup();
    
    return 1;
}

/*
 * 输入参数1：发送到的地址
 * 输入参数2：发送的数据
 * 输出参数：返回的内容
 * 返回值:1：成功，0：失败
 * */
int SendData(const char *pszURL, const char *pszSnedData, char *pszRetData)
{
    CURL *pCurl;                            //curl的结构体，指向建立起来的curl
    CURLcode nRet;                          //定义nRet来保存curl/http的请求的返回码

    struct curl_slist* pHeaders = NULL;     //定义curl的头部结构体

    //全局初始化
    nRet = curl_global_init(CURL_GLOBAL_ALL);
    if( CURLE_OK != nRet )
    {
		ytk_log((int)nRet, curl_easy_strerror(nRet));
		
        return 0;
    }

    /* get a curl handle */
    pCurl = curl_easy_init();
    if( NULL == pCurl )
    {
        curl_global_cleanup();

        ytk_log(0, "curl_easy_init()执行失败");

        return 0;
    }

    //curl要发送的报文添加头部   begin=====================================================
    //表示本地curl接受报文为json
    pHeaders = curl_slist_append(pHeaders, "Accept:application/json");

    //表示我们发送的报文的编码格式为ut-8类型的格式
    pHeaders = curl_slist_append(pHeaders, "charset:utf-8");

    //curl结构体添加刚刚组好的头部
    curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, pHeaders);
    //curl要发送的报文添加头部   end======================================================

    //curl结构体中设置要发送请求的url
    curl_easy_setopt(pCurl, CURLOPT_URL, pszURL);

    //设置curl的发送时间为60S，过了60S就超时
    curl_easy_setopt(pCurl, CURLOPT_TIMEOUT, 60);

    //设置curl为post发送方式
    curl_easy_setopt(pCurl, CURLOPT_POST, 1);

    //curl结构体中设置要发送的数据
    curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, pszSnedData);

    //curl结构体定义一个回调函数处理url返回的数据
    curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, GetData);

    //curl结构体定义一个值，传给回调函数处理
    curl_easy_setopt(pCurl, CURLOPT_WRITEDATA, (void*)pszRetData);

    //执行
    nRet = curl_easy_perform(pCurl);
    if( CURLE_OK != nRet )
    {
		ytk_log((int)nRet, curl_easy_strerror(nRet));
        
        curl_slist_free_all(pHeaders);
        curl_easy_cleanup(pCurl);
        curl_global_cleanup();

        return 0;
    }

    ytk_log(1, "SendData()执行成功");

    curl_slist_free_all(pHeaders);
    curl_easy_cleanup(pCurl);
    curl_global_cleanup();
    
    return 1;
}

//记录日志基本要求：时间，错误文件，错误行号，错误函数名，错误码，错误信息
void _ytk_log(const int ulErrorCode, const char *error, 
        const char *file_name, int line, const char *func)
{
    FILE *pszFile;
    
    char time_str[40] = {0};
    time_t t;
    struct tm *nowtime;
    
    char log_name[50];

    time(&t);
    nowtime = localtime(&t);

	//test begin
    //printf("time: %d\n", nowtime->tm_year);
	//test end
	
    strftime(log_name, sizeof(log_name), "./ytk_%Y%m%d.log", nowtime);
    
    pszFile = fopen(log_name, "at+");
    if(NULL == pszFile)
    {
        printf("打开日志文件失败\n");

        return;
    }

    strftime(time_str, sizeof(time_str), "%Y-%m-%02d-%H:%M:%S", nowtime);
	
	//test begin
    //sprintf( time_str， "%04d%02d%02d%02d%02d%02d", nowtime->tm_year+1900, nowtime->tm_mon+1, 
    //        nowtime->tm_mday, nowtime->tm_hour, nowtime->tm_min, nowtime->tm_sec );
	//test end
	
    fprintf(pszFile, "%s_%s_%d_%s_%d : %s\n", time_str, file_name, line, func, ulErrorCode, error);

    fclose(pszFile); 
}
