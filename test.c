#include "nt_ytk.h"

int main(int argc, char **argv)
{
    //发送json格式的数据
    char *pszSendDataByJson = "{\"reqData\":{\"balance\":\"4000\",\"file0015\":\"2FB9E3B6AB44010001160444019300000000000711201401010034D804C00F61B3843C1126150910412CB4A2D6B59000\",\"institutionCode\":\"000J0000011\"}}";    

    //发送的数据
    char *pszSendData = "user.mobilephone=15975606172&securityCodeType=orgreg";

    char pszRetData[1024] = {0};     //接收的数据
    
    char *pszURL = "http://61.145.127.28:8090/InterfaceManage/ws/rest/check";    //卡检查地址

    if( 0 != SendDataByJson(pszURL, pszSendDataByJson, pszRetData) )
        printf("接收到的json数据：%s\n", pszRetData);

    memset(pszRetData, 0, sizeof(pszRetData));

    pszURL = "http://61.145.127.28:8090/InterfaceManage/admin/user_verificationCode.do";   //获取手机号

    if( 0 != SendData(pszURL, pszSendData, pszRetData) )
        printf("接收到的数据：%s\n", pszRetData);


    const unsigned char *pszSourceData = "00112233445566778899AABBCCDDEEFF";    //待加密的数据
    char pszHexEncryptData[1024] = {0};					//加密后16进制字符串数据
    char pszDecryptData[1024] = {0};					//解密后的数据
	int nDecryptDataLen = 0;							//解密后的数据的长度
	char pszHexSignData[1024] = {0};					//签名后的16进制字符串数据
	unsigned int nHexSignDataLen = 0;					//签名后的16进制字符串数据的长度
	
    const char *pszPublicKeyPath = "/home/dell/ytk_project/rsa_public_key.pem";
    const char *pszPrivateKeyPath = "/home/dell/ytk_project/rsa_private_key.pem";
	
    //test begin
    //const char *pszPublicKeyPath = "/home/lin/RSA/RSA_Release/RSA_C/base64_test/lhdz_public_key.pem";
    //const char *pszPrivateKeyPath = "/home/lin/RSA/RSA_Release/RSA_C/base64_test/lhdz_private_key.pem";
	//test end

    //rsa加密 begin	
    //载入openssl的人类可读的错误信息
    InitRsaErrData();

    printf("原始数据: %s\n", pszSourceData);
 
    //加密
    if( 1 == RsaEncrypt(pszSourceData, strlen((const unsigned char *)pszSourceData), pszPublicKeyPath, pszHexEncryptData) )
    {
        printf("pszHexEncryptData: %s\n", pszHexEncryptData);
        printf("加密成功\n");
    }

    //解密
    if( 1 == RsaDecrypt(pszHexEncryptData, pszPrivateKeyPath, pszDecryptData, &nDecryptDataLen) )
    {
        printf("pszDecryptData: %s\nnDecryptDataLen：%d\n", pszDecryptData, nDecryptDataLen);
        printf("解密成功\n");
    }
	
    //签名
    if(1 == RsaSign(pszSourceData, pszPrivateKeyPath, pszHexSignData, &nHexSignDataLen) )
    {
        printf("pszHexSignData: %s\nnHexSignDataLen: %d\n", pszHexSignData, nHexSignDataLen);
        printf("签名成功\n");
    }

    //验证签名 
    if( 1 == RsaVerify(pszHexSignData, nHexSignDataLen, pszSourceData, pszPublicKeyPath) )
    {
        printf("验证签名成功\n");
    }
    //rsa加密 end

    return 0;
}
