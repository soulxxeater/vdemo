//设备信息标识
var SGD_DEVICE_SORT                      = 0x00000201;  //设备类别
var SGD_DEVICE_TYPE                      = 0x00000202;  //设备型号
var SGD_DEVICE_NAME                      = 0x00000203;  //设备名称
var SGD_DEVICE_MANUFACTURER              = 0x00000204;  //生产厂商
var SGD_DEVICE_HARDWARE_VERSION          = 0x00000205;  //硬件版本
var SGD_DEVICE_SOFTWARE_VERSION          = 0x00000206;  //软件版本
var SGD_DEVICE_STANDARD_VERSION          = 0x00000207;  //符合标准版本
var SGD_DEVICE_SERIAL_NUMBER             = 0x00000208;  //设备编号 设备序列号 介质编号
var SGD_DEVICE_SUPPORT_ALG               = 0x00000209;  //设备能力字段,标识密码设备支持的非对称密码算法
var SGD_DEVICE_SUPPORT_SYM               = 0x0000020A;  //设备能力字段,标识密码设备支持的对称密码算法
var SGD_DEVICE_SUPPORT_HASH_ALG          = 0x0000020B;  //设备能力字段,标识密码设备支持的杂凑密码算法
var SGD_DEVICE_SUPPORT_STORAGE_SPACE     = 0x0000020C;  //设备能力字段,标识密码设备最大文件存储空间
var SGD_DEVICE_SUPPORT_FREE_SPACE        = 0x0000020D;  //设备能力字段,标识密码设备空闲文件存储空间
var SGD_DEVICE_RUNTIME                   = 0x0000020E;  //已运行时间
var SGD_DEVICE_USED_TIMES                = 0x0000020F;  //设备调用次数
var SGD_DEVICE_LOCATION                  = 0x00000210;  //设备物理位置
var SGD_DEVICE_DESCRIPTION               = 0x00000211;  //设备描述
var SGD_DEVICE_MANAGER_INFO              = 0x00000212;  //设备管理者描述信息
var SGD_DEVICE_MAX_DATA_SIZE             = 0x00000213;  //设备能力字段,一次能处理的数据容量
var SGD_DEVICE_MAX_ECC_BUF_SIZE          = 0x00000214;  //能够处理的ECC加密数据大小
var SGD_DEVICE_MAX_BUF_SIZE              = 0x00000215;  //能够处理的分组运算和杂凑运算的数据大小
var SGD_EXT_DEVICE_TYPE                  = 0x00000300;  //设备类型(自定义扩展)
var SGD_EXT_DEVICE_VIDPID                = 0x00000301;  //设备VID和PID信息(自定义扩展)

//证书解析项标识
var SGD_CERT_ALL                         = 0x00000000;  //证书信息
var SGD_CERT_VERISON                     = 0x00000001;  //证书版本
var SGD_CERT_SERIAL                      = 0x00000002;  //证书序列号
var SGD_CERT_SIGNALG                     = 0x00000004;  //证书签名算法
var SGD_CERT_ISSUER                      = 0x00000005;  //证书颁发者信息
var SGD_CERT_VALID_TIME                  = 0x00000006;  //证书有效期
var SGD_CERT_SUBJECT                     = 0x00000007;  //证书拥有者信息
var SGD_CERT_DER_PUBLIC_KEY              = 0x00000008;  //证书公钥信息
var SGD_CERT_DER_EXTENSIONS              = 0x00000009;  //证书扩展项信息
var SGD_EXT_AUTHORITYKEYIDENTIFIER_INFO  = 0x00000011;  //颁发者密钥标识符
var SGD_EXT_SUBJECTKEYIDENTIFIER_INFO    = 0x00000012;  //证书持有者密钥标识符
var SGD_EXT_KEYUSAGE_INFO                = 0x00000013;  //密钥用途
var SGD_EXT_PRIVATEKEYUSAGEPERIOD_INFO   = 0x00000014;  //私钥有效期
var SGD_EXT_CERTIFICATEPOLICIES_INFO     = 0x00000015;  //证书策略
var SGD_EXT_POLICYMAPPINGS_INFO          = 0x00000016;  //策略映射
var SGD_EXT_BASICCONSTRAINTS_INFO        = 0x00000017;  //基本限制
var SGD_EXT_POLICYCONTRAINTS_INFO        = 0x00000018;  //策略限制
var SGD_EXT_EXTKEYUSAGE_INFO             = 0x00000019;  //扩展密钥用途
var SGD_EXT_CRLDISTRIBUTIONPOINTS_INFO   = 0x0000001A;  //CRL发布点
var SGD_EXT_NETSCAPE_CERT_TYPE_INFO      = 0x0000001B;  //Netscape属性
var SGD_EXT_SELFDEFINED_EXTENSION_INFO   = 0x0000001C;  //私有的自定义扩展项
var SGD_CERT_ISSUER_CN                   = 0x00000021;  //证书颁发者CN
var SGD_CERT_ISSUER_O                    = 0x00000022;  //证书颁发者O
var SGD_CERT_ISSUER_OU                   = 0x00000023;  //证书颁发者OU
var SGD_CERT_SUBJECT_CN                  = 0x00000031;  //证书拥有者信息CN
var SGD_CERT_SUBJECT_O                   = 0x00000032;  //证书拥有者信息O
var SGD_CERT_SUBJECT_OU                  = 0x00000033;  //证书拥有者信息OU
var SGD_CERT_SUBJECT_EMAIL               = 0x00000034;  //证书拥有者信息EMAIL

//扩展类型
var SGD_EXT_CERT_TYPE_UFID               = 0x00010001;  //证书类型统一编号
var SGD_EXT_CERT_TYPE_SUBCODE            = 0x00010002;  //证书类型子代码
var SGD_EXT_CERT_TYPE_ALL                = 0x00010003;  //证书类型统一编号及子代码
var SGD_CERT_VALID_TIME_FMT1             = 0x00010006;  //证书有效期 格式yyyy-MM-dd hh:mm:ss
var SGD_NOT_BEFORE_TIME                  = 0x00010007;  //证书生效日期 格式yyyy-MM-dd hh:mm:ss
var SGD_NOT_AFTER_TIME                   = 0x00010008;  //证书截止日期 格式yyyy-MM-dd hh:mm:ss
var SGD_AUTHORITYKEYIDENTIFIER_INFO      = 0x00010009;  //授权密钥标识符 格式：KeyID=118fe3fd39191d9c191f49376eac448c55ea14bd
var SGD_SUBJECTKEYIDENTIFIER_INFO        = 0x0001000A;  //证书持有者密钥标识符 格式：118fe3fd39191d9c191f49376eac448c55ea14bd
var SGD_CERT_SUBJECT_INFO                = 0x0001000B;  //证书使用者信息
var SGD_CERT_ISSUER_INFO                 = 0x0001000C;  //证书颁发者信息

//安全认证服务错误码
var SAR_MsgParseErr     				 = 0x0A000002;	//报文解析错误
var SAR_MsgParamErr     				 = 0x0A000003;	//报文参数错误
var SAR_MsgBase64Err     				 = 0x0A000004;	//Base64编解码失败

//0020接口错误代码
var SOR_OK                      = 0;             //成功
var SOR_UnknownErr              = 0x0B000001;    //异常错误
var SOR_NotSupportYetErr        = 0x0B000002;    //不支持的服务
var SOR_FileErr                 = 0x0B000003;    //文件操作错误
var SOR_ProviderTypeErr         = 0x0B000004;    //服务提供者参数类型错误
var SOR_LoadProviderErr         = 0x0B000005;    //导入服务提供者接口错误
var SOR_LoadDevMngApiErr        = 0x0B000006;    //导入设备管理接口错误
var SOR_AlgoTypeErr             = 0x0B000007;    //算法类型错误
var SOR_NameLenErr              = 0x0B000008;    //名称长度错误
var SOR_KeyUsageErr             = 0x0B000009;    //密钥用途错误
var SOR_ModulusLenErr           = 0x0B000010;    //模的长度错误
var SOR_NotInitializeErr        = 0x0B000011;    //未初始化
var SOR_ObjErr                  = 0x0B000012;    //对象错误
var SOR_MemoryErr               = 0x0B000100;    //内存错误
var SOR_TimeoutErr              = 0x0B000101;    //服务超时
var SOR_IndataLenErr            = 0x0B000200;    //输入数据长度错误
var SOR_IndataErr               = 0x0B000201;    //输入数据错误
var SOR_GenRandErr              = 0x0B000300;    //生成随机数错误
var SOR_HashObjErr              = 0x0B000301;    //HASH对象错
var SOR_HashErr                 = 0x0B000302;    //HASH运算错误
var SOR_GenRsaKeyErr            = 0x0B000303;    //产生RSA密钥错
var SOR_RsaModulusLenErr        = 0x0B000304;    //RSA密钥模长错误
var SOR_CspImprtPubKeyErr       = 0x0B000305;    //CSP服务导入公钥错误
var SOR_RsaEncErr               = 0x0B000306;    //RSA加密错误
var SOR_RsaDecErr               = 0x0B000307;    //RSA解密错误
var SOR_HashNotEqualErr         = 0x0B000308;    //HASH值不相等
var SOR_KeyNotFountErr          = 0x0B000309;    //密钥未发现
var SOR_CertNotFountErr         = 0x0B000310;    //证书未发现
var SOR_NotExportErr            = 0x0B000311;    //对象未导出
var SOR_VeryPolicyErr           = 0x0B000312;    //未能完全按照策略验证成功宏描述预定义值说明
var SOR_DecryptPadErr           = 0x0B000400;    //解密时做补丁错误
var SOR_MacLenErr               = 0x0B000401;    //MAC长度错误
var SOR_KeyInfoTypeErr          = 0x0B000402;    //密钥类型错误
var SOR_NULLPointerErr          = 0x0B000403;    //某一个参数为空指针
var SOR_APPNotFoundErr          = 0x0B000404;    //没有找到该应用
var SOR_CERTENCODEErr           = 0x0B000405;    //证书编码格式错误
var SOR_CERTINVALIDErr          = 0x0B000406;    //证书无效,不是可信CA颁发的证书
var SOR_CERTHASEXPIREDErr       = 0x0B000407;    //证书已过期
var SOR_CERTREVOKEDErr          = 0x0B000408;    //证书已经被吊销
var SOR_SIGNDATAErr             = 0x0B000409;    //签名失败
var SOR_VERIFYSIGNDATAErr       = 0x0B000410;    //验证签名失败
var SOR_READFILEErr             = 0x0B000411;    //读文件异常,可能文件不存在限等或没有读取权
var SOR_WRITEFILEErr            = 0x0B000412;    //写文件异常,
var SOR_SECRETSEGMENTErr        = 0x0B000413;    //门限算法密钥分割失败
var SOR_SECERTRECOVERYErr       = 0x0B000414;    //门限恢复失败
var SOR_ENCRYPTDATAErr          = 0x0B000415;    //对数据的对称加密失败
var SOR_DECRYPTDATAErr          = 0x0B000416;    //对称算法的数据解密失败
var SOR_PKCS7ENCODEErr          = 0x0B000417;    //PKCS7编码格式错误
var SOR_XMLENCODEErr            = 0x0B000418;    //不是合法的xml编码数据
var SOR_PARAMETERNOTSUPPORTErr  = 0x0B000419;    //不支持的参数
var SOR_CTLNOTFOUND             = 0x0B000420;    //没有发现信任列表
var SOR_APPNOTFOUND             = 0x0B000421;    //设置的应用名称没发现
var SOR_BufferTooSmallErr       = 0x0B000422;	 //缓冲区太小
var SOR_Undefined        		= 0x0B000423;	 //未定义
var SOR_InitializeErr        	= 0x0B000424;	 //初始化失败
var SOR_ContainerNotExistErr    = 0x0B000425;	 //容器不存在
var SOR_WrongPinErr        		= 0x0B000426;	 //错误的口令
var SOR_ECCEncErr             	= 0x0B000427;    //ECC加密错误
var SOR_P7SignErr             	= 0x0B000428;    //P7签名错误
var SOR_P7DecErr             	= 0x0B000429;    //P7解密错误
var SOR_TSP_DataErr             = 0x0B000430;    //时间戳服务器应答数据错误
var SOR_TSP_Err             	= 0x0B000431;    //时间戳服务器错误
var SOR_FileExistErr            = 0x0B000432;    //文件已存在
var SOR_NotEnoughSpace          = 0x0B000433;    //空间不足
var SOR_FileNotExistErr         = 0x0B000434;    //文件不存在
var SOR_ReachMaxFileNum         = 0x0B000435;    //已达到最大可创建文件数
var SOR_MUSpaceNotAllocErr      = 0x0B000436;    //多用户空间未分配
var SOR_CAAuthErr       		= 0x0B000437;	 //公私钥不匹配
var SOR_NotLoginErr	      	    = 0x0B000438;    //用户未登录
var SOR_ContainerExistErr       = 0x0B000439;    //容器已存在
var SOR_KeyPairNotMatchErr      = 0x0B000440;    //公私钥不匹配
var SOR_MUNotLogin       		= 0x0B000441;    //多用户未登录
var SOR_UserPinLocked       	= 0x0B000442;    //用户Pin被锁
var SOR_CertParseErr       		= 0x0B000443;    //证书解析错误
var SOR_OIDInfoNotExist       	= 0x0B000444;    //OID信息项不存在
var SOR_UserCancel       	    = 0x0B000447;    //用户取消操作
var SOR_DeviceRemoved       	= 0x0B000448;    //设备已移除

var SOR_EnumDevErr              = 0x0B000500;	 //设备枚举错误
var SOR_CertNotYetValidErr      = 0x0B000501;    //证书未生效
var SOR_CertFrozenErr           = 0x0B000502;    //证书被冻结
var SOR_KeyNotMatchErr          = 0x0B000503;    //密钥不匹配
var SOR_LableNotExist       	= 0x0B000504;    //标签不存在

var SOR_ServiceErr	      	  	= 0x0B001000;	 //
var SOR_ServiceTimeoutErr  	  	= 0x0B001001;	 //
var SOR_ServiceComErr  	  	    = 0x0B001002;	 //通讯错误
var SOR_ServiceNotConnect       = 0x0B001003;	 //未连接服务
var SOR_ServiceInitErr  	    = 0x0B001004;	 //初始化失败
var SOR_XHROpenErr  	        = 0x0B001005;	 //XMLHttpRequest失败
var SOR_XHRNotInitErr           = 0x0B001006;	 //XMLHttpRequest未初始化
var SOR_XHROnReadyErr           = 0x0B001007;	 //onreadystatechange
var SOR_XHRSendErr              = 0x0B001008;	 //
var SOR_XHRExceptionErr         = 0x0B001009;	 //
var SOR_EnumNoCertErr           = 0x0B00100A;	 //未检测到证书
var SOR_CertValicateErr         = 0x0B00100B;	 //证书验证失败

var SOR_TSPEncodeErr      	  	= 0x0B010001;	 //时间戳响应编码失败
var SOR_TSPDecodeErr      	  	= 0x0B010002;	 //时间戳响应解码失败
var SOR_TSPNotExist      	  	= 0x0B010003;	 //时间戳响应不存在
var SOR_Base64EncodeErr       	= 0x0B010004;    //base64编码错误
var SOR_Base64DecodeErr       	= 0x0B010005;    //base64解码错误
var SOR_SM2EncErr           	= 0x0B010006;    //SM2加密错误
var SOR_HttpReqeustErr          = 0x0B010007;    //HTTP请求出错
var SOR_JsonParseErr            = 0x0B010008;    //JSON解析错误
var SOR_FaceMatchFail           = 0x0B010009;    //人脸匹配失败
var SOR_ServerErr               = 0x0B01000A;    //服务器错误
var SOR_SealNotExist            = 0x0B01000B;    //印章不存在
var SOR_HttpReqeustTimeOutErr   = 0x0B01000C;    //HTTP请求超时
var SOR_SealParseErr            = 0x0B01000D;    //印章解析失败
var SOR_FileOpenErr             = 0x0B01000E;    //文件打开失败
var SOR_DataDestroyed           = 0x0B01000F;    //数据被破坏
var SOR_DNItemNotExist          = 0x0B010010;    //DN项信息不存在
var SOR_CACertNotExist          = 0x0B010011;    //CA证书不存在
var SOR_CertNotTrustedErr       = 0x0B010012;    //证书不被信任

//签名算法
var SGD_SM3_RSA      = 0x00010001;     	  //基于SM3算法和RSA算法的签名
var SGD_SHA1_RSA     = 0x00010002;     	  //基于SHA_1算法和RSA算法的签名
var SGD_SHA256_RSA   = 0x00010004;     	  //基于SHA_256算法和RSA算法的签名
var SGD_SM3_SM2      = 0x00020201;     	  //基于SM3算法和SM2算法的签名

//哈希算法
var SGD_SM3      	= 0x00000001;
var SGD_SHA1      	= 0x00000002;
var SGD_SHA256      = 0x00000004;

//分组密码算法
var SGD_SM1_ECB     = 0x00000101;         //SM1算法ECB加密模式
var SGD_SM1_CBC     = 0x00000102;         //SM1算法CBC加密模式
var SGD_SM1_CFB     = 0x00000104;         //SM1算法CFB加密模式
var SGD_SM1_OFB     = 0x00000108;         //SM1算法OFB加密模式
var SGD_SM1_MAC     = 0x00000110;         //SM1算法MAC运算

var SGD_SSF33_ECB   = 0x00000201;         //SSF33算法ECB加密模式
var SGD_SSF33_CBC   = 0x00000202;         //SSF33算法CBC加密模式
var SGD_SSF33_CFB   = 0x00000204;         //SSF33算法CFB加密模式
var SGD_SSF33_OFB   = 0x00000208;         //SSF33算法OFB加密模式
var SGD_SSF33_MAC   = 0x00000210;         //SSF33算法MAC运算

var SGD_SM4_ECB     = 0x00000401;         //SM4算法ECB加密模式
var SGD_SM4_CBC     = 0x00000402;         //SM4算法CBC加密模式
var SGD_SM4_CFB     = 0x00000404;         //SM4算法CFB加密模式
var SGD_SM4_OFB     = 0x00000408;         //SM4算法OFB加密模式
var SGD_SM4_MAC     = 0x00000410;         //SM4算法MAC运算

var SGD_ZUC_EEA3    = 0x00000801;         //ZUC祖冲之;机密性算法128-EEA3算法
var SGD_ZUC_EEI3    = 0x00000802;         //ZUC祖冲之机密性算法128-EIA3算法

var SGD_RSA         = 0x00010000;          //RSA算法
var SGD_SM2         = 0x00020100;          //SM2椭圆曲线密码算法

var XML_SIGN_INFO_PLAIN_DATA =		1;	  //原文
var XML_SIGN_INFO_DIGEST =			2;	  //摘要
var XML_SIGN_INFO_SIGNVALUE =		3;	  //签名值
var XML_SIGN_INFO_SIGNER_CERT =		4;	  //签名证书
var XML_SIGN_INFO_DIGESTALGORITHM =	5;	  //摘要算法
var XML_SIGN_INFO_SIGNALGORITHM =	6;	  //签名算法

//消息签名标识
var SIGN_FLAG_WITH_ORI    =  0;         //带原文
var SIGN_FLAG_WITHOUT_ORI =  1;         //不带原文

var CERT_TYPE_SIGN 		= 1;			//签名证书
var CERT_TYPE_ENCRYPT   = 2;			//加密证书
var CERT_TYPE_EXCHANGE  = 2;			//加密证书

var DEV_EVENT_ARRIVAL = 1;				//设备插入
var DEV_EVENT_REMOVE  = 2;				//设备拔出

var PROTO_NO_SSL = 1;					//不使用SSL通讯
var PROTO_SSL    = 2;					//使用SSL
var PROTO_AUTO   = 3;					//根据网站访问协议自动判断

//证书状态
var SOF_CERT_NOT_TRUSTED			= -1;
var SOF_CERT_HASEXPIRED				= -2;		
var SOF_CERT_REVOKED				= -3;
var SOF_CERT_FROZEN					= -4;
var SOF_CERT_NOTYETVALID			= -5;
var SOF_CERT_OTHER_ERR				= -6;

//设置类型
var SOF_SET_SUPPORT_DEVICE  				= 1;	//设置支持设备
var SOF_SET_INDATA_FORMAT   				= 2;	//设置P1数据签名,P7数据签名和写多用户数据等输入数据格式
var SOF_SET_SIGNMESSAGE_WITH_TSP   			= 3;	//设置P7签名是否带时间戳
var SOF_SET_TSP_URL   						= 4;	//设置时间戳地址
var SOF_SET_TSP_USERNAME   					= 5;	//设置时间戳用户名
var SOF_SET_TSP_PASSWORD   					= 6;	//设置时间戳密码
var SOF_SET_TSP_DIGEST_ALG   				= 7;	//设置时间戳哈希算法
var SOF_SET_HTTP_TIMEOUT            		= 9;	//设置http服务超时时间 (http服务接口有效)
var SOF_SET_P7_ENVELOP_TYPE         		= 10;	//设置P7数字信封格式
var SOF_SET_SUPPORT_DEVICE_EX   			= 11;	//设置支持设备
var SOF_SET_CONNECT_FIRST_DEVICE_WHEN_INIT  = 14;	//设置初始化时就连接第一个枚举到的设备
var SOF_SET_ENUM_NULL_CONTAINER             = 19;	//设置是否枚举空容器 默认否
var SOF_SET_ENUM_MICROSOFT_PFX              = 20;	//设置是否枚举CSP提供者为微软的软证书 默认否
var SOF_SET_GM_TSP_ENDPOINT                 = 24;	//设置国密时间戳URL地址
var SOF_SET_FILE_PART_LEN                   = 29;	//设置文件对称加解密，文件P1签名验签和文件摘要等操作分段计算长度

//支持设备标志,GDCA设备默认支持
var DEV_GDCA_CSP			= 0x8;		    //GDCA-CSP
var DEV_ONLINE				= 0x100000;	    //在线设备
var DEV_ONLINE_GDCA			= 0x200000;	    //GDCA在线设备

//证书颁发方类型
var CA_UNKNOW 	= 0;		//未知
var CA_GDCA 	= 1;		//数安时代
var CA_NETCA 	= 2;		//网证通
var CA_BJCA 	= 3;		//北京CA
var CA_SZCA 	= 4;		//深圳CA
var CA_HNCA 	= 5;		//华测CA

//权限类型
var SECURE_NEVER_ACCOUNT	= 0x00000000;	//不允许
var SECURE_ADM_ACCOUNT		= 0x00000001;	//管理员权限
var SECURE_USER_ACCOUNT		= 0x00000010;	//用户权限
var SECURE_EVERYONE_ACCOUNT	= 0x000000FF;	//任何人

//数据格式
var DATA_FMT_PLAIN		= 1;	//纯文本格式
var DATA_FMT_BASE64		= 2;	//Base64编码格式
var DATA_FMT_HEX		= 3;	//十六进制字符串格式

//标签名称
var LAB_USERCERT_SIG    = "LAB_USERCERT_SIG";
var LAB_USERCERT_SIG_SN = "LAB_USERCERT_SIG_SN";
var LAB_USERCERT_ENC    = "LAB_USERCERT_ENC";
var LAB_USERCERT_ENC_SN = "LAB_USERCERT_ENC_SN";
var LAB_USERID          = "LAB_USERID";
var LAB_OPERATORID      = "LAB_OPERATORID";
var CA_CERT             = "CA_CERT";
var LAB_DISAID          = "LAB_DISAID";

//标签类型
var  GDCA_LBL_CONFIG        = 1;
var  GDCA_LBL_DATA          = 2;
var  GDCA_LBL_EXDATA        = 3;
var  GDCA_LBL_SIGNKEY_1024  = 4;
var  GDCA_LBL_ENCKEY_1024   = 5;
var  GDCA_LBL_SIGNCERT      = 7;
var  GDCA_LBL_ENCCERT       = 8;
var  GDCA_LBL_CACERT        = 9;

var  GDCA_LBL_SIGNKEY_2048 = 14;
var  GDCA_LBL_ENCKEY_2048  = 15;

var  GDCA_LBL_SIGNKEY_SM2 = 44;
var  GDCA_LBL_ENCKEY_SM2  = 45;

//标签读写模式：只读MODE_RD 只写MODE_WR 读写MODE_RW
var GDCA_LBLMODE_RD = 1;
var GDCA_LBLMODE_WR = 2;
var GDCA_LBLMODE_RW = 3;

//密钥用法
var KEY_USAGE_SIGN    = 1;      //签名
var KEY_USAGE_ENCRYPT = 2;      //加密

//印章信息类型
var SOF_SEAL_BASIC_INFO  = 1;       //印章基本信息
var SOF_SEAL_DATA        = 2;       //印章数据
var SOF_SEAL_PIC_DATA    = 3;       //印章图片数据
var SOF_SEAL_SIGNER_INFO = 4;       //签章人信息
var SAF_SEAL_MAKER_CERT  = 5;       //制章人证书

//OID定义
var OID_GDCA_TRUST_ID       = "1.2.86.21.1.3"         //GDCA信任服务号(唯一标识)
var OID_ID_NUM              = "1.2.86.11.7.1"         //个人身份证号码
var OID_SOCIAL_INSURANCE_ID = "1.2.86.11.7.2"         //个人社会保险号
var OID_GDCA_ORG_CODE       = "1.2.86.11.7.3"         //企业组织机构代码
var OID_GDCA_USCC           = "1.2.86.11.7.7550243.1" //GDCA统一社会信用代码
var OID_ORG_REG_ID          = "1.2.86.11.7.4"         //企业工商注册号
var OID_ENTITY_UNIQUE_ID    = "2.16.156.112548"       //实体唯一标识
var OID_HEALTH_UID          = "1.2.156.112576"        //卫生实体唯一标识

//p7消息签名解析类型
var P7_SIGN_PLAIN      = 1;         //原文
var P7_SIGN_SIGNCERT   = 2;         //签名证书
var P7_SIGN_SIGNVALUE  = 3;         //签名值
var P7_SIGN_TSP_CERT   = 4;         //时间戳服务器证书
var P7_SIGN_TSP_INFO   = 5;         //时间戳信息

//认证类型
var CA_AUTH       = 1;
var EXTERNAL_AUTH = 2;
var UNLOCK_AUTH   = 3;

//格式化类型
var FORMAT_NOT_GM    = 1;       //非国密key，不需要认证(类型：11, 16)
var FORMAT_GM_TOKEN  = 2;       //旧国密key，第一次认证(类型：18, 28, 29, 30, 31)
var FORMAT_GM_ROOTDF = 3;       //旧国密key，第二次认证(类型：18, 28, 29, 30, 31)
var FORMAT_NEW_GM    = 4;       //新国密key，一次认证(类型：32, 33, 34, 35, 36)
var FORMAT_SKF       = 5;       //标准SKF

//生成密钥对类型
var KEYPAIR_RSA1024 = 1;
var KEYPAIR_RSA2048 = 2;
var KEYPAIR_SM2     = 3;

//设备类别
var DEV_CLASS_NOT_GM = 1;       //非国密key,设备类型：11, 16
var DEV_CLASS_OLD_GM = 2;       //旧国密key, 设备类型：18, 28, 29, 30, 31)
var DEV_CLASS_NEW_GM = 3;       //新国密key, 设备类型：32, 33, 34, 35, 36)


var os_type_t = 
{
    unknow:0,
    windows:1,
    linux:2,
    mac:3,
    unix:4
};

var Command = {get_adapter_info:8, get_mainboard_sn:9, get_hostname:10};


(function(t,r){if(typeof exports==="object"){module.exports=exports=r()}else if(typeof define==="function"&&define.amd){define([],r)}else{t.CryptoJS=r()}})(this,function(){var t=t||function(v,n){var i=Object.create||function(){function n(){}return function(t){var r;n.prototype=t;r=new n;n.prototype=null;return r}}();var t={};var r=t.lib={};var e=r.Base=function(){return{extend:function(t){var r=i(this);if(t){r.mixIn(t)}if(!r.hasOwnProperty("init")||this.init===r.init){r.init=function(){r.$super.init.apply(this,arguments)}}r.init.prototype=r;r.$super=this;return r},create:function(){var t=this.extend();t.init.apply(t,arguments);return t},init:function(){},mixIn:function(t){for(var r in t){if(t.hasOwnProperty(r)){this[r]=t[r]}}if(t.hasOwnProperty("toString")){this.toString=t.toString}},clone:function(){return this.init.prototype.extend(this)}}}();var h=r.WordArray=e.extend({init:function(t,r){t=this.words=t||[];if(r!=n){this.sigBytes=r}else{this.sigBytes=t.length*4}},toString:function(t){return(t||s).stringify(this)},concat:function(t){var r=this.words;var n=t.words;var i=this.sigBytes;var e=t.sigBytes;this.clamp();if(i%4){for(var a=0;a<e;a++){var s=n[a>>>2]>>>24-a%4*8&255;r[i+a>>>2]|=s<<24-(i+a)%4*8}}else{for(var a=0;a<e;a+=4){r[i+a>>>2]=n[a>>>2]}}this.sigBytes+=e;return this},clamp:function(){var t=this.words;var r=this.sigBytes;t[r>>>2]&=4294967295<<32-r%4*8;t.length=v.ceil(r/4)},clone:function(){var t=e.clone.call(this);t.words=this.words.slice(0);return t},random:function(t){var r=[];var n=function(r){var r=r;var n=987654321;var i=4294967295;return function(){n=36969*(n&65535)+(n>>16)&i;r=18e3*(r&65535)+(r>>16)&i;var t=(n<<16)+r&i;t/=4294967296;t+=.5;return t*(v.random()>.5?1:-1)}};for(var i=0,e;i<t;i+=4){var a=n((e||v.random())*4294967296);e=a()*987654071;r.push(a()*4294967296|0)}return new h.init(r,t)}});var a=t.enc={};var s=a.Hex={stringify:function(t){var r=t.words;var n=t.sigBytes;var i=[];for(var e=0;e<n;e++){var a=r[e>>>2]>>>24-e%4*8&255;i.push((a>>>4).toString(16));i.push((a&15).toString(16))}return i.join("")},parse:function(t){var r=t.length;var n=[];for(var i=0;i<r;i+=2){n[i>>>3]|=parseInt(t.substr(i,2),16)<<24-i%8*4}return new h.init(n,r/2)}};var o=a.Latin1={stringify:function(t){var r=t.words;var n=t.sigBytes;var i=[];for(var e=0;e<n;e++){var a=r[e>>>2]>>>24-e%4*8&255;i.push(String.fromCharCode(a))}return i.join("")},parse:function(t){var r=t.length;var n=[];for(var i=0;i<r;i++){n[i>>>2]|=(t.charCodeAt(i)&255)<<24-i%4*8}return new h.init(n,r)}};var f=a.Utf8={stringify:function(t){try{return decodeURIComponent(escape(o.stringify(t)))}catch(t){throw new Error("Malformed UTF-8 data")}},parse:function(t){return o.parse(unescape(encodeURIComponent(t)))}};var c=r.BufferedBlockAlgorithm=e.extend({reset:function(){this._data=new h.init;this._nDataBytes=0},_append:function(t){if(typeof t=="string"){t=f.parse(t)}this._data.concat(t);this._nDataBytes+=t.sigBytes},_process:function(t){var r=this._data;var n=r.words;var i=r.sigBytes;var e=this.blockSize;var a=e*4;var s=i/a;if(t){s=v.ceil(s)}else{s=v.max((s|0)-this._minBufferSize,0)}var o=s*e;var f=v.min(o*4,i);if(o){for(var c=0;c<o;c+=e){this._doProcessBlock(n,c)}var u=n.splice(0,o);r.sigBytes-=f}return new h.init(u,f)},clone:function(){var t=e.clone.call(this);t._data=this._data.clone();return t},_minBufferSize:0});var u=r.Hasher=c.extend({cfg:e.extend(),init:function(t){this.cfg=this.cfg.extend(t);this.reset()},reset:function(){c.reset.call(this);this._doReset()},update:function(t){this._append(t);this._process();return this},finalize:function(t){if(t){this._append(t)}var r=this._doFinalize();return r},blockSize:512/32,_createHelper:function(n){return function(t,r){return new n.init(r).finalize(t)}},_createHmacHelper:function(n){return function(t,r){return new p.HMAC.init(n,r).finalize(t)}}});var p=t.algo={};return t}(Math);return t});

(function(r,e){if(typeof exports==="object"){module.exports=exports=e(require("./core"))}else if(typeof define==="function"&&define.amd){define(["./core"],e)}else{e(r.CryptoJS)}})(this,function(i){(function(){var r=i;var e=r.lib;var f=e.WordArray;var a=r.enc;var t=a.Base64={stringify:function(r){var e=r.words;var a=r.sigBytes;var t=this._map;r.clamp();var i=[];for(var n=0;n<a;n+=3){var v=e[n>>>2]>>>24-n%4*8&255;var o=e[n+1>>>2]>>>24-(n+1)%4*8&255;var f=e[n+2>>>2]>>>24-(n+2)%4*8&255;var s=v<<16|o<<8|f;for(var c=0;c<4&&n+c*.75<a;c++){i.push(t.charAt(s>>>6*(3-c)&63))}}var h=t.charAt(64);if(h){while(i.length%4){i.push(h)}}return i.join("")},parse:function(r){var e=r.length;var a=this._map;var t=this._reverseMap;if(!t){t=this._reverseMap=[];for(var i=0;i<a.length;i++){t[a.charCodeAt(i)]=i}}var n=a.charAt(64);if(n){var v=r.indexOf(n);if(v!==-1){e=v}}return o(r,e,t)},_map:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="};function o(r,e,a){var t=[];var i=0;for(var n=0;n<e;n++){if(n%4){var v=a[r.charCodeAt(n-1)]<<n%4*2;var o=a[r.charCodeAt(n)]>>>6-n%4*2;t[i>>>2]|=(v|o)<<24-i%4*8;i++}}return f.create(t,i)}})();return i.enc.Base64});

//从右往左去空格
function rtrim(stringObj) {
    while (stringObj.charCodeAt(stringObj.length - 1) == 32) {
        stringObj = stringObj.substring(0, stringObj.length - 1);
    }
    return stringObj;
}

//从左往右去空格
function ltrim(stringObj) {
    while (stringObj.charCodeAt(0) == 32) {
        stringObj = stringObj.substring(1, stringObj.length);
    }
    return stringObj;
}

//去掉字符串左右两边的空格
function trim(stringObj) {
    return(ltrim(rtrim(stringObj)));
}

/*****************************************************
 *  函数名称：replaceChars;
 *  函数功能：替换字符串中的相应字符串;
 *******************************************************/
function replaceChars(entry, orgStr, replaceStr) {
    temp = "" + entry;
    while (temp.indexOf(orgStr) > -1) {
        pos = temp.indexOf(orgStr);
        temp = "" + (temp.substring(0, pos) + replaceStr + temp.substring((pos + orgStr.length), temp.length));
    }

    return temp;
}

function FilePathAddSufix(path, sufix) {

    var idx = path.lastIndexOf(".");
    if(idx != -1)
    {
        return path.substr(0, idx) + sufix + path.substr(idx);
    }
    else
    {
        return path + sufix;
    }
}

function InsertObjectNode(webCore, sObjName, sClassid) {
    if(webCore == 1)
    {
        document.writeln("<OBJECT id=\"" + sObjName + "\" classid=\"CLSID:" + sClassid + "\" style=\"display:none\"></OBJECT>");
    }else{
        document.writeln("<OBJECT id=\"" + sObjName + "\" TYPE=\"application/gdca-activex\" clsid=\"{" + sClassid + "}\" WIDTH=\"0\" HEIGHT=\"0\"></OBJECT>");
    }
}

function LoadComObj(sObjName, sClassid) {
    var browser = navigator.appName;

    //判断浏览器类型选择合适的ActiveX控件调用方式
    if (browser == "Microsoft Internet Explorer")  //IE浏览器
    {
        InsertObjectNode(1, sObjName, sClassid);
    }
    else if (browser == "Netscape")  //IE11, Chrome,Firefox浏览器
    {
        if (navigator.userAgent.search("Trident") != -1) //IE11
            InsertObjectNode(1, sObjName, sClassid);
        else
            InsertObjectNode(2, sObjName, sClassid);
    }
}

function setOpacity(obj, opacity) { 
	if (obj.style.opacity != undefined) { 
		obj.style.opacity = opacity;  ///兼容FF和GG和新版本IE 
	} else { 
		obj.style.filter = "alpha(opacity=" + opacity * 100 + ")";  ///兼容老版本ie 
	} 
}

var is_fading = false;

//淡入
function fadein(obj, interval, precision) {
	var num = 0;
    if (!is_fading) {
        var st = setInterval(function(){
            num++;
            is_fading = true;
            setOpacity(obj, num / precision);
            if (num >= precision) {
                clearInterval(st);
                is_fading = false;
            }
        }, interval);
    }
}

 //淡出
function fadeout(obj, interval, precision, cb_end) {
	var num = precision;
    if (!is_fading) {
        var st = setInterval(function(){
            num--;
            is_fading = true;
            setOpacity(obj, num / precision);
            if (num <= 0) {
                clearInterval(st);
                is_fading = false;
                cb_end();
            }
        }, interval);
    }
}

function OnFadoutEnd() {
	var notify_wrap=document.getElementById('notify_wrap');
	notify_wrap.style.display="none";
}

//弹出一个淡入淡出的提示框, stay为停留时间
function show_msg(text, stay) {
	var msg_wrap=document.getElementById('msg_wrap');
	var msg=document.getElementById('msg');
	var old_ie = false;

	if (navigator.appName == "Microsoft Internet Explorer")  //IE浏览器
	{
		old_ie = true;
	}

	msg_wrap.style.display="inline-block";
	msg.innerHTML=text;

	old_ie?fadein(msg, 30, 20):fadein(msg_wrap, 30, 20)
		
	setTimeout(function(){
		old_ie?fadeout(msg, 30, 20, OnFadoutEnd):fadeout(msg_wrap, 30, 20, OnFadoutEnd)
	}, stay);
}

function get_radio_val(radio_name) {
	var vals = document.getElementsByName(radio_name);  
    for(var i = 0;i < vals.length;i++)  {
        if(vals[i].checked==true) {
            return vals[i].value;  
        }  
    }
    return null;
}

function genRandString(len) {
	len = len || 32;
	var $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890';
	var maxPos = $chars.length;
	var s = '';
	
	for (i = 0; i < len; i++) {
		s += $chars.charAt(Math.floor(Math.random() * maxPos));
	}
	
	return s;
}

var split;


// Avoid running twice; that would break the `nativeSplit` reference

split = split || function (undef) {

    var nativeSplit = String.prototype.split,
        compliantExecNpcg = /()??/.exec("")[1] === undef, // NPCG: nonparticipating capturing group
        self;

    self = function (str, separator, limit) {
        // If `separator` is not a regex, use `nativeSplit`
        if (Object.prototype.toString.call(separator) !== "[object RegExp]") {
            return nativeSplit.call(str, separator, limit);
        }
        var output = [],
            flags = (separator.ignoreCase ? "i" : "") +
                    (separator.multiline ? "m" : "") +
                    (separator.extended ? "x" : "") + // Proposed for ES6
                    (separator.sticky ? "y" : ""), // Firefox 3+
            lastLastIndex = 0,
            // Make `global` and avoid `lastIndex` issues by working with a copy
            separator = new RegExp(separator.source, flags + "g"),
            separator2, match, lastIndex, lastLength;
        str += ""; // Type-convert
        if (!compliantExecNpcg) {
            // Doesn't need flags gy, but they don't hurt
            separator2 = new RegExp("^" + separator.source + "$(?!\\s)", flags);
        }
        /* Values for `limit`, per the spec:
         * If undefined: 4294967295 // Math.pow(2, 32) - 1
         * If 0, Infinity, or NaN: 0
         * If positive number: limit = Math.floor(limit); if (limit > 4294967295) limit -= 4294967296;
         * If negative number: 4294967296 - Math.floor(Math.abs(limit))
         * If other: Type-convert, then use the above rules
         */
        limit = limit === undef ?
            -1 >>> 0 : // Math.pow(2, 32) - 1
            limit >>> 0; // ToUint32(limit)
        while (match = separator.exec(str)) {
            // `separator.lastIndex` is not reliable cross-browser
            lastIndex = match.index + match[0].length;
            if (lastIndex > lastLastIndex) {
                output.push(str.slice(lastLastIndex, match.index));
                // Fix browsers whose `exec` methods don't consistently return `undefined` for
                // nonparticipating capturing groups
                if (!compliantExecNpcg && match.length > 1) {
                    match[0].replace(separator2, function () {
                        for (var i = 1; i < arguments.length - 2; i++) {
                            if (arguments[i] === undef) {
                                match[i] = undef;
                            }
                        }
                    });
                }
                if (match.length > 1 && match.index < str.length) {
                    Array.prototype.push.apply(output, match.slice(1));
                }
                lastLength = match[0].length;
                lastLastIndex = lastIndex;
                if (output.length >= limit) {
                    break;
                }
            }
            if (separator.lastIndex === match.index) {
                separator.lastIndex++; // Avoid an infinite loop
            }
        }
        if (lastLastIndex === str.length) {
            if (lastLength || !separator.test("")) {
                output.push("");
            }
        } else {
            output.push(str.slice(lastLastIndex));
        }
        return output.length > limit ? output.slice(0, limit) : output;
    };

    // For convenience
    String.prototype.split = function (separator, limit) {
        return self(this, separator, limit);
    };

    return self;
}();

var CryptoJSUtil = 
{
	base64Encode: function(val){
	    var src = CryptoJS.enc.Utf8.parse(val);
		return CryptoJS.enc.Base64.stringify(src).toString();
	},
	base64Decode: function(val){
	    var wa = CryptoJS.enc.Base64.parse(val);
		return CryptoJS.enc.Utf8.stringify(wa);
	}
}

//判断插件名称是否存在
function hasPlugin(name) {
    name = name.toLowerCase();
    for (var i = 0; i < navigator.plugins.length; i++) {
        if (navigator.plugins[i].name.toLowerCase().indexOf(name) > -1) {
            return true;
        }
    }
    return false;
}

//判断操作系统
function check_os() {
    if (navigator.userAgent.indexOf("Windows", 0) != -1)
    	return os_type_t.windows;
    else if (navigator.userAgent.indexOf("Linux", 0) != -1)
    	return os_type_t.linux;
    else if (navigator.userAgent.indexOf("mac", 0) != -1)
    	return os_type_t.mac;
    else if (navigator.userAgent.indexOf("X11", 0) != -1)
    	return os_type_t.unix;
	else
		return os_type_t.unknow;
}

/****************************************************************************************
* 函数名称：getCookie
* 函数功能：客户端从cookie中得到服务方的信息
* 输入参数：name    cookie中标识名
* 输出参数：rvalue  得到标识名对应的值
*****************************************************************************************/
function getCookie(name)
{
	var cookies = document.cookie;
	var start = -1;
	var end = -1;
	var rvalue = null;

	if(cookies.length>0)
	{
	     start = cookies.indexOf(name);
	     if(start!=-1)
	     {
	          start += name.length+1;
	          end = cookies.indexOf(";",start);
	          if(end ==-1)
	          {
	              end = cookies.length;
	          }
	          rvalue = cookies.substring(start,end);
	     }
	}

	rvalue=replaceChars(rvalue,"%0D","\r");
	rvalue=replaceChars(rvalue,"%0A","\n");
	rvalue=replaceChars(rvalue,"%2F","/");
	rvalue=replaceChars(rvalue,"%2B","+");
	rvalue=replaceChars(rvalue,"%3D","=");
	return rvalue;
 }

function isIE() {
    return ("ActiveXObject" in window);
}

function getIEVersion() 
{
    var userAgent = navigator.userAgent; //取得浏览器的userAgent字符串  
    var isIE = userAgent.indexOf("compatible") > -1 && userAgent.indexOf("MSIE") > -1; //判断是否IE<11浏览器  
    var isEdge = userAgent.indexOf("Edge") > -1 && !isIE; //判断是否IE的Edge浏览器  
    var isIE11 = userAgent.indexOf('Trident') > -1 && userAgent.indexOf("rv:11.0") > -1;
    if(isIE) {
        var reIE = new RegExp("MSIE (\\d+\\.\\d+);");
        reIE.test(userAgent);
        var fIEVersion = parseFloat(RegExp["$1"]);
        if(fIEVersion == 7) {
            return 7;
        } else if(fIEVersion == 8) {
            return 8;
        } else if(fIEVersion == 9) {
            return 9;
        } else if(fIEVersion == 10) {
            return 10;
        } else {
            return 6;//IE版本<=7
        }   
    } else if(isEdge) {
        return 'edge';//edge
    } else if(isIE11) {
        return 11; //IE11  
    }else{
        return -1;//不是ie浏览器
    }
}

/*
 * 版本号比较方法
 * 传入两个字符串，当前版本号：curV；比较版本号：reqV
 * 当前版本号大于等于比较版本号返回true
 * 调用方法举例：compare("1.1","1.2")，将返回false
 */
function xs_compare_ver(curV, reqV){
  //将两个版本号拆成数字
  var arr1 = curV.split('.');
  var arr2 = reqV.split('.');
  
  var minLength=Math.min(arr1.length, arr2.length);
  var position=0;
  var diff=0;
  
  //依次比较版本号每一位大小，当对比得出结果后跳出循环
  while(position<minLength && ((diff=parseInt(arr1[position])-parseInt(arr2[position]))==0)){
      position++;
  }
  
  diff=(diff!=0)?diff:(arr1.length-arr2.length);

  return diff >= 0;
}

function get_str_len(val, cn)
{
    var len = 0;
    
	for(i = 0; i < val.length; i++) 
	{ 
		if(val.charCodeAt(i) > 128)
			len += cn;
		else
			len++;
	}

	return len;
}

function trimOIDVal(val) {
	if(val.substr(0, 2) == '..') return val.substr(2);
	return val;
}

function onBtnEvent(obj, evt) {
    var img = 'x_normal';

    if(evt == 1)
        img = 'x_hover';
    else if(evt == 3)
        img = 'x_press';
    else if(evt == 4)
        img = 'x_hover';
    else if(evt == 5){
        var notify_wrap = document.getElementById('notify_wrap');
        notify_wrap.style.display="none";
    }

    obj.style.background = 'url("./img/' + img + '.png") no-repeat';
}

function NotifyBar() {
	var _notify_wrap = null;
	var _notify = null;
	var _icons = ['loading.gif','warning.png','error.png','ok.png'];
	var _isOldIE = false;

	this.init = function() {
    	_notify_wrap = document.getElementById('notify_wrap');
    	_notify = document.getElementById('notify');

    	if (navigator.appName == "Microsoft Internet Explorer")
    		_isOldIE = true;
	};
	
	this.show = function(stay) {
    	_notify_wrap.style.display="inline-block";

        if(stay != undefined){
        	setTimeout(function(){
        		_isOldIE?fadeout(_notify_wrap, 30, 20, OnFadoutEnd):fadeout(_notify_wrap, 30, 20, OnFadoutEnd)
        	}, stay);
        }
	};
	
	this.hide = function() {
    	_notify_wrap.style.display="none";
	};

	this.setText = function(text, icon, stay) {
	    _notify.innerHTML = '<img align="absmiddle" src="img/' + _icons[icon] +'" />' + text + 
	    '<input type="button" class="img_btn" value="" onmouseenter="onBtnEvent(this, 1)" onmouseleave="onBtnEvent(this, 2)" onmousedown="onBtnEvent(this, 3)" onmouseup="onBtnEvent(this, 4)" onclick="onBtnEvent(this, 5)"/>';
	    this.show(stay);
	};
}

function isGDCADevice(devType)
{
    if( (devType >= 10 && devType < 40) || (devType >= 50 && devType < 300))
        return true;
    else
        return false;
}

function getBrowserInfo() {
    let userAgent = navigator.userAgent;
    let name = '';
    let version = '';

    // 尝试匹配常见的浏览器名称和版本
    if (/MSIE|Trident/.test(userAgent)) {
        // 匹配旧版IE浏览器
        let matches = /MSIE\s(\d+\.\d+)/.exec(userAgent) || /rv:(\d+\.\d+)/.exec(userAgent);
        if (matches) {
            name = 'IE';
            version = matches[1];
        }
    } else if (/Edge/.test(userAgent)) {
        // 匹配Edge浏览器
        let matches = /Edge\/(\d+\.\d+)/.exec(userAgent);
        if (matches) {
            name = 'Edge';
            version = matches[1];
        }
    } else if (/Chrome/.test(userAgent) && /Google Inc/.test(navigator.vendor)) {
        // 匹配Chrome浏览器
        let matches = /Chrome\/(\d+\.\d+)/.exec(userAgent);
        if (matches) {
            name = 'Chrome';
            version = matches[1];
        }
    } else if (/Firefox/.test(userAgent)) {
        // 匹配Firefox浏览器
        let matches = /Firefox\/(\d+\.\d+)/.exec(userAgent);
        if (matches) {
            name = 'Firefox';
            version = matches[1];
        }
    } else if (/Safari/.test(userAgent) && /Apple Computer/.test(navigator.vendor)) {
        // 匹配Safari浏览器
        let matches = /Version\/(\d+\.\d+)([^S]*)(Safari)/.exec(userAgent);
        if (matches) {
            name = 'Safari';
            version = matches[1];
        }
    }

    return {
        name: name,
        version: version
    };
}

function isFirefox() {
    return /Firefox/.test(window.navigator.userAgent);
}

const caInfoMap = new Map();

function initCAInfo()
{
    caInfoMap.set('77430910f7158b3ab011d24c7b079404f0145446', CA_GDCA);
    caInfoMap.set('954d131f6b2191096f16128a65bc0b560b116bc8', CA_GDCA);
    caInfoMap.set('118fe3fd39191d9c191f49376eac448c55ea14bd', CA_GDCA);
    caInfoMap.set('09c8f757029d342d4456e1183794fa0a5e8523f2', CA_GDCA);
    caInfoMap.set('843ec005adc2244bc98f609cdc3320ba0ca3b682', CA_GDCA);
    caInfoMap.set('3bb9bc1edbbbcfb8323b1ce928cec50282acab6b', CA_GDCA);
    caInfoMap.set('87464e2c6a08cb9cfd2d24785c8855c8ecee37f1', CA_GDCA);
    caInfoMap.set('fa8ba174fa46d4db6f194b15ec364be4409016d3', CA_GDCA);
    caInfoMap.set('03d160600c0dec7ee49dae7e25fff23c723da79e', CA_GDCA);
}

//根据密钥标识符判断CA类型
function getCAByKeyId(keyId) {
    if(caInfoMap.has(keyId))
        return caInfoMap.get(keyId);
    else
        return CA_UNKNOW;
}