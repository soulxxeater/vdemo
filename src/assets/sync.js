var gsSelectUser = '';
var gsSelectContainer = '';
var gUserList = [];
var gIsLogin = false;
var gIsScan = false;
var t1;
var t2;
var g_api_ver = '';
var g_timer_get_ver = '';
var g_enum_flags = 0;
var notifyBar = new NotifyBar();

function clearForm() {
    mainForm.dev_info.value = "";
    mainForm.sign_cert.value = "";
    mainForm.enc_cert.value = "";
    mainForm.CertInfo.value = "";
    mainForm.CertInfo2.value = "";
    mainForm.SignMsgInfo.value = "";
    mainForm.SignedData.value = "";
    mainForm.signed_msg.value = "";
    mainForm.EncryptedData.value = "";
    mainForm.DecryptedData.value = "";
    mainForm.RandomData.value = "";
    mainForm.xml_signed.value = "";
    mainForm.xml_sign_info.value = "";
}

function OnEncryptPlainDataChannged(obj) {
	$('#enc_pdata_len').html(String(obj.value.length));
}

function UpdateProtocol() {
	var proto = parseInt(get_radio_val("http_protocol"));
	gPKISvc.setProtocol(proto);

	g_login = false;
}

function parse_trustid(trustid) {
	if(trustid.substr(0, 2) == '..') return trustid.substr(2);
	return trustid;
}

function ClearListBox(obj_id) {
	$('#'+obj_id).html('');
}

window.onload=function(){
	mainForm.api_version.value = "";

	clearForm();

	mainForm.xml_sign_plain.value = '' + 
'<?xml version="1.0" encoding="utf-8"?>\n' +
'<info title="title">\n' +
'   <intro>信息</intro>\n' +
'    <list id="001">\n' +
'     <head>auto_userone</head>\n' +
'     <name>Jordy</name>\n' +
'     <number>12345678</number>\n' +
'     <age>20</age>\n' +
'     <sex>Man</sex>\n' +
'     <hobby>看电影</hobby>\n' +
'    </list>\n' +
'</info>';

    notifyBar.init();
    notifyBar.setText('正在初始化通讯· · · · · · ', 0);

    window.setTimeout(function (){
        var retCode = gPKISvc.Initialize(PROTO_AUTO);
        if(retCode == SOR_OK){
            notifyBar.setText('通讯初始化成功', 3, 1200);
        }else{
            notifyBar.setText('通讯初始化失败', 2);
        }
    }, 100);
};

window.onbeforeunload = function(){
}  

window.onunload = function(){  
}  


function ShowError(e)
{
    if(e.ErrorMsg != undefined){
        alert("\n错误信息：" + e.ErrorMsg + "\n错误代码：0x" + e.ErrorCode.toString(16).toUpperCase() + " (" + gPKISvc.SOF_GetErrMsg(e.ErrorCode) + ")");
    }
    else
        alert("Exception:\n" + e.ErrorMsg);
}

function ReSetData()
{
    gsSelectUser = "";
    gsSelectContainer = "";
}

function OnCertTypeChange()
{
    mainForm.CertData.value = "";
}

function OnUserSelected()
{
    ReSetData();
    clearForm();

    var Index = mainForm.UserList.options.selectedIndex;

    var sUser = gUserList[Index];

    var UserInfo = sUser.split("||");
    
    gsSelectUser = UserInfo[0];
    gsSelectContainer = UserInfo[1];

	gIsScan = gsSelectContainer == 'SCAN_CONTAINER';
}

function OnEncFileChanged() {
    var sPath = document.getElementById('EncInFilePath').value;
    document.getElementById('EncOutFilePath').value = FilePathAddSufix(sPath, "_encrypted");
}

function OnDecFileChanged() {
    var sPath = document.getElementById('DecInFilePath').value;
    document.getElementById('DecOutFilePath').value = FilePathAddSufix(sPath, "_decrypted");
}

function OnExtEncFileChanged() {
    var sPath = document.getElementById('ExtEncInFilePath').value;
    document.getElementById('ExtEncOutFilePath').value = FilePathAddSufix(sPath, "_encrypted");
}

function OnExtDecFileChanged() {
    var sPath = document.getElementById('ExtDecInFilePath').value;
    document.getElementById('ExtDecOutFilePath').value = FilePathAddSufix(sPath, "_decrypted");
}

function CheckCert(cert_type)
{
    if(cert_type == CERT_TYPE_SIGN && mainForm.sign_cert.value == '')
    {
        alert("签名证书为空！");
        return false;
    }
    else if(cert_type == CERT_TYPE_EXCHANGE && mainForm.enc_cert.value == '')
    {
        alert("加密证书为空！");
        return false;
    }

    return true;
}

function CheckUser()
{
    if(gsSelectContainer == '')
    {
        alert("请先枚举证书！");
        return false;
    }

    return true;
}

function CheckLogin()
{
	if(gIsScan) return true;
	
    if(!gIsLogin)
    {
        alert("请先登录！");
        return false;
    }

    return true;
}

function CheckScan()
{
    if(gIsScan){
	    alert("本功能不支持一扫签！");
	    return false;
    }

    return true;
}

function UpdateSetSupportDevFlags()
{
	var dev_online = document.getElementById('dev_online');
	g_enum_flags = DEV_GDCA_CSP;

	if(dev_online.checked)
		g_enum_flags |= DEV_ONLINE;
	else
		g_enum_flags |= DEV_ONLINE_GDCA;
}

function SupportDeviceClick()
{
	UpdateSetSupportDevFlags();

	gPKISvc.SOF_Config(SOF_SET_SUPPORT_DEVICE_EX, g_enum_flags);
}

function EnumPFXClick()
{
    var enum_pfx = document.getElementById('enum_pfx');
    
    gPKISvc.SOF_Config(SOF_SET_ENUM_MICROSOFT_PFX, enum_pfx.checked?1:0);
}

//1.获取接口版本号
function Test_GetVersion()
{
	mainForm.api_version.value = '';
	
	t1 = new Date().getTime();
    var res = gPKISvc.SOF_GetVersion();
	t2 = new Date().getTime();
	
	mainForm.elapse1.value = t2 - t1;
	
	if(res.ErrorCode == SOR_OK){
		mainForm.api_version.value = res.Result.Version;
		g_api_ver = res.Result.Version;
	}else
		ShowError(res);
}

//2.获取产品版本号
function Test_GetProductVersion()
{
	var product_type = parseInt(mainForm.product_type.value);	
	mainForm.product_version.value = '';
	
	t1 = new Date().getTime();
    var res = gPKISvc.SOF_Ext_GetProductVersion(product_type);   
	t2 = new Date().getTime();
	
	mainForm.elapse2.value = t2 - t1;

	if(res.ErrorCode == SOR_OK){
		mainForm.product_version.value = res.Result.Version;
	}else{
		ShowError(res);
	}
}

//3.设置多CA兼容设备
function Test_ConfigSupportDevice()
{
	var dev_flags = parseInt(mainForm.dev_flags.value);

	t1 = new Date().getTime();
	var res = gPKISvc.SOF_Config(SOF_SET_SUPPORT_DEVICE_EX, dev_flags);
	t2 = new Date().getTime();
	
	mainForm.elapse7.value = t2 - t1;

	if(res.ErrorCode == SOR_OK){
		alert("设置成功");
	}else{
		ShowError(res);
	}
}

function Test_Config()
{
	var set_type = parseInt(document.getElementById('set_type').value);
	var set_val = document.getElementById('set_val').value;
	var set_data_type = parseInt(document.getElementById('set_data_type').value);

	if(set_data_type == 1)
		set_val = parseInt(set_val);

	t1 = new Date().getTime();
	var res = gPKISvc.SOF_Config(set_type, set_val);
	t2 = new Date().getTime();
	
	mainForm.elapse4.value = t2 - t1;

	if(res.ErrorCode == SOR_OK){
		alert("设置成功");
	}else{
		ShowError(res);
	}
}

//4.设置数据输入格式
function SetInDataFormat()
{
	var indata_format = parseInt(document.getElementById('indata_format').value);

	t1 = new Date().getTime();
	var res = gPKISvc.SOF_Config(SOF_SET_INDATA_FORMAT, indata_format);
	t2 = new Date().getTime();
	
	mainForm.elapse4.value = t2 - t1;

	if(parseInt(res.ErrorCode,16) == SOR_OK){
		alert("设置成功");
	}else{
		ShowError(res);
	}
}

//设置服务响应超时
function Test_ConfigServerTimeout()
{
	var set_times = parseInt(document.getElementById('server_timeout').value);

	t1 = new Date().getTime();
	var res = gPKISvc.SOF_Config(SOF_SET_HTTP_TIMEOUT, set_times);
	t2 = new Date().getTime();
	
	mainForm.elapse4.value = t2 - t1;

	if(parseInt(res.ErrorCode,16) == SOR_OK){
		alert("设置成功");
	}else{
		ShowError(res);
	}
}

//5.枚举设备
function Test_EnumDevice()
{
	mainForm.enum_dev.value = '';

	t1 = new Date().getTime();
    var res = gPKISvc.SOF_Ext_EnumDevice();
	t2 = new Date().getTime();
	
	mainForm.elapse5.value = t2 - t1;

	if(res.ErrorCode == SOR_OK){
		mainForm.enum_dev.value = res.Result.DeviceInfo;
		var devTypeList = JSON.parse(res.Result.DeviceInfo);
		if(devTypeList.length == 0){
			alert("没有检测到UKey！");
		}
	}else{
		ShowError(res);
	}
}

//6.获取设备类型
function Test_GetDeviceType()
{
	mainForm.dev_type.value = '';
	
	t1 = new Date().getTime();
	var res = gPKISvc.SOF_Ext_GetDeviceType();
	t2 = new Date().getTime();
	
	mainForm.elapse6.value = t2 - t1;

	if(res.ErrorCode == SOR_OK){
		mainForm.dev_type.value = res.Result.devType;
	}else{
		ShowError(res);
	}
}

//7.枚举证书
function Test_EnumCert(obj)
{
	document.getElementById("UserList").options.length = 0; 

	t1 = new Date().getTime();
	var res = gPKISvc.SOF_GetUserList();
	t2 = new Date().getTime();
	
	mainForm.elapse7.value = t2 - t1;
	
	if(res.ErrorCode == SOR_OK && res.Status == 1){
		gUserList =	res.Result;
		
		for (i = 0; i < res.Result.length; i++)
            mainForm.UserList.options.add(new Option(res.Result[i]), i);
	
		mainForm.UserList.options[0].selected=true;		
		OnUserSelected();
	}else{
		if(res.ErrorCode == SOR_OK && res.Status == 0)
			alert("找不到证书！");
		else
			ShowError(res);
	}
}

//8.获取设备信息
function Test_GetDeviceInfo()
{
	document.getElementById('dev_info').value = '';	
	
	var devInfoType = parseInt(mainForm.DevInfoType.value, 16);
	
	t1 = new Date().getTime();
	var res = gPKISvc.SOF_GetDeviceInfo(gsSelectContainer,devInfoType);
	t2 = new Date().getTime();
	
	mainForm.elapse8.value = t2 - t1;
	
	if(res.ErrorCode == SOR_OK){
		mainForm.dev_info.value = res.Result.DeviceInfo;
	}else{
		mainForm.dev_info.value = "";
		if(res.ErrorCode == SOR_NotSupportYetErr)
			alert("设备不支持此属性！");
		else
			ShowError(res);
	}
}

//9.用户登录
function Test_Login()
{
    if(!CheckScan()) return;
       
    if(!CheckUser())
       return;
       
    var sPassword = mainForm.password.value;
    if(sPassword == "")
    {
        alert("请输入密码!");
        return;
    }
        
	t1 = new Date().getTime();
	var res = gPKISvc.SOF_Login(gsSelectContainer, sPassword);
	t2 = new Date().getTime();
	
	mainForm.elapse9.value = t2 - t1;

	if(res.ErrorCode == SOR_OK){
		alert("登录成功");
		gIsLogin = true;
	}else{
		ShowError(res);
	}
}

//10.判断是否登陆
function Test_IsLogin()
{
	if(!CheckScan()) return;
       
    if(!CheckUser())
       return;
       
	t1 = new Date().getTime();
	var res =gPKISvc.SOF_Ext_isLogin(gsSelectContainer, 1);
	t2 = new Date().getTime();
	
	mainForm.elapse10.value = t2 - t1;

	if(res.ErrorCode == SOR_OK){
		alert("已登录");
	}else if(res.ErrorCode == SOR_NotLoginErr)
		alert("未登录");
	else
		ShowError(res);
}

//11.获取口令剩余重试次数	
function Test_GetPinRetryCount()
{
	mainForm.PinRetryCount.value = '';
	
	if(!CheckScan()) return;
	
    if(!CheckUser())
        return;

	t1 = new Date().getTime();
	var res = gPKISvc.SOF_GetPinRetryCount(gsSelectContainer);
	t2 = new Date().getTime();
	
	mainForm.elapse11.value = t2 - t1;

	if(res.ErrorCode == SOR_OK){
		mainForm.PinRetryCount.value = res.Result.RetryCount;
	}else{
		ShowError(res);
	}
}

//12.退出登录
function Test_Ext_Logout()
{
	if(!CheckScan()) return;
       
    if(!CheckUser())
       return;
       
	t1 = new Date().getTime();
	var res = gPKISvc.SOF_Ext_Logout(gsSelectContainer, 1);
	t2 = new Date().getTime();
	
	mainForm.elapse12.value = t2 - t1;

	 if(res.ErrorCode == SOR_OK){
		alert("登出成功");
		gIsLogin = false;
	}else{
		ShowError(res);
	}
}

//13.修改密码
function Test_ChangePassWd()
{
	if(!CheckScan()) return;
	
    if(!CheckUser())
        return;
        
    var oldpin = mainForm.OldPassword.value;
    var newpin = mainForm.NewPassword.value;
    if(oldpin == "" || newpin == "")
    {
        alert("请输入完整!");
        return;
    }
        
	t1 = new Date().getTime();
	var res = gPKISvc.SOF_ChangePassWd(gsSelectContainer,oldpin,newpin);
	t2 = new Date().getTime();
	mainForm.elapse13.value = t2 - t1;

	if(res.ErrorCode == SOR_OK){
		alert("修改密码成功");
	}else{
		ShowError(res);
	}
}

//14.读取证书
function Test_ReadUserCert(certType)
{
    if(!CheckUser())
        return;
        
    var cert_type = parseInt(certType);
	var sContainer = gsSelectContainer;
	
	t1 = new Date().getTime();

	if(cert_type == 1){
		mainForm.sign_cert.value = '';
		var res = gPKISvc.SOF_ExportUserCert(sContainer);
		if(res.ErrorCode == SOR_OK){
		    t2 = new Date().getTime();
		    mainForm.sign_cert.value = res.Result.UserCert;
		    mainForm.elapse14_1.value = t2 - t1;
		}else{
			ShowError(res);
		}
	}
	else{
		mainForm.enc_cert.value = '';
		var res = gPKISvc.SOF_ExportExChangeUserCert(sContainer);
		if(res.ErrorCode == SOR_OK){
			t2 = new Date().getTime();
			mainForm.enc_cert.value = res.Result.UserCert;
			mainForm.elapse14_2.value = t2 - t1;
		}else{
			ShowError(res);
		}
	}	
}

//15.解析证书信息
var g_info = '';
var g_info_count = 0;
var g_time = 0;

function GetCertInfo(title, usercert, info_type, obj) {

	$('textarea[id="CertInfo"]').val('');

	t1 = new Date().getTime();
	var res = gPKISvc.SOF_GetCertInfo(usercert, info_type);
	t2 = new Date().getTime();
	g_time += t2 - t1;	
	g_info_count++;

	if(res.ErrorCode == SOR_OK){
		g_info += title + res.Result.Info + '\n';
	}else{
		g_info += title + " " + '\n';
	}
		
	if(g_info_count == 26){
		g_info_count = 0;
		$('textarea[id="CertInfo"]').val(g_info);
		mainForm.elapse15.value = g_time;
		g_time = 0;
		g_info = '';
		obj.disabled=false;
	}
}

//15.解析证书信息
function Test_GetCertInfo(obj)
{
    var info_type = parseInt(mainForm.CertInfoType.value, 16);
	var cert_type = parseInt(mainForm.CertType1.value);
	var usercert = '';

	$('textarea[id="CertInfo"]').val('');
	
    if(!CheckCert(cert_type))
        return;

	obj.disabled=true;

	usercert = (cert_type == CERT_TYPE_SIGN)?mainForm.sign_cert.value:mainForm.enc_cert.value;
    
	if(info_type == 0){
        GetCertInfo('证书版本: ', usercert, SGD_CERT_VERISON, obj);
        GetCertInfo('证书序列号: ', usercert, SGD_CERT_SERIAL, obj);
        GetCertInfo('签名算法: ', usercert, SGD_CERT_SIGNALG, obj);
		GetCertInfo('证书颁发者信息: ', usercert, SGD_CERT_ISSUER, obj);
		GetCertInfo('证书有效期: ', usercert, SGD_CERT_VALID_TIME, obj);
		GetCertInfo('证书拥有者信息: ', usercert, SGD_CERT_SUBJECT, obj);
		GetCertInfo('证书公钥信息: ', usercert, SGD_CERT_DER_PUBLIC_KEY, obj);
		GetCertInfo('证书扩展项信息: ', usercert, SGD_CERT_DER_EXTENSIONS, obj);
		GetCertInfo('颁发者密钥标识符: ', usercert, SGD_EXT_AUTHORITYKEYIDENTIFIER_INFO, obj);
		GetCertInfo('证书持有者密钥标识符: ', usercert, SGD_EXT_SUBJECTKEYIDENTIFIER_INFO, obj);
		GetCertInfo('密钥用途: ', usercert, SGD_EXT_KEYUSAGE_INFO, obj);
		GetCertInfo('私钥有效期: ', usercert, SGD_EXT_PRIVATEKEYUSAGEPERIOD_INFO, obj);
		GetCertInfo('证书策略: ', usercert, SGD_EXT_CERTIFICATEPOLICIES_INFO, obj);
		GetCertInfo('策略映射: ', usercert, SGD_EXT_POLICYMAPPINGS_INFO, obj);
		GetCertInfo('基本限制: ', usercert, SGD_EXT_BASICCONSTRAINTS_INFO, obj);
		GetCertInfo('策略限制: ', usercert, SGD_EXT_POLICYCONTRAINTS_INFO, obj);
		GetCertInfo('扩展密钥用途: ', usercert, SGD_EXT_EXTKEYUSAGE_INFO, obj);
		GetCertInfo('CRL发布点: ', usercert, SGD_EXT_CRLDISTRIBUTIONPOINTS_INFO, obj);
		GetCertInfo('Netscape属性: ', usercert, SGD_EXT_NETSCAPE_CERT_TYPE_INFO, obj);
		GetCertInfo('证书颁发者CN: ', usercert, SGD_CERT_ISSUER_CN, obj);
		GetCertInfo('证书颁发者O: ', usercert, SGD_CERT_ISSUER_O, obj);
		GetCertInfo('证书颁发者OU: ', usercert, SGD_CERT_ISSUER_OU, obj);
		GetCertInfo('证书拥有者信息CN: ', usercert, SGD_CERT_SUBJECT_CN, obj);
		GetCertInfo('证书拥有者信息O: ', usercert, SGD_CERT_SUBJECT_O, obj);
		GetCertInfo('证书拥有者信息OU: ', usercert, SGD_CERT_SUBJECT_OU, obj);
		GetCertInfo('证书拥有者信息EMAIL: ', usercert, SGD_CERT_SUBJECT_EMAIL, obj);

	}else{
		t1 = new Date().getTime();
		var res = gPKISvc.SOF_GetCertInfo(usercert, info_type);
		t2 = new Date().getTime();
		
		mainForm.elapse15.value = t2 - t1;
		
		obj.disabled = false;

		if(res.ErrorCode == SOR_OK){
			if(info_type == SGD_CERT_ISSUER 
			|| info_type == SGD_CERT_SUBJECT
			|| info_type == SGD_CERT_ISSUER_CN
			|| info_type == SGD_CERT_ISSUER_O
			|| info_type == SGD_CERT_ISSUER_OU
			|| info_type == SGD_CERT_SUBJECT_O
			|| info_type == SGD_CERT_SUBJECT_OU
			|| info_type == SGD_CERT_SUBJECT_CN
			|| info_type == SGD_CERT_SUBJECT_EMAIL
			|| info_type == SGD_CERT_DER_PUBLIC_KEY
			|| info_type == SGD_CERT_DER_EXTENSIONS){
				$('#CertInfo').val(res.Result.Info);
			}else{
				$('#CertInfo').val(gPKISvc.base64Decode(res.Result.Info));
			}
		}else{
			$('#CertInfo').val("");
			ShowError(res);
		}
	}
}

//16.解析证书信息（OID）
function Test_GetCertInfoByOid()
{
    var oid_name = mainForm.OIDNameSel.value;
	var cert_type = parseInt(mainForm.CertType2.value);
	var usercert = '';

	mainForm.CertInfo2.value = '';
	
    if(!CheckCert(cert_type))
        return;

	usercert = (cert_type == CERT_TYPE_SIGN)?mainForm.sign_cert.value:mainForm.enc_cert.value;

    if(oid_name == "0"){
        if(mainForm.OID.value == '')
        {
            alert("请填写OID");
            return;
        }
        oid_name = mainForm.OID.value;
    }

	t1 = new Date().getTime();	
	var res = gPKISvc.SOF_GetCertInfoByOid(usercert, oid_name);
		
	if(res.ErrorCode == SOR_OK){
		var info = gPKISvc.base64Decode(res.Result.Info);
		
		if(oid_name == '1.2.86.21.1.3')
			res = parse_trustid(info);
		mainForm.CertInfo2.value = info;
	}else{
		mainForm.CertInfo2.value = "";
		ShowError(res);
	}

	t2 = new Date().getTime();
	mainForm.elapse16.value = t2 - t1;
}

//17.证书验证
function Test_ValidateCert()
{
	var cert_type = parseInt(mainForm.CertType3.value);
	var usercert = '';

    if(!CheckCert(cert_type))
        return;
        
	usercert = (cert_type == CERT_TYPE_SIGN)?mainForm.sign_cert.value:mainForm.enc_cert.value;
	
	t1 = new Date().getTime();
	
	var res = gPKISvc.SOF_ValidateCert(usercert);
	t2 = new Date().getTime();
	mainForm.elapse17.value = t2 - t1;
	
	if(res.ErrorCode == SOR_OK){
			alert("证书验证通过");
	}else{
		switch (res.ErrorCode) 
		{
		case SOF_CERT_NOT_TRUSTED:
			alert("证书验证失败：证书不被信任！");
			break;
			
		case SOF_CERT_HASEXPIRED:
			alert("证书验证失败：证书已过有效期！");
			break;
			
		case SOF_CERT_REVOKED:
			alert("证书验证失败：证书已被吊销！");
			break;
			
		case SOF_CERT_FROZEN:
			alert("证书验证失败：证书已被冻结！");
			break;
			
		case SOF_CERT_NOTYETVALID:
			alert("证书验证失败：证书未生效！");
			break;
			
		case SOF_CERT_OTHER_ERR:
			alert("证书验证失败！");
			break;
			
		default:
			alert("证书验证失败(0x" + res.ErrorCode.toString(16).toUpperCase() + ")！");
			break;
		}
	}
}

//18.P1签名验签
function Test_Sign()
{
	mainForm.SignedData.value = '';
	
    if(!CheckUser())
        return;

	var sSignPlainData = mainForm.SignPlainData.value;
	
	t1 = new Date().getTime();
	var res =gPKISvc.SOF_SignData(gsSelectContainer, sSignPlainData);
	t2 = new Date().getTime();
	mainForm.elapse18_1.value = t2 - t1;

	var errCode = res.ErrorCode;
	if(errCode == SOR_OK){
		mainForm.SignedData.value = res.Result.Sign;
		alert("P1签名成功!");
	}else{
			//此处错误码判断，需要4.1.7以上版本
		if(errCode == SOR_RsaEncErr || errCode == SOR_ECCEncErr)
			alert("P1签名失败，请确认是否登录!");
		else if(errCode == SOF_CERT_HASEXPIRED)
			alert("P1签名失败，证书已过期!");
		else if(errCode == SOF_CERT_REVOKED)
			alert("P1签名失败，证书已被吊销!");
		else if(errCode == SOF_CERT_NOT_TRUSTED)
			alert("P1签名失败，证书不被信任!");
		else if(errCode == SOR_IndataErr)
			alert("P1签名失败：原文不是Base64格式!");
		else
			ShowError(res);
	}
}

//18.P1签名验签
function Test_Verify()
{
    var sign_cert = mainForm.sign_cert.value;
    var sSignPlainData = mainForm.SignPlainData.value;
    var sSignedDataB64 = mainForm.SignedData.value;
    
	if(sign_cert.length == 0 || sign_cert == null){
		alert("签名证书为空");
		return;
	}
	
	t1 = new Date().getTime();
	var res = gPKISvc.SOF_VerifySignedData(sign_cert, sSignPlainData, sSignedDataB64);
	t2 = new Date().getTime();
	mainForm.elapse18_2.value = t2 - t1;

	if(res.ErrorCode == SOR_OK){
		alert("P1验签成功");
	}else{
		ShowError(res);
	}
}

//20.P1文件验签
function Test_PKCS1_File_Sign()
{
	mainForm.FileSignedValue.value = '';
    if(!CheckUser())
       return;

	var sInFilePath = mainForm.SignInFilePath.value;

	t1 = new Date().getTime();


	var res =gPKISvc.SOF_SignFile(gsSelectContainer, sInFilePath);
	t2 = new Date().getTime();		
	mainForm.elapse20_1.value = t2 - t1;

	if(res.ErrorCode == SOR_OK){
		mainForm.FileSignedValue.value = res.Result.Sign;
		alert("P1文件签名成功");
	}else{
		//此处错误码判断，需要4.1.7以上版本
		if(res.ErrorCode == SOR_RsaEncErr || res.ErrorCode == SOR_ECCEncErr)
			alert("P1文件签名失败，请确认是否登录!");
		else if(res.ErrorCode == SOF_CERT_HASEXPIRED)
			alert("P1文件签名失败，证书已过期!");
		else if(res.ErrorCode == SOF_CERT_REVOKED)
			alert("P1文件签名失败，证书已被吊销!");
		else if(res.ErrorCode == SOF_CERT_NOT_TRUSTED)
			alert("P1文件签名失败，证书不被信任!");
		else
			ShowError(res);
	}
}

//20.P1文件验签
function Test_PKCS1_File_VerifySign()
{
    var sign_cert = mainForm.sign_cert.value;  
	var sInFilePath = mainForm.SignInFilePath.value;
    var sSignedValue64 = mainForm.FileSignedValue.value;

	if(sign_cert.length == 0 || sign_cert == null){
		alert("签名证书为空");
		return;
	}
	
	t1 = new Date().getTime();
	var res =  gPKISvc.SOF_VerifySignedFile(sign_cert, sInFilePath, sSignedValue64);
	t2 = new Date().getTime();
	mainForm.elapse20_2.value = t2 - t1;
	
	if(res.ErrorCode == SOR_OK){
		alert("P1文件验签成功");
	}else{
		ShowError(res);
	}
}

function SetSignMessageTSPURL()
{
	var ts_url = mainForm.signmsg_ts_url.value;

	if(ts_url.length > 0){
		var res =gPKISvc.SOF_Config(SOF_SET_TSP_URL, ts_url);
		if(res.ErrorCode == SOR_OK){
			alert("设置成功！");
		}else{
			ShowError(res);
		}
	}else{
		alert('地址不能为空！');
	}
}

//21.P7签名
function Test_SignMessage()
{
	mainForm.signed_msg.value = '';
	
    if(!CheckUser())
        return;

    var plain_data = mainForm.signmsg_plain_data.value;
    var sign_flag = parseInt(mainForm.sign_flag.value);
    var indata_format = parseInt(mainForm.indata_format.value);
	var ts_digest = mainForm.signmsg_ts_digest.value;
	
	if(indata_format == DATA_FMT_BASE64 && sign_flag == SIGN_FLAG_WITH_ORI){
		alert('带原文不支持Base64格式输入！');
		return;
	}

	var res = gPKISvc.SOF_Config(SOF_SET_SIGNMESSAGE_WITH_TSP, mainForm.signmsg_with_ts.checked?1:0);
	var errCode = res.ErrorCode;

	if(errCode == SOR_OK){
		res = gPKISvc.SOF_Config(SOF_SET_TSP_DIGEST_ALG, ts_digest);
		errCode = res.ErrorCode;
		if(errCode == SOR_OK){
			t1 = new Date().getTime();
			res = gPKISvc.SOF_SignMessage(sign_flag,gsSelectContainer, plain_data);
			errCode = res.ErrorCode;
			if(errCode == SOR_OK){
				t2 = new Date().getTime();
				mainForm.elapse21_1.value = t2 - t1;
				mainForm.signed_msg.value = res.Result.SignData;
				alert("P7签名成功");
			}else{
				//此处错误码判断，需要4.1.7以上版本
				if(errCode == SOR_P7SignErr)
					alert("P7签名失败，请确认是否登录!");
				else if(errCode == SOF_CERT_HASEXPIRED)
					alert("P7签名失败，证书已过期!");
				else if(errCode == SOF_CERT_REVOKED)
					alert("P7签名失败，证书已被吊销!");
				else if(errCode == SOF_CERT_NOT_TRUSTED)
					alert("P7签名失败，证书不被信任!");
				else if(errCode == SOR_IndataErr)
					alert("P7签名失败：原文不是Base64格式!");
				else if(errCode == SOR_TSP_DataErr)
					alert("P7签名失败：时间戳服务器数据错误!");
				else if(errCode == SOR_TSP_Err)
					alert("P7签名失败：时间戳服务器错误!");
				else
					ShowError(res);
			}
		}else{
			ShowError(res);
		}
	}else{
		ShowError(res);
	}

}


//21.p7验签
function Test_VerifyMessage()
{
    var signed_msg = mainForm.signed_msg.value;
    var plain_data = mainForm.signmsg_plain_data.value;
    var sign_flag = parseInt(mainForm.sign_flag.value);
    
	if(sign_flag == SIGN_FLAG_WITH_ORI) plain_data = null;
	
	t1 = new Date().getTime();
	var res = gPKISvc.SOF_VerifySignedMessage(signed_msg, plain_data);
	t2 = new Date().getTime();
	mainForm.elapse21_2.value = t2 - t1;

	if(res.ErrorCode == SOR_OK){
		alert("P7验签成功");
	}else{
		ShowError(res);
	}
}

//21.P7解析签名
function Test_ParseSignMessage()
{
	var signed_msg = mainForm.signed_msg.value;
    var iParseType = parseInt(mainForm.ParseType.value);

	mainForm.SignMsgInfo.value = '';
    
	t1 = new Date().getTime();
	var res =gPKISvc.SOF_GetInfoFromSignedMessage(signed_msg, iParseType);
	t2 = new Date().getTime();
	
	mainForm.elapse21_3.value = t2 - t1;

	if(res.ErrorCode == SOR_OK){
		mainForm.SignMsgInfo.value = res.Result.Info;
	}else{
		ShowError(res);
	}
}

//23.P7文件签名
function Test_Pkcs7_File_Sign()
{
	mainForm.P7SignedValue.value = '';
    if(!CheckUser())
       return;

	var sInFilePath = mainForm.P7_SignInFilePath.value;
	var psignfile_flag = parseInt(mainForm.signfile_flag.value);

	t1 = new Date().getTime();
	
	var res = gPKISvc.SOF_Ext_PKCS7_SignFile(gsSelectContainer, sInFilePath, psignfile_flag);
	t2 = new Date().getTime();		
	mainForm.elapse23_1.value = t2 - t1;

	var errCode = res.ErrorCode;
	if(errCode == SOR_OK){
			mainForm.P7SignedValue.value = res.Result.Sign;
			alert("P7文件签名成功");
	}else{
			//此处错误码判断，需要4.1.7以上版本
		if(errCode == SOR_P7SignErr)
			alert("P7签名失败，请确认是否登录!");
		else if(errCode == SOF_CERT_HASEXPIRED)
			alert("P7签名失败，证书已过期!");
		else if(errCode == SOF_CERT_REVOKED)
			alert("P7签名失败，证书已被吊销!");
		else if(errCode == SOF_CERT_NOT_TRUSTED)
			alert("P7签名失败，证书不被信任!");
		else
			ShowError(res);
	}
}

//23.P7文件验签
function Test_Pkcs7_File_VerifySign()
{
	var signed_msg = mainForm.P7SignedValue.value;
    var sInFilePath = mainForm.P7_SignInFilePath.value;
    var psignfile_flag = parseInt(mainForm.signfile_flag.value);
    
	//if(sign_flag == SIGN_FLAG_WITH_ORI) plain_data = null;
	
	t1 = new Date().getTime();
	var res = gPKISvc.SOF_Ext_PKCS7_VerifySignedFile(signed_msg, sInFilePath, psignfile_flag);
	t2 = new Date().getTime();
	mainForm.elapse23_2.value = t2 - t1;

	if( res.ErrorCode == SOR_OK){
		alert("P7验签成功");
	}else{
		ShowError(res);
	}
}

//24.设置加密格式
function Test_SetEnvelopType()
{
	var envType = parseInt(mainForm.EnvType.value);

	var res =  gPKISvc.SOF_Ext_SetEnvelopType(envType);
	if( res.ErrorCode == SOR_OK){
		alert("设置成功");
	}else{
		ShowError(res);
	}
}

//24.P7加密
function Test_Encrypt()
{
	mainForm.EncryptedData.value = '';
	
	if(!CheckScan()) return;
	
    var sEncryptPlainData = mainForm.EncryptPlainData.value;

    if(!CheckCert(CERT_TYPE_EXCHANGE))
        return;
        
	t1 = new Date().getTime();
	var res =gPKISvc.SOF_EncryptData(mainForm.enc_cert.value, sEncryptPlainData);
	t2 = new Date().getTime();
	mainForm.elapse24_1.value = t2 - t1;

	if( res.ErrorCode == SOR_OK){
		mainForm.EncryptedData.value= res.Result.EncryptData;
		alert("P7加密成功");
	}else{
		ShowError(res);
	}
}

//24.P7解密
function Test_Decrypt()
{
	mainForm.DecryptedData.value = '';
	
	if(!CheckScan()) return;
	
    if(!CheckUser())
        return;
	
	var sEncryptedDataB64 = mainForm.EncryptedData.value;
	var sEncryptPlainData = mainForm.EncryptPlainData.value;
	
	t1 = new Date().getTime();
	var res =gPKISvc.SOF_DecryptData(gsSelectContainer, sEncryptedDataB64);
	t2 = new Date().getTime();
	mainForm.elapse24_2.value = t2 - t1;

	var errCode = res.ErrorCode;
	if(errCode == SOR_OK){
		if(sEncryptPlainData == res.Result.DecryptData)
			alert("P7解密成功");
		else
			alert("P7解密失败,解密出结果和原文不相等");

		mainForm.DecryptedData.value = res.Result.DecryptData;

	}else{
		//此处错误码判断，需要4.1.7以上版本
		if(errCode == SOR_P7DecErr)
			alert("P7解密失败，请确认是否登录!")
		else
			ShowError(res);
	}
}

//26.P7文件加密
function Test_PKCS7_File_Encrypt()
{
	if(!CheckScan()) return;
	
	var sEnc_cert = mainForm.enc_cert.value;
	var sInFilePath = mainForm.EncInFilePath.value;
    var sOutFilePath = mainForm.EncOutFilePath.value;

    if(!CheckCert(CERT_TYPE_EXCHANGE))
        return;
        
	t1 = new Date().getTime();
	var res = gPKISvc.SOF_EncryptFile(sEnc_cert, sInFilePath,sOutFilePath);
	t2 = new Date().getTime();
	mainForm.elapse26_1.value = t2 - t1;
	
	var errCode = res.ErrorCode;
	if(errCode == SOR_OK){
		alert("P7文件加密成功");
	}else{
		ShowError(res);
	}
}

//26.P7文件解密
function Test_PKCS7_File_Decrypt()
{
	if(!CheckScan()) return;
	
    if(!CheckUser())
        return;
	
	 var sInFilePath = mainForm.DecInFilePath.value;
     var sOutFilePath = mainForm.DecOutFilePath.value;
	
	t1 = new Date().getTime();
	var res = gPKISvc.SOF_DecryptFile(gsSelectContainer, sInFilePath, sOutFilePath);
	t2 = new Date().getTime();
	mainForm.elapse26_2.value = t2 - t1;

	var errCode = res.ErrorCode;
	if(errCode == SOR_OK){
		alert("P7文件解密成功");
	}else{
		//此处错误码判断，需要4.1.7以上版本
		if(errCode == SOR_P7DecErr){
			alert("P7文件解密失败，请确认是否登录!");
		}
		else{
			ShowError(res);
		}
	}
}

//27.随机数
function Test_GenRandom()
{
	var gen_len = parseInt(mainForm.RandomLen.value);

	mainForm.RandomData.value = '';
	
	t1 = new Date().getTime();
	var res =  gPKISvc.SOF_GenRandom(gen_len);
	t2 = new Date().getTime();
	mainForm.elapse27.value = t2 - t1;

	if(res.ErrorCode== SOR_OK){
		mainForm.RandomData.value = res.Result.RandomData;
	}else{
		ShowError(res);
	}
}

//28.读标签
function Test_Ext_ReadLabel()
{
	mainForm.LabelData.value='';
	if(!CheckScan()) return;
	
	var lable_name = mainForm.preset_lable_name.value;
	var lable_type = GDCA_LBL_EXDATA;

	if(lable_name == "custom"){
		lable_type = GDCA_LBL_EXDATA;
		lable_name = mainForm.custom_lable_name.value;
	}else if(lable_name == LAB_USERCERT_SIG)
		lable_type = GDCA_LBL_SIGNCERT;
	else if(lable_name == LAB_USERCERT_ENC)
		lable_type = GDCA_LBL_ENCCERT;
	else if(lable_name == CA_CERT)
		lable_type = GDCA_LBL_CACERT;
	
	t1 = new Date().getTime();
	var res = gPKISvc.SOF_Ext_ReadLabel(gsSelectContainer, lable_name, lable_type);
	t2 = new Date().getTime();
	mainForm.elapse28.value = t2 - t1;
	
	var errCode = res.ErrorCode;
	if(errCode == SOR_OK){
		mainForm.LabelData.value = res.Result.lableData;
		alert("读标签成功");
	}else{
		if(errCode == SOR_CertNotFountErr)
			alert("标签不存在！");
		else
        	ShowError(res);
	}
}

//29.写/读 多用户数据
function Test_Ext_WriteUsrDataFile()
{
	if(!CheckScan()) return;

	if(mainForm.WriteData.value.length == 0){
		alert("写入数据为空！");
		return;
	}
	
	var userpin = mainForm.FilePIN.value;
	var nFileType = parseInt(mainForm.FileType.value, 16);
	var nFileIndex = parseInt(mainForm.FileIndex.value, 10);
	var nFileOffset = parseInt(mainForm.FileOffset.value, 10);
	var sWriteData = mainForm.WriteData.value;

	var nLen = 0;
	var i = 0;

	for(i = 0; i < sWriteData.length; i++) 
	{ 
		if(sWriteData.charCodeAt(i) > 128)
			nLen = nLen + 3;
		else
			nLen = nLen + 1;	
	}
	
	alert("写入长度: " + nLen);

	var sWriteDataBase64 = CryptoJSUtil.base64Encode(mainForm.WriteData.value); 
	
	t1 = new Date().getTime();
    res =gPKISvc.SOF_Ext_WriteUsrDataFile(gsSelectContainer, userpin, nFileType, nFileIndex, nFileOffset, sWriteDataBase64);
	t2 = new Date().getTime();
	
	mainForm.elapse29_1.value = t2 - t1;

	var errCode = res.ErrorCode;
	if(errCode == SOR_OK){
		alert("写入成功");
	}else{
		if(errCode == SOR_IndataErr)
			alert("写多用户数据失败：写入数据不是Base64格式")
		else
			ShowError(res);
	}
}

//29.读 多用户数据
function Test_Ext_ReadUsrDataFile()
{
	if(!CheckScan()) return;
	
	var nFileType = parseInt(mainForm.FileType.value, 16);
	var nFileIndex = parseInt(mainForm.FileIndex.value, 10);
	var nFileOffset = parseInt(mainForm.FileOffset.value, 10);
	var nReadLen = parseInt(mainForm.ReadLen.value, 10);
	
	t1 = new Date().getTime();
	var res = gPKISvc.SOF_Ext_ReadUsrDataFile(gsSelectContainer, nFileType, nFileIndex, nFileOffset,nReadLen);
	t2 = new Date().getTime();
	
	mainForm.elapse29_2.value = t2 - t1;
	
	var errCode = res.ErrorCode;
	if(errCode == SOR_OK){
		mainForm.ReadData.value = res.Result.ReadData;
		try{
			mainForm.ReadDataBase64DecodeData.value = CryptoJSUtil.base64Decode(res.Result.ReadData);  
		}catch(e){
			mainForm.ReadDataBase64DecodeData.value = '';
		}
	}else{
		mainForm.ReadDataBase64DecodeData.value = '';
		mainForm.ReadData.value = '';
		ShowError(res);
	}
}

function Test_DataHash()
{
	var hashAlg = parseInt(mainForm.hash_alg.value, 16);
	var inData = mainForm.hash_in_data.value;
	var pubKey = '';
	var uid = '';
	var inDataFmt = parseInt($("#hash_indata_format").val());

	if(hashAlg == SGD_SM3){
		pubKey = mainForm.hash_pubkey.value;
		uid = mainForm.hash_uid.value;
	}
		
    var t1 = new Date().getTime();

    var res = gPKISvc.SOF_Ext_HashData(hashAlg, inData, inDataFmt, pubKey, uid);
    
	t2 = new Date().getTime();
	
	mainForm.elapse40.value = t2 - t1;
	
	if(res.ErrorCode == SOR_OK){
		alert("计算哈希成功");
		mainForm.hash_val.value = res.Result.HashValue;
	}else{
		ShowError(res);
	}
}

function Test_FileHash()
{
	var hashAlg = parseInt(mainForm.hash_alg.value, 16);
	var inData = mainForm.hash_in_data.value;
	var pubKey = '';
	var uid = '';
	var filepath = $('#hash_file_path').val();
	
	if(hashAlg == SGD_SM3){
		pubKey = mainForm.hash_pubkey.value;
		uid = mainForm.hash_uid.value;
	}
		
    var t1 = new Date().getTime();

    var res = gPKISvc.SOF_Ext_HashFile(hashAlg, filepath, pubKey, uid);
    
	t2 = new Date().getTime();
	
	mainForm.elapse40.value = t2 - t1;
	
	if(res.ErrorCode == SOR_OK){
		alert("文件哈希成功");
		mainForm.hash_val.value = res.Result.HashValue;
	}else{
		if(res.ErrorCode == SOR_FileErr)
			alert("文件打开错误，请确认输入文件是否存在!")
		else
			ShowError(res);
	}
}

//31.XML签名
function Test_XMLSign()
{
	mainForm.xml_signed.value = '';

    if(!CheckUser())
        return;

	var xml_sign_plain = mainForm.xml_sign_plain.value;
	
	t1 = new Date().getTime();
	var res = gPKISvc.SOF_SignDataXML(gsSelectContainer, xml_sign_plain);
	t2 = new Date().getTime();
	mainForm.elapse31_1.value = t2 - t1;

	var errCode = res.ErrorCode;
	if(errCode == SOR_OK){
		mainForm.xml_signed.value = res.Result.SignedData;
		alert("XML签名成功");
	}else{
		//此处错误码判断，需要4.1.7以上版本
		if(errCode == SOR_RsaEncErr || errCode == SOR_ECCEncErr)
			alert("XML签名失败，请确认是否登录!")
		else if(errCode == SOF_CERT_HASEXPIRED)
			alert("XML签名失败，证书已过期!");
		else if(errCode == SOF_CERT_REVOKED)
			alert("XML签名失败，证书已被吊销!");
		else if(errCode == SOF_CERT_NOT_TRUSTED)
			alert("XML签名失败，证书不被信任!");
		else
			ShowError(res);
	}
}

//31.XML验签
function Test_VerifyXMLSign()
{
	var xml_signed = mainForm.xml_signed.value;
	
	t1 = new Date().getTime();
	var res = gPKISvc.SOF_VerifySignedDataXML(xml_signed);
	t2 = new Date().getTime();
	mainForm.elapse31_2.value = t2 - t1;
	
	var errCode = res.ErrorCode;
	if(errCode == SOR_OK){
		alert("验签成功");
	}else{
		ShowError(res);
	}
}

//31.解析XML签名数据
function Test_ParseXMLSignResult()
{
    var xml_signed = mainForm.xml_signed.value;
    var xml_info_type = parseInt(mainForm.xml_info_type.value);

	mainForm.xml_sign_info.value = '';
    
	t1 = new Date().getTime();
	var res = gPKISvc.SOF_GetXMLSignatureInfo(xml_signed, xml_info_type);
	t2 = new Date().getTime();
	mainForm.elapse31_3.value = t2 - t1;
	
	var errCode = res.ErrorCode;
	if(errCode == SOR_OK){
		mainForm.xml_sign_info.value = res.Result.Info;
	}else{
		ShowError(res);
	}
}

//32.获取时间戳
function Test_Ext_GM_TspGetTime()
{
	$('#gm_tsp_time').val('');
	
	t1 = new Date().getTime();
	var res =gPKISvc.SOF_Ext_TspGetTime();
	t2 = new Date().getTime();
	mainForm.elapse32_1.value = t2 - t1;

	var errCode = res.ErrorCode;
	if(errCode == SOR_OK){
		$('#gm_tsp_time').val(res.Result.TimeStamp);
		alert("获取时间戳成功");
	}else{
		ShowError(res);
	}
}

//32.加盖时间戳
function Test_Ext_GM_TspSealTimeStamp()
{
	var in_data = mainForm.gm_tsp_in_data.value;
	var algType = parseInt(mainForm.gm_tsp_alg_type.value, 16);
	var codeType = parseInt(mainForm.gm_tsp_indata_code.value);
	
	$('#gm_tsp_timestamp').val('');

	t1 = new Date().getTime();
	var res = gPKISvc.SOF_Ext_TspGetStamp(in_data, algType);
	t2 = new Date().getTime();
	mainForm.elapse32_2.value = t2 - t1;
	
	var errCode = res.ErrorCode;
	if(errCode == SOR_OK){
		$('#gm_tsp_timestamp').val(res.Result.SealData);
		alert("加盖时间戳成功");
	}else{
		if(codeType == 2 && errCode == SOR_IndataErr)
			alert("输入数据错误，必须是base64格式！");
		else
			ShowError(res);
	}
}

//32.验证时间戳
function Test_Ext_GM_TspVerifyTimeStamp()
{
	var gm_tsp_in_data = $('#gm_tsp_in_data').val();
	var gm_tsp_timestamp = $('#gm_tsp_timestamp').val();
	var cert = '';

	$('#gm_tsp_verify_result').val('');

	t1 = new Date().getTime();
	var res = gPKISvc.SOF_Ext_TspVerifyStamp(gm_tsp_in_data, gm_tsp_timestamp, cert);
	t2 = new Date().getTime();
	mainForm.elapse32_3.value = t2 - t1;
	
	var errCode = res.ErrorCode;
	if(errCode == SOR_OK){
		$('#gm_tsp_verify_result').val(res.Result.TimeStamp);
		alert('验证时间戳成功');
	}else{
		ShowError(res);
	}
}

//33.接口控制
function apiControl(obj, ctrl_name, ctrl_cmd)
{
    if(!CheckUser())
        return;
        
	var ctrl_cmd = get_radio_val(ctrl_cmd);

	t1 = new Date().getTime();
	var res = gPKISvc.SOF_Ext_Control(gsSelectContainer, ctrl_name, ctrl_cmd);
	t2 = new Date().getTime();
	mainForm.elapse33.value = t2 - t1;

	var errCode = res.ErrorCode;
	if(errCode == SOR_OK){
		alert('设置成功');
	}else{
		ShowError(res);
	}
	return false;
}

//34.文件对称加密
function Test_SymmEncFile()
{
	var symmAlg = parseInt(mainForm.symmAlg.value, 16);
	var symmKey = mainForm.symmKey.value;
	var symmIV = mainForm.symmIV.value;
	var inFilePath = $('#symmFileEncInPath').val();
	var outFilePath = $('#symmFileEncOutPath').val();

	t1 = new Date().getTime();

	var res = gPKISvc.SOF_Ext_SymmEncryptFile(symmAlg, symmKey, symmIV, inFilePath, outFilePath);
	t2 = new Date().getTime();
	mainForm.elapse34_1.value = t2 - t1;
	
	var errCode = res.ErrorCode;
	if(errCode == SOR_OK){
		 alert("加密成功");
	}else{
		if(errCode == SOR_IndataLenErr)
			alert("密钥或初始向量长度不正确，3DES为24，其它算法16")
		else if(errCode == SOR_FileErr)
			alert("文件打开错误，请确认输入文件是否存在!")
		else
			ShowError(res);
	}
}

//34.文件对称解密
function Test_SymmDecFile()
{
	var symmAlg = parseInt(mainForm.symmAlg.value, 16);
	var symmKey = mainForm.symmKey.value;
	var symmIV = mainForm.symmIV.value;
	var inFilePath = $('#symmFileDecInPath').val();
	var outFilePath = $('#symmFileDecOutPath').val();

	t1 = new Date().getTime();
	var res = gPKISvc.SOF_Ext_SymmDecryptFile(symmAlg, symmKey, symmIV, inFilePath, outFilePath);
	t2 = new Date().getTime();
	mainForm.elapse34_2.value = t2 - t1;

	var errCode = res.ErrorCode;
	if(errCode == SOR_OK){
		alert("解密成功");
	}else{
		if(errCode == SOR_IndataLenErr)
			alert("密钥或初始向量长度不正确，3DES为24，其它算法16")
		else if(errCode == SOR_FileErr)
			alert("文件打开错误，请确认输入文件是否存在!")
		else
			ShowError(res);
	}
}

function GetFileReadRights()
{
	var frr_admin = document.getElementById('frr_admin');
	var frr_user = document.getElementById('frr_user');
	var frr_everyone = document.getElementById('frr_everyone');

	var rights = 0;

	if(frr_admin.checked)
		rights |= SECURE_ADM_ACCOUNT;
		
	if(frr_user.checked)
		rights |= SECURE_USER_ACCOUNT;
		
	if(frr_everyone.checked)
		rights |= SECURE_EVERYONE_ACCOUNT;

	return rights;
}

function GetFileWriteRights()
{
	var frw_admin = document.getElementById('frw_admin');
	var frw_user = document.getElementById('frw_user');
	var frw_everyone = document.getElementById('frw_everyone');

	var rights = 0;

	if(frw_admin.checked)
		rights |= SECURE_ADM_ACCOUNT;
		
	if(frw_user.checked)
		rights |= SECURE_USER_ACCOUNT;
		
	if(frw_everyone.checked)
		rights |= SECURE_EVERYONE_ACCOUNT;

	return rights;
}

function Test_CreateFile()
{
	var file_name = mainForm.file_create_name.value;
	var file_len = parseInt(mainForm.file_create_length.value, 10);
	var readRights = GetFileReadRights();
	var writeRights = GetFileWriteRights();
	
    var t1 = new Date().getTime();

    var res = gPKISvc.SOF_Ext_CreateFile(gsSelectContainer, file_name, file_len, readRights, writeRights);

    var t2 = new Date().getTime();

    mainForm.elapse35.value = t2 - t1;

	if(res.ErrorCode == SOR_OK)
    	alert("创建成功");
    else
    	ShowError(res);
}

function OnFileSelected()
{
    var idx = mainForm.file_list.options.selectedIndex;
    
	if(idx == -1)
		return;

	g_select_file_name = g_file_list[idx];

	mainForm.file_name_wr.value =g_select_file_name;
}

function Test_EnumFile()
{
	var file_list = document.getElementById('file_list');
	g_file_list = [];
	
    if(!CheckUser())
       return;
       
    //先清除原来的内容
	file_list.length=0;
	
    for (i = 0; i < mainForm.file_list.options.length; i++)
        mainForm.file_list.options.remove(0);

    var t1 = new Date().getTime();

	var res = gPKISvc.SOF_Ext_EnumFile(gsSelectContainer);

    var t2 = new Date().getTime();

	if(res.ErrorCode == SOR_OK){
		if(res.Result.FileNames.length > 0)
			g_file_list = res.Result.FileNames.split("&&");

    	if(g_file_list.length > 0){
	    	for (i = 0; i < g_file_list.length; i++)
    			file_list.options.add(new Option(g_file_list[i]), i);
    			
        	mainForm.file_list.options[0].selected = true;
        	OnFileSelected();
    	}else{
	    	alert("找不到文件!");
    	}
	}else
		ShowError(res);

    mainForm.elapse36.value = t2 - t1;
}

function Test_GetFileAttr()
{
    if(!CheckUser())
       return;
   	
    var t1 = new Date().getTime();

    var res = gPKISvc.SOF_Ext_GetFileAttribute(gsSelectContainer, g_select_file_name);

    var t2 = new Date().getTime();

	if(res.ErrorCode == SOR_OK){
		mainForm.file_length.value = res.Result.FileAttr.fileSize.toString();
		mainForm.file_read_rights.value = res.Result.FileAttr.readRights.toString();
		mainForm.file_write_rights.value = res.Result.FileAttr.writeRights.toString();
	}else
		ShowError(res);

    mainForm.elapse36.value = t2 - t1;
}

function Test_ReadFile()
{
	var file_name = mainForm.file_name_wr.value;
	var file_offset = parseInt(mainForm.file_offset.value, 10);
	var file_read_len = parseInt(mainForm.file_read_len.value, 10);
	
    if(!CheckUser())
       return;
       
    var t1 = new Date().getTime();

    var res = gPKISvc.SOF_Ext_ReadFile(gsSelectContainer, file_name, file_offset, file_read_len);

    var t2 = new Date().getTime();
    
    mainForm.elapse37.value = t2 - t1;
    
	if(res.ErrorCode == SOR_OK){
		var fileData = res.Result.FileData;
		
		mainForm.file_read_data.value = fileData;
		//mainForm.fdata_hex.value = GDCACom.SOF_Ext_Base64DecodeToHexStr(fileData, 24, true);
		mainForm.fdata_base64_decode.value = gPKISvc.base64Decode(fileData);
	}
    else
    	ShowError(res);
}

function Test_WriteFile()
{
	var file_name = mainForm.file_name_wr.value;
	var write_data = mainForm.file_write_data.value;
	var file_offset = parseInt(mainForm.file_offset.value, 10);
	var fw_indata_fmt = parseInt(get_radio_val('fw_indata_fmt'));
	
    if(!CheckUser())
       return;
       
	if(write_data.length == 0){
		alert('写入数据不能为空!');
		return;
	}

	var nLen = 0;
	var i = 0;
		
	for(i = 0; i < write_data.length; i++) 
	{ 
		if(write_data.charCodeAt(i) > 128)
			nLen = nLen + 3;
		else
			nLen = nLen + 1;	
	}
	
	alert("写入长度: " + nLen);
	
    var t1 = new Date().getTime();

    var res = gPKISvc.SOF_Ext_WriteFile(gsSelectContainer, file_name, file_offset, fw_indata_fmt, mainForm.file_write_data.value);

    var t2 = new Date().getTime();
    
    mainForm.elapse37.value = t2 - t1;
    
	if(res.ErrorCode == SOR_OK)
		alert('写入成功');
	else
		ShowError(res);
}

function Test_DeleteFile()
{
	var file_name = mainForm.file_name_wr.value;
	
    if(!CheckUser())
       return;
       
    var t1 = new Date().getTime();

    var res = gPKISvc.SOF_Ext_DeleteFile(gsSelectContainer, file_name);

    var t2 = new Date().getTime();

    mainForm.elapse37.value = t2 - t1;
    
	if(res.ErrorCode == SOR_OK)
		alert('删除成功');
	else
		ShowError(res);
}


function Test_ExportPublicKey()
{
    if(!CheckUser())
       return;
       
	var keyUsage = parseInt(mainForm.key_usage.value, 10);
       
    var t1 = new Date().getTime();

    var res = gPKISvc.SOF_Ext_ExportPublicKey(gsSelectContainer, keyUsage);

    var t2 = new Date().getTime();

    mainForm.elapse38.value = t2 - t1;
    
	if(res.ErrorCode == SOR_OK)
		mainForm.public_key.value = res.Result.pubKey;
	else
		ShowError(res);
}

function Test_Ext_AsymmEncyptData()
{
    var in_data = mainForm.asymm_enc_in.value;
    var pubkey = mainForm.asymm_enc_pubkey.value;
    
	if(in_data.length == 0){
		alert('原文不能为空!');
		return;
	}
	
	if(pubkey.length == 0){
		alert('公钥不能为空!');
		return;
	}

    var t1 = new Date().getTime();

    var res = gPKISvc.SOF_Ext_AsymmEncryptData(in_data, pubkey);

    var t2 = new Date().getTime();

    mainForm.elapse39.value = t2 - t1;
    
	if(res.ErrorCode == SOR_OK){
		mainForm.asymm_enc_out.value = res.Result.EncryptData;
		alert('加密成功');
	}
	else
		ShowError(res);
}

function Test_Ext_AsymmDecryptData()
{
    if(!CheckUser())
        return;
        
    var enc_data = mainForm.asymm_enc_out.value;
    
    var t1 = new Date().getTime();

    var res = gPKISvc.SOF_Ext_AsymmDecryptData(gsSelectContainer, enc_data);

    var t2 = new Date().getTime();

    mainForm.elapse39.value = t2 - t1;
    
	if(res.ErrorCode == SOR_OK){
		mainForm.asymm_dec_out.value = res.Result.DecryptData;
		alert('解密成功');
	} else
		ShowError(res);
}

function Test_GetAdapterInfo()
{
    var params = {};
    
    var t1 = new Date().getTime();

    var res = gPKISvc.CommonCommand(Command.get_adapter_info, params);

    var t2 = new Date().getTime();

    mainForm.elapse40.value = t2 - t1;
    
	if(res.ErrorCode == SOR_OK){
		var ethInfo = res.Result;

		mainForm.ethInfo.value = '';
		
		for (i = 0; i < ethInfo.length; i++){
    		var ipList = '[';
            ipList += ethInfo[i].ipList.join(', '),
    		ipList += ']';

        	mainForm.ethInfo.value += '网卡名称：' + ethInfo[i].desc + '\n' + 'IP地址：' + ipList + '\n' + 'Mac地址：' + ethInfo[i].mac + '\n\n';
		}
	} else
		ShowError(res);
}

//35.清理
function Test_Finalize()
{
	t1 = new Date().getTime();
	var res = gPKISvc.SOF_Finalize();
	t2 = new Date().getTime();
	
	mainForm.elapse41.value = t2 - t1;

	if(res.ErrorCode == SOR_OK)
		 alert('清理成功！');
	else
		ShowError(res);
}


