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
var pic_type_name = ["", "bmp", "gif", "jpg", "png"];
var g_seal_format = ["未知", "GDCA印章", "国密印章", "国标印章"];


function clearForm() {
    mainForm.dev_info.value = "";
    mainForm.sign_cert.value = "";
    mainForm.enc_cert.value = "";
    mainForm.CertInfo.value = "";
    mainForm.CertInfo2.value = "";
    mainForm.CertInfo3.value = "";
    mainForm.SignMsgInfo.value = "";
    mainForm.p1Signature.value = "";
    mainForm.signed_msg.value = "";
    mainForm.EncryptedData.value = "";
    mainForm.DecryptedData.value = "";
    mainForm.RandomData.value = "";
    mainForm.xml_signed.value = "";
    mainForm.xml_sign_info.value = "";
}

function OnInputDataChannged(obj, lenId)
{
    document.getElementById(lenId).innerHTML = get_str_len(obj.value, 3).toString();
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
'    </list>\n' +
'</info>';

    initCAInfo();

    try
    {
        PKIServiceInit();
    }
    catch (e)
    {
        alert(e.message)
    }
};

function doPKIServiceInit(callback) {
    
    gPKISvc.Initialize(PROTO_AUTO, function(event, arg, ec){
        if(event == WUEvent.connect && arg){
            callback();
        }else if(event == WUEvent.connect && !arg){
            notifyBar.setText('通讯初始化失败（错误码：0x' + ec.toString(16).toUpperCase() +'）', 2);
        }else if(event == WUEvent.closed)
            notifyBar.setText('通讯已断开', 1);
        else if(event == WUEvent.ukey_event){
            //处理设备插拔事件
            if(arg.evt == 1)
                $('#dev_evt').html('设备插入,设备类型'+arg.type);
            else
                $('#dev_evt').html('设备拔出');
        }
    });
}

function InitCallback() {
    notifyBar.setText('通讯初始化成功', 3, 1200);
}

function PKIServiceInit() {
    notifyBar.init();
    notifyBar.setText('正在初始化通讯· · · · · · ', 0);
    doPKIServiceInit(InitCallback);
}

function timerCheckGetVer() {
	if(g_api_ver != ''){
		clearInterval(g_timer_get_ver);
		if(!xs_compare_ver(g_api_ver, "1.1.3")){
			alert('您的证书客户端版本太低，需要4.2.1或更高版本！');
		}
	}
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

    gPKISvc.SOF_Config(SOF_SET_SUPPORT_DEVICE_EX, g_enum_flags, function(res){
		if(res.ErrorCode != SOR_OK){
			ShowError(res);
		}
    });
}

function EnumPFXClick()
{
    var enum_pfx = document.getElementById('enum_pfx');
    
    gPKISvc.SOF_Config(SOF_SET_ENUM_MICROSOFT_PFX, enum_pfx.checked?1:0, function(res){
		if(res.ErrorCode != SOR_OK){
			ShowError(res);
		}
    });
}

//1.获取接口版本号
function Test_GetVersion()
{
	mainForm.api_version.value = '';
	
	t1 = new Date().getTime();

    gPKISvc.SOF_GetVersion(function(res){
		t2 = new Date().getTime();
		mainForm.elapse1.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			mainForm.api_version.value = res.Result.Version;
			g_api_ver = res.Result.Version;
		}else
			ShowError(res);
    });
}

//2.获取产品版本号
function Test_GetProductVersion()
{
	var product_type = parseInt(mainForm.product_type.value);	
	mainForm.product_version.value = '';

	t1 = new Date().getTime();
	
    gPKISvc.SOF_Ext_GetProductVersion(product_type, function(res){
		t2 = new Date().getTime();
		mainForm.elapse2.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			mainForm.product_version.value = res.Result.Version;
		}else
			ShowError(res);
    });
}

function Test_Config()
{
	var set_type = parseInt(document.getElementById('set_type').value);
	var set_val = document.getElementById('set_val').value;
	var set_data_type = parseInt(document.getElementById('set_data_type').value);

	if(set_data_type == 1){
    	if(set_val.indexOf("0x") != -1)
		    set_val = parseInt(set_val, 16);
		else
		    set_val = parseInt(set_val);
	}

	t1 = new Date().getTime();

    gPKISvc.SOF_Config(set_type, set_val, function(res){
		t2 = new Date().getTime();
		mainForm.elapse4.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("设置成功");
		}else
			ShowError(res);
    });
}

//4.设置数据输入格式
function SetInDataFormat()
{
	var indata_format = parseInt(document.getElementById('indata_format').value);

	t1 = new Date().getTime();

    gPKISvc.SOF_Config(SOF_SET_INDATA_FORMAT, indata_format, function(res){
		t2 = new Date().getTime();
		mainForm.elapse4.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("设置成功");
		}else
			ShowError(res);
    });
}

function SetFilePartLen(objId)
{
    var val = document.getElementById(objId).value;

    if(val.length == 0){
        alert('长度不能为空!');
        return;
    }
    
	var file_part_len = parseInt(val);
    
	t1 = new Date().getTime();

    gPKISvc.SOF_Config(SOF_SET_FILE_PART_LEN, file_part_len, function(res){
		t2 = new Date().getTime();
		mainForm.elapse4.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("设置成功");
		}else
			ShowError(res);
    });
}

//设置服务响应超时
function Test_ConfigServerTimeout()
{
	var set_times = parseInt(document.getElementById('server_timeout').value);

	t1 = new Date().getTime();
	
    gPKISvc.SOF_Config(SOF_SET_HTTP_TIMEOUT, set_times, function(res){
		t2 = new Date().getTime();
		mainForm.elapse4.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("设置成功");
		}else
			ShowError(res);
    });
}

//5.枚举设备
function Test_EnumDevice()
{
	mainForm.enum_dev.value = '';

	t1 = new Date().getTime();

    gPKISvc.SOF_Ext_EnumDevice(function(res){
		t2 = new Date().getTime();
		mainForm.elapse5.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			mainForm.enum_dev.value =res.Result.DeviceInfo;
			var devTypeList = JSON.parse(res.Result.DeviceInfo);
			if(devTypeList.length == 0){
				alert("没有检测到UKey！");
			}
		}else
			ShowError(res);
    });
}

//6.获取设备类型
function Test_GetDeviceType()
{
	mainForm.dev_type.value = '';
	
	t1 = new Date().getTime();

    gPKISvc.SOF_Ext_GetDeviceType(function(res){
		t2 = new Date().getTime();
		mainForm.elapse6.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			mainForm.dev_type.value =res.Result.devType;
		}else
			ShowError(res);
    });
}

//7.枚举证书
function Test_EnumCert(obj)
{
	document.getElementById("UserList").options.length = 0; 

    if(obj != undefined)
	    obj.disabled = true;

	t1 = new Date().getTime();
	
	gPKISvc.SOF_GetUserList(function(res){
		t2 = new Date().getTime();

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
		
		if(obj != undefined)
		    obj.disabled = false;
		    
		mainForm.elapse7.value = t2 - t1;
	});
}

//8.获取设备信息
function Test_GetDeviceInfo()
{
    if(!CheckUser())
       return;
    
	document.getElementById('dev_info').value = '';	
	
	var devInfoType = parseInt(mainForm.DevInfoType.value, 16);
	
	t1 = new Date().getTime();

    gPKISvc.SOF_GetDeviceInfo(gsSelectContainer, devInfoType, function(res){
		t2 = new Date().getTime();
		mainForm.elapse8.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			mainForm.dev_info.value =res.Result.DeviceInfo;
		}else{
			mainForm.dev_info.value = "";
			if(res.ErrorCode == SOR_NotSupportYetErr)
				alert("设备不支持此属性！");
			else
				ShowError(res);
		}
    });
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
	
    gPKISvc.SOF_Login(gsSelectContainer, sPassword, function(res){
		t2 = new Date().getTime();
		mainForm.elapse9.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("登录成功");
			gIsLogin = true;
		}else
			ShowError(res);
    });
}

//10.判断是否登陆
function Test_IsLogin()
{
	if(!CheckScan()) return;
       
    if(!CheckUser())
       return;
       
	t1 = new Date().getTime();
	
    gPKISvc.SOF_Ext_isLogin(gsSelectContainer, 1, function(res){
		t2 = new Date().getTime();
		mainForm.elapse10.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("已登录");
		}else if(res.ErrorCode == SOR_NotLoginErr)
			alert("未登录");
		else
			ShowError(res);
    });
}

//11.获取口令剩余重试次数
//多CA兼容时获取剩余重试次数
function Test_GetPinRetryCount()
{
	mainForm.PinRetryCount.value = '';
	
	if(!CheckScan()) return;
	
    if(!CheckUser())
        return;

	t1 = new Date().getTime();
	
    gPKISvc.SOF_GetPinRetryCount(gsSelectContainer, function(res){
		t2 = new Date().getTime();
		mainForm.elapse11.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			mainForm.PinRetryCount.value =res.Result.RetryCount;
		}else
			ShowError(res);
    });
}

//12.退出登录
function Test_Ext_Logout()
{
	if(!CheckScan()) return;
       
    if(!CheckUser())
       return;
       
	t1 = new Date().getTime();
	
    gPKISvc.SOF_Ext_Logout(gsSelectContainer, 1, function(res){
		t2 = new Date().getTime();
		mainForm.elapse11.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("登出成功");
			gIsLogin = false;
		}else
			ShowError(res);
    });
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
	
    gPKISvc.SOF_ChangePassWd(gsSelectContainer, oldpin, newpin, function(res){
		t2 = new Date().getTime();
		mainForm.elapse12.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("修改密码成功");
		}else
			ShowError(res);
    });
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
		
	    gPKISvc.SOF_ExportUserCert(sContainer, function(res){
			t2 = new Date().getTime();
			mainForm.elapse13.value = t2 - t1;
			
			if(res.ErrorCode == SOR_OK){
				mainForm.sign_cert.value = res.Result.UserCert;
			}else
				ShowError(res);
	    });
	}
	else{
		mainForm.enc_cert.value = '';
		
	    gPKISvc.SOF_ExportExChangeUserCert(sContainer, function(res){
			t2 = new Date().getTime();
			mainForm.elapse13.value = t2 - t1;
			
			if(res.ErrorCode == SOR_OK){
				mainForm.enc_cert.value = res.Result.UserCert;
			}else
				ShowError(res);
	    });
	}
}

//检测是否湛江平台证书
//页面初始化时需先调用initCAInfo();
function checkIsZhanjiangCert()
{
	var cert_type = parseInt(mainForm.CertType3.value);
	var usercert = '';

    if(!CheckCert(cert_type))
        return;

	usercert = (cert_type == CERT_TYPE_SIGN)?mainForm.sign_cert.value:mainForm.enc_cert.value;

    gPKISvc.SOF_GetCertInfo(usercert, SGD_AUTHORITYKEYIDENTIFIER_INFO, function(res1){
		if(res1.ErrorCode == SOR_OK){
            gPKISvc.SOF_GetCertInfo(usercert, SGD_CERT_SUBJECT_OU, function(res2){
        		if(res2.ErrorCode == SOR_OK){
            		var authorityKeyId = res1.Result.Info.replace('KeyID=', '');
            		var ou = res2.Result.Info;

            		if(getCAByKeyId(authorityKeyId) == CA_GDCA && ou == 'ZJGC')
            		    alert('是湛江平台证书');
            		else
            		    alert('非湛江平台证书');
        		}else{
        			ShowError(res2);
        		}
            });
    		
		}else{
			ShowError(res1);
		}
    });
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

	obj.disabled = true;

	usercert = (cert_type == CERT_TYPE_SIGN)?mainForm.sign_cert.value:mainForm.enc_cert.value;

	t1 = new Date().getTime();

    gPKISvc.SOF_GetCertInfo(usercert, info_type, function(res){
		t2 = new Date().getTime();
		mainForm.elapse14.value = t2 - t1;
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
			|| info_type == SGD_CERT_DER_EXTENSIONS
			|| info_type == SGD_NOT_BEFORE_TIME
			|| info_type == SGD_NOT_AFTER_TIME
			|| info_type == SGD_AUTHORITYKEYIDENTIFIER_INFO
			|| info_type == SGD_SUBJECTKEYIDENTIFIER_INFO
			|| info_type == SGD_CERT_SUBJECT_INFO
			|| info_type == SGD_CERT_ISSUER_INFO){
				$('#CertInfo').val(res.Result.Info);
			}else{
				$('#CertInfo').val(gPKISvc.base64Decode(res.Result.Info));
			}
		}else{
			$('#CertInfo').val("");
			ShowError(res);
		}
    });
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

    gPKISvc.SOF_GetCertInfoByOid(usercert, oid_name, function(res){
		t2 = new Date().getTime();
		mainForm.elapse15.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			var info = gPKISvc.base64Decode(res.Result.Info);
			
			if(oid_name == OID_GDCA_TRUST_ID)
				res = trimOIDVal(info);
			mainForm.CertInfo2.value = info;
		}else{
			mainForm.CertInfo2.value = "";
			ShowError(res);
		}
    });
}

function Test_ParseCertInfo(obj)
{
	var cert_type = parseInt(mainForm.CertType3.value);
	var usercert = '';
	var flags = 0x00000FFF;
	var oids = [];

	$('#CertInfo3').val("");

    oids.push(OID_GDCA_TRUST_ID);         //GDCA信任服务号
    oids.push(OID_GDCA_ORG_CODE);         //企业组织机构代码
    oids.push(OID_GDCA_USCC);             //GDCA统一社会信用代码
    oids.push(OID_ID_NUM);                //个人身份证号码
	
    if(!CheckCert(cert_type))
        return;

	obj.disabled = true;

	usercert = (cert_type == CERT_TYPE_SIGN)?mainForm.sign_cert.value:mainForm.enc_cert.value;

	t1 = new Date().getTime();

    gPKISvc.SOF_Ext_ParseCertInfo(usercert, flags, oids, function(res){
		t2 = new Date().getTime();
		mainForm.elapse16.value = t2 - t1;
		obj.disabled = false;
		
		if(res.ErrorCode == SOR_OK){
            mainForm.CertInfo3.value = JSON.stringify(res.Result, null, "\t");;
		}else{
			ShowError(res);
		}
    });
}


//17.证书验证
function Test_ValidateCert()
{
	var cert_type = parseInt(mainForm.CertType4.value);
	var usercert = '';

    if(!CheckCert(cert_type))
        return;
        
	usercert = (cert_type == CERT_TYPE_SIGN)?mainForm.sign_cert.value:mainForm.enc_cert.value;
	
	t1 = new Date().getTime();
	
    gPKISvc.SOF_ValidateCert(usercert, function(res){
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
    });
}

function P1SignRandClick()
{
    var p1sign_rand_data = document.getElementById('p1sign_rand_data');

    document.getElementById('SignPlainData').disabled = p1sign_rand_data.checked;
}

function Test_SetP1SignMethod()
{
	var signMethod = parseInt(mainForm.p1SignMethod.value, 16);

    gPKISvc.SOF_SetSignMethod(signMethod, function(res){
		
		if(res.ErrorCode == SOR_OK){
			alert("设置成功");
		}else
			ShowError(res);
    });
}

function Test_SetP7SignMethod()
{
	var signMethod = parseInt(mainForm.p7SignMethod.value, 16);

    gPKISvc.SOF_SetSignMethod(signMethod, function(res){
		
		if(res.ErrorCode == SOR_OK){
			alert("设置成功");
		}else
			ShowError(res);
    });
}


var g_p1sign_indata;

//18.P1签名验签
function Test_Sign()
{
    var p1sign_rand_data = document.getElementById('p1sign_rand_data');
    
	mainForm.p1Signature.value = '';
	
    if(!CheckUser())
        return;

    if(p1sign_rand_data.checked){
        var p1sign_rand_len = parseInt(mainForm.p1sign_rand_len.value);
        g_p1sign_indata = genRandString(p1sign_rand_len);
    }else
	    g_p1sign_indata = mainForm.SignPlainData.value;

	t1 = new Date().getTime();
	
    gPKISvc.SOF_SignData(gsSelectContainer, g_p1sign_indata, function(res){
		t2 = new Date().getTime();
		mainForm.elapse18_1.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			mainForm.p1Signature.value = res.Result.Sign;
			alert("P1签名成功!");
		}else{
			//此处错误码判断，需要4.1.7以上版本
			if(res.ErrorCode == SOR_RsaEncErr || res.ErrorCode == SOR_ECCEncErr)
				alert("P1签名失败，请确认是否登录!");
			else if(res.ErrorCode == SOF_CERT_HASEXPIRED)
				alert("P1签名失败，证书已过期!");
			else if(res.ErrorCode == SOF_CERT_REVOKED)
				alert("P1签名失败，证书已被吊销!");
			else if(res.ErrorCode == SOF_CERT_NOT_TRUSTED)
				alert("P1签名失败，证书不被信任!");
			else if(res.ErrorCode == SOR_IndataErr)
				alert("P1签名失败：原文不是Base64格式!");
			else
				ShowError(res);
		}
    });
}

//18.P1签名验签
function Test_Verify()
{
    var sign_cert = mainForm.signCertOfP1Veirfy.value;
    var plain_data = mainForm.SignPlainData.value;
    var signed_data = mainForm.p1Signature.value;
    var p1sign_rand_data = document.getElementById('p1sign_rand_data');
    
	if(sign_cert.length == 0 || sign_cert == null){
		alert("签名证书为空");
		return;
	}
	
    if(p1sign_rand_data.checked)
        plain_data = g_p1sign_indata;
	    
	t1 = new Date().getTime();
	
    gPKISvc.SOF_VerifySignedData(sign_cert, plain_data, signed_data, function(res){
		t2 = new Date().getTime();
		mainForm.elapse18_2.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("P1验签成功");
		}else
			ShowError(res);
    });
}

function Test_SignHash()
{
    var hashAlg = parseInt(mainForm.p1_hashsign_alg.value);
    var hashData = document.getElementById('p1_hashsign_hash').value;

	mainForm.p1_hashsign_sig.value = '';
	
    if(!CheckUser())
        return;

	t1 = new Date().getTime();
	
    gPKISvc.SOF_Ext_SignHash(gsSelectContainer, hashAlg, hashData, function(res){
		t2 = new Date().getTime();
		mainForm.elapse19.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			mainForm.p1_hashsign_sig.value = res.Result;
			alert("P1哈希签名成功!");
		}else{
			if(res.ErrorCode == SOR_RsaEncErr || res.ErrorCode == SOR_ECCEncErr)
				alert("签名失败，请确认是否登录!");
			else if(res.ErrorCode == SOF_CERT_HASEXPIRED)
				alert("签名失败，证书已过期!");
			else if(res.ErrorCode == SOF_CERT_REVOKED)
				alert("签名失败，证书已被吊销!");
			else if(res.ErrorCode == SOF_CERT_NOT_TRUSTED)
				alert("签名失败，证书不被信任!");
			else if(res.ErrorCode == SOR_IndataErr)
				alert("签名失败：原文不是Base64格式!");
			else
				ShowError(res);
		}
    });
}

function Test_SignMultiHash()
{
    var hashAlg = parseInt(mainForm.p1_hashsign_alg.value);
    var hashData = mainForm.p1_hashdata_multi.value.split('\n');
    
	mainForm.p1_hashsign_sig_multi.value = '';
	
    if(!CheckUser())
        return;

	t1 = new Date().getTime();
	
    gPKISvc.SOF_Ext_SignMultiHash(gsSelectContainer, hashAlg, hashData, function(res){
		t2 = new Date().getTime();
		mainForm.elapse19.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
    		var sigRusult = '';
    
    		for (i = 0; i < res.Result.length; i++)
        		sigRusult += res.Result[i] + '\n';
    		
			mainForm.p1_hashsign_sig_multi.value = sigRusult;

			alert("P1哈希签名成功!");
		}else{
			if(res.ErrorCode == SOR_RsaEncErr || res.ErrorCode == SOR_ECCEncErr)
				alert("签名失败，请确认是否登录!");
			else if(res.ErrorCode == SOF_CERT_HASEXPIRED)
				alert("签名失败，证书已过期!");
			else if(res.ErrorCode == SOF_CERT_REVOKED)
				alert("签名失败，证书已被吊销!");
			else if(res.ErrorCode == SOF_CERT_NOT_TRUSTED)
				alert("签名失败，证书不被信任!");
			else if(res.ErrorCode == SOR_IndataErr)
				alert("签名失败：原文不是Base64格式!");
			else
				ShowError(res);
		}
    });
}

function Test_VerifyHashSign()
{
    var signCert = mainForm.sign_cert.value;
    var hashData = document.getElementById('p1_hashsign_hash').value;
    var signature = mainForm.p1_hashsign_sig.value;

	if(signCert.length == 0 || signCert == null){
		alert("签名证书为空");
		return;
	}
	
	t1 = new Date().getTime();
	
    gPKISvc.SOF_Ext_VerifySignedHash(signCert, hashData, signature, function(res){
		t2 = new Date().getTime();
		mainForm.elapse19.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("P1哈希验签成功");
		}else
			ShowError(res);
    });
}

//20.P1文件验签
function Test_PKCS1_File_Sign()
{
	mainForm.FileSignedValue.value = '';
    if(!CheckUser())
       return;

	var sInFilePath = mainForm.SignInFilePath.value;

	t1 = new Date().getTime();


    gPKISvc.SOF_SignFile(gsSelectContainer, sInFilePath, function(res){
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
    });
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

    gPKISvc.SOF_VerifySignedFile(sign_cert, sInFilePath, sSignedValue64, function(res){
		t2 = new Date().getTime();
		mainForm.elapse20_2.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("P1文件验签成功");
		}else
			ShowError(res);
    });
}

//带时间戳要接口版本1.1.0及以上版本
function SetSignMessageTSPURL()
{
	var ts_url = mainForm.signmsg_ts_url.value;
	
	gPKISvc.SOF_Config(SOF_SET_SIGNMESSAGE_WITH_TSP, mainForm.signmsg_with_ts.checked?1:0, function(res){
		if(res.ErrorCode == SOR_OK){
			if(mainForm.signmsg_with_ts.checked){
				var ts_digest = mainForm.signmsg_ts_digest.value;

				gPKISvc.SOF_Config(SOF_SET_TSP_DIGEST_ALG, ts_digest, function(res){
					if(res.ErrorCode == SOR_OK){
                        if(ts_url.length != 0){
    						gPKISvc.SOF_Config(SOF_SET_TSP_URL, ts_url, function(res){
    							if(res.ErrorCode == SOR_OK){
    								alert("设置成功");
    							}
    							else
    								ShowError(res);
    						});
                        }else{
                            alert("设置成功");
                        }
					}
					else
						ShowError(res);
				});
			}else
				alert("设置成功");
		}else
			ShowError(res);
	});
}

function OnSetSignMessageTSPURL()
{
    gPKISvc.SOF_GetVersion(function(res){
		if(res.ErrorCode == SOR_OK){
         	if(!xs_compare_ver(res.Result.Version, "1.1.0")){
        		alert('您的证书客户端版本太低，需要中间件1.1.0或更高版本！');
        		return;
        	}

            SetSignMessageTSPURL();
		}else
			ShowError(res);
    });
}

function P7SignRandClick()
{
    var p7sign_rand_data = document.getElementById('p7sign_rand_data');

    document.getElementById('signmsg_plain_data').disabled = p7sign_rand_data.checked;
}

var g_p7sign_indata;

//21.P7签名
function Test_SignMessage()
{
    var p7sign_rand_data = document.getElementById('p7sign_rand_data');
    
	mainForm.signed_msg.value = '';
	
    if(!CheckUser())
        return;

    var sign_flag = parseInt(mainForm.sign_flag.value);
    var indata_format = parseInt(mainForm.indata_format.value);
	
	if(indata_format == DATA_FMT_BASE64 && sign_flag == SIGN_FLAG_WITH_ORI){
		alert('带原文不支持Base64格式输入！');
		return;
	}

    if(p7sign_rand_data.checked){
        var p7sign_rand_len = parseInt(mainForm.p7sign_rand_len.value);
        g_p7sign_indata = genRandString(p7sign_rand_len);
    }else
	    g_p7sign_indata = mainForm.signmsg_plain_data.value;
	
	gPKISvc.SOF_SignMessage(sign_flag, gsSelectContainer, g_p7sign_indata, function(res){
		if(res.ErrorCode == SOR_OK){
			t2 = new Date().getTime();
			mainForm.elapse21_1.value = t2 - t1;
			mainForm.signed_msg.value = res.Result.SignData;
			alert("P7签名成功");
		}else{
			//此处错误码判断，需要4.1.7以上版本
			if(res.ErrorCode == SOR_P7SignErr)
				alert("P7签名失败，请确认是否登录!");
			else if(res.ErrorCode == SOF_CERT_HASEXPIRED)
				alert("P7签名失败，证书已过期!");
			else if(res.ErrorCode == SOF_CERT_REVOKED)
				alert("P7签名失败，证书已被吊销!");
			else if(res.ErrorCode == SOF_CERT_NOT_TRUSTED)
				alert("P7签名失败，证书不被信任!");
			else if(res.ErrorCode == SOR_IndataErr)
				alert("P7签名失败：原文不是Base64格式!");
			else if(res.ErrorCode == SOR_TSP_DataErr)
				alert("P7签名失败：时间戳服务器数据错误!");
			else if(res.ErrorCode == SOR_TSP_Err)
				alert("P7签名失败：时间戳服务器错误!");
			else
				ShowError(res);
		}
	});

}

//21.p7验签
function Test_VerifyMessage()
{
    var signed_msg = mainForm.signed_msg.value;
    var plain_data = mainForm.signmsg_plain_data.value;
    var sign_flag = parseInt(mainForm.sign_flag.value);
    var p7sign_rand_data = document.getElementById('p7sign_rand_data');
    
	if(sign_flag == SIGN_FLAG_WITH_ORI)
	    plain_data = null;
	else if(p7sign_rand_data.checked)
        plain_data = g_p7sign_indata;
	
	t1 = new Date().getTime();
	
    gPKISvc.SOF_VerifySignedMessage(signed_msg, plain_data, function(res){
		t2 = new Date().getTime();
		mainForm.elapse21_2.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("P7验签成功");
		}else
			ShowError(res);
    });
}

//21.P7解析签名
function Test_ParseSignMessage()
{
	var signed_msg = mainForm.signed_msg.value;
    var iParseType = parseInt(mainForm.ParseType.value);

	mainForm.SignMsgInfo.value = '';
    
	t1 = new Date().getTime();
	
    gPKISvc.SOF_GetInfoFromSignedMessage(signed_msg, iParseType, function(res){
		t2 = new Date().getTime();
		mainForm.elapse21_3.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
    		if(iParseType == P7_SIGN_TSP_INFO){
        		var value = '';

        		value += 'Version: ' + res.Result.version + '\n';
        		value += 'Policy OID: ' + res.Result.policyId + '\n';
        		value += 'Hash Algorithm: ' + res.Result.hashAlg + '\n';
        		value += 'Serial number: ' + res.Result.sn + '\n';
        		value += 'Time stamp: ' + res.Result.timeStamp + '\n';

			    mainForm.SignMsgInfo.value = value;
    		}
    		else
			    mainForm.SignMsgInfo.value = res.Result.Info;
		}else
			ShowError(res);
    });
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
	
    gPKISvc.SOF_Ext_PKCS7_SignFile(gsSelectContainer, sInFilePath, psignfile_flag, function(res){
		t2 = new Date().getTime();
		mainForm.elapse23_1.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			mainForm.P7SignedValue.value = res.Result.Sign;
			alert("P7文件签名成功");
		}else{
			if(res.ErrorCode == SOR_P7SignErr)
				alert("P7签名失败，请确认是否登录!");
			else if(res.ErrorCode == SOF_CERT_HASEXPIRED)
				alert("P7签名失败，证书已过期!");
			else if(res.ErrorCode == SOF_CERT_REVOKED)
				alert("P7签名失败，证书已被吊销!");
			else if(res.ErrorCode == SOF_CERT_NOT_TRUSTED)
				alert("P7签名失败，证书不被信任!");
			else
				ShowError(res);
		}
    });
}

//23.P7文件验签
function Test_Pkcs7_File_VerifySign()
{
	var signed_msg = mainForm.P7SignedValue.value;
    var sInFilePath = mainForm.P7_SignInFilePath.value;
    var psignfile_flag = parseInt(mainForm.signfile_flag.value);
    
	t1 = new Date().getTime();

    gPKISvc.SOF_Ext_PKCS7_VerifySignedFile(signed_msg, sInFilePath, psignfile_flag, function(res){
		t2 = new Date().getTime();
		mainForm.elapse23_2.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("P7验签成功");
		}else
			ShowError(res);
    });
}

//24.设置加密格式
function Test_SetEnvelopType()
{
	var envType = parseInt(mainForm.EnvType.value);

    gPKISvc.SOF_Ext_SetEnvelopType(envType, function(res){
		if(res.ErrorCode == SOR_OK){
			alert("设置成功");
		}else
			ShowError(res);
    });
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

    gPKISvc.SOF_EncryptData(mainForm.enc_cert.value, sEncryptPlainData, function(res){
		t2 = new Date().getTime();
		mainForm.elapse24_1.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			mainForm.EncryptedData.value=res.Result.EncryptData;
			alert("P7加密成功");
		}else
			ShowError(res);
    });
}

//24.P7解密
function Test_Decrypt()
{
	mainForm.DecryptedData.value = '';
	
	if(!CheckScan()) return;
	
    if(!CheckUser())
        return;
	
	var sEncryptedDataB64 = mainForm.EncryptedData.value;
	
	t1 = new Date().getTime();

    gPKISvc.SOF_DecryptData(gsSelectContainer, sEncryptedDataB64, function(res){
		t2 = new Date().getTime();
		mainForm.elapse24_2.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			mainForm.DecryptedData.value = res.Result.DecryptData;
			
    		alert("解密结束，解密长度: " + get_str_len(res.Result.DecryptData, 3));
		}else{
			//此处错误码判断，需要4.1.7以上版本
			if(res.ErrorCode == SOR_P7DecErr)
				alert("P7解密失败，请确认是否登录!")
			else
				ShowError(res);
		}
    });
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

    gPKISvc.SOF_EncryptFile(sEnc_cert, sInFilePath, sOutFilePath, function(res){
		t2 = new Date().getTime();
		mainForm.elapse26_1.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("P7文件加密成功");
		}else
			ShowError(res);
    });
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

    gPKISvc.SOF_DecryptFile(gsSelectContainer, sInFilePath, sOutFilePath, function(res){
		t2 = new Date().getTime();
		mainForm.elapse26_2.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("P7文件解密成功");
		}else{
			//此处错误码判断，需要4.1.7以上版本
			if(res.ErrorCode == SOR_P7DecErr)
				alert("P7文件解密失败，请确认是否登录!");
			else
				ShowError(res);
		}
    });
}

//27.随机数
function Test_GenRandom()
{
	var genLen = parseInt(mainForm.RandomLen.value);

	mainForm.RandomData.value = '';
	
	t1 = new Date().getTime();

    gPKISvc.SOF_GenRandom(genLen, function(res){
		t2 = new Date().getTime();
		mainForm.elapse27.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			mainForm.RandomData.value = res.Result.RandomData;
		}else
			ShowError(res);
    });
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

    gPKISvc.SOF_Ext_ReadLabel(gsSelectContainer, lable_name, lable_type, function(res){
		t2 = new Date().getTime();
		mainForm.elapse28.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			mainForm.LabelData.value = res.Result.lableData;
			alert("读标签成功");
		}else{
			if(res.ErrorCode == SOR_CertNotFountErr)
				alert("标签不存在");
			else
				ShowError(res);
		}
    });
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

    if(!mainForm.mu_write_base64.checked){
	    alert("写入长度: " + get_str_len(sWriteData, 3));
	    sWriteData = CryptoJSUtil.base64Encode(mainForm.WriteData.value);
    }else{
	    //var dataDecode = CryptoJSUtil.base64Decode(mainForm.WriteData.value);
	    //alert("写入长度: " + get_str_len(dataDecode, 3));
    }
	
	t1 = new Date().getTime();

    gPKISvc.SOF_Ext_WriteUsrDataFile(gsSelectContainer, userpin, nFileType, nFileIndex, nFileOffset, sWriteData, function(res){
		t2 = new Date().getTime();
		mainForm.elapse29_1.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("写入成功");
		}else{
			if(res.ErrorCode == SOR_IndataErr)
				alert("写多用户数据失败：写入数据不是Base64格式");
			else
				ShowError(res);
		}
    });
}

//29.读多用户数据
function Test_Ext_ReadUsrDataFile()
{
	if(!CheckScan()) return;
	
	var nFileType = parseInt(mainForm.FileType.value, 16);
	var nFileIndex = parseInt(mainForm.FileIndex.value, 10);
	var nFileOffset = parseInt(mainForm.FileOffset.value, 10);
	var nReadLen = parseInt(mainForm.ReadLen.value, 10);
	
	t1 = new Date().getTime();

    gPKISvc.SOF_Ext_ReadUsrDataFile(gsSelectContainer, nFileType, nFileIndex, nFileOffset, nReadLen, function(res){
		t2 = new Date().getTime();
		mainForm.elapse29_2.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			mainForm.ReadData.value = res.Result.ReadData;
			try{
    			mainForm.mu_data_hex.value = CryptoJS.enc.Base64.parse(res.Result.ReadData).toString().toUpperCase();
				mainForm.ReadDataBase64DecodeData.value = CryptoJSUtil.base64Decode(res.Result.ReadData);
			}catch(e){
				mainForm.ReadDataBase64DecodeData.value = '';
			}
		}else{
			mainForm.ReadData.value = '';
			mainForm.ReadDataBase64DecodeData.value = '';
			ShowError(res);
		}
    });
}

function onHashAlgSel() {
	var hash_alg = parseInt(mainForm.hash_alg.value, 16);

	if(hash_alg != SGD_SM3){
		document.getElementById('hash_uid').disabled = true;
		document.getElementById('hash_pubkey').disabled = true;
	}else{
		document.getElementById('hash_uid').disabled = false;
		document.getElementById('hash_pubkey').disabled = false;
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

    gPKISvc.SOF_Ext_HashData(hashAlg, inData, inDataFmt, pubKey, uid, function(res){
		t2 = new Date().getTime();
		mainForm.elapse40.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("计算哈希成功");
			mainForm.hash_val.value = res.Result.HashValue;
			mainForm.hash_val_hex.value = CryptoJS.enc.Base64.parse(res.Result.HashValue).toString().toUpperCase();
		}else
			ShowError(res);
    });
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

    gPKISvc.SOF_Ext_HashFile(hashAlg, filepath, pubKey, uid, function(res){
		t2 = new Date().getTime();
		mainForm.elapse40.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("文件哈希成功");
			mainForm.hash_val.value = res.Result.HashValue;
			mainForm.hash_val_hex.value = CryptoJS.enc.Base64.parse(res.Result.HashValue).toString().toUpperCase();
		}else{
			if(res.ErrorCode == SOR_FileErr)
				alert("文件打开错误，请确认输入文件是否存在!")
			else
				ShowError(res);
		}
    });
}

//31.XML签名
function Test_XMLSign()
{
	mainForm.xml_signed.value = '';

    if(!CheckUser())
        return;

	var xml_sign_plain = mainForm.xml_sign_plain.value;
	
	t1 = new Date().getTime();

    gPKISvc.SOF_SignDataXML(gsSelectContainer, xml_sign_plain, function(res){
		t2 = new Date().getTime();
		mainForm.elapse31_1.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			mainForm.xml_signed.value = res.Result.p1Signature;
			alert("XML签名成功");
		}else{
			//此处错误码判断，需要4.1.7以上版本
			if(res.ErrorCode == SOR_RsaEncErr || res.ErrorCode == SOR_ECCEncErr)
				alert("XML签名失败，请确认是否登录!")
			else if(res.ErrorCode == SOF_CERT_HASEXPIRED)
				alert("XML签名失败，证书已过期!");
			else if(res.ErrorCode == SOF_CERT_REVOKED)
				alert("XML签名失败，证书已被吊销!");
			else if(res.ErrorCode == SOF_CERT_NOT_TRUSTED)
				alert("XML签名失败，证书不被信任!");
			else
				ShowError(res);
		}
    });
}

//31.XML验签
function Test_VerifyXMLSign()
{
	var xml_signed = mainForm.xml_signed.value;
	
	t1 = new Date().getTime();

    gPKISvc.SOF_VerifySignedDataXML(xml_signed, function(res){
		t2 = new Date().getTime();
		mainForm.elapse31_2.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("验签成功");
		}else{
			ShowError(res);
		}
    });
}

//31.解析XML签名数据
function Test_ParseXMLSignResult()
{
    var xml_signed = mainForm.xml_signed.value;
    var xml_info_type = parseInt(mainForm.xml_info_type.value);

	mainForm.xml_sign_info.value = '';
    
	t1 = new Date().getTime();

    gPKISvc.SOF_GetXMLSignatureInfo(xml_signed, xml_info_type, function(res){
		t2 = new Date().getTime();
		mainForm.elapse31_3.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			mainForm.xml_sign_info.value = res.Result.Info;
		}else
			ShowError(res);
    });
}

function SetTSPEndpoint()
{
    var endpoint = mainForm.gm_tsp_endpoint.value;

    if(endpoint.length != 0){
		gPKISvc.SOF_Config(SOF_SET_GM_TSP_ENDPOINT, endpoint, function(res){
			if(res.ErrorCode == SOR_OK){
				alert("设置成功");
			}
			else
				ShowError(res);
		});
    }else{
        alert("地址不能为空");
    }
}

function OnSetTSPEndpoint()
{
    gPKISvc.SOF_GetVersion(function(res){
		if(res.ErrorCode == SOR_OK){
         	if(!xs_compare_ver(res.Result.Version, "1.3.0")){
        		alert('您的证书客户端版本太低，需要中间件1.3.0或更高版本！');
        		return;
        	}

            SetTSPEndpoint();
		}else
			ShowError(res);
    });
}

//32.获取时间戳
function Test_Ext_GM_TspGetTime()
{
	$('#gm_tsp_time').val('');
	
	t1 = new Date().getTime();
	
    gPKISvc.SOF_Ext_TspGetTime(function(res){
		t2 = new Date().getTime();
		mainForm.elapse32_1.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			$('#gm_tsp_time').val(res.Result.TimeStamp);
			alert("获取时间戳成功");
		}else
			ShowError(res);
    });
}

//32.加盖时间戳
function Test_Ext_GM_TspSealTimeStamp()
{
	var in_data = mainForm.gm_tsp_in_data.value;
	var algType = parseInt(mainForm.gm_tsp_alg_type.value, 16);
	var codeType = parseInt(mainForm.gm_tsp_indata_code.value);
	
	$('#gm_tsp_timestamp').val('');

	t1 = new Date().getTime();

    gPKISvc.SOF_Ext_TspGetStamp(in_data, algType, function(res){
		t2 = new Date().getTime();
		mainForm.elapse32_2.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			$('#gm_tsp_timestamp').val(res.Result.SealData);
			alert("加盖时间戳成功");
		}else{
			if(codeType == 2 && res.ErrorCode == SOR_IndataErr)
				alert("输入数据错误，必须是base64格式！");
			else
				ShowError(res);
		}
    });
}

//32.验证时间戳
function Test_Ext_GM_TspVerifyTimeStamp()
{
	var gm_tsp_in_data = $('#gm_tsp_in_data').val();
	var gm_tsp_timestamp = $('#gm_tsp_timestamp').val();
	var cert = '';

	$('#gm_tsp_verify_result').val('');

	t1 = new Date().getTime();

    gPKISvc.SOF_Ext_TspVerifyStamp(gm_tsp_in_data, gm_tsp_timestamp, cert, function(res){
		t2 = new Date().getTime();
		mainForm.elapse32_3.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			$('#gm_tsp_verify_result').val(res.Result.TimeStamp);
			alert('验证时间戳成功');
		}else
			ShowError(res);
    });
}

//33.接口控制
function apiControl(obj, ctrl_name, ctrl_cmd)
{
    if(!CheckUser())
        return;
        
	var ctrl_cmd = get_radio_val(ctrl_cmd);

	t1 = new Date().getTime();
	
    gPKISvc.SOF_Ext_Control(gsSelectContainer, ctrl_name, ctrl_cmd, function(res){
		t2 = new Date().getTime();
		mainForm.elapse33.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("设置成功");
		}else
			ShowError(res);
    });
};

function Test_SymmEncrypt()
{
	var symmAlg = parseInt(mainForm.symm_alg.value, 16);
	var symmKey = mainForm.symm_key.value;
	var symmIV = mainForm.symm_iv.value;
	var inData = $('#symm_in').val();

	t1 = new Date().getTime();

    gPKISvc.SOF_Ext_SymmEncrypt(symmAlg, symmKey, symmIV, inData, function(res){
		t2 = new Date().getTime();
		mainForm.elapse42.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
    		mainForm.symm_enc.value = res.Result;
    		mainForm.symm_enc_hex.value = CryptoJS.enc.Base64.parse(res.Result).toString().toUpperCase();
			alert("加密成功");
		}else{
			ShowError(res);
		}
    });
}

function Test_SymmDecrypt()
{
	var symmAlg = parseInt(mainForm.symm_alg.value, 16);
	var symmKey = mainForm.symm_key.value;
	var symmIV = mainForm.symm_iv.value;
	var inData = $('#symm_enc').val();

	t1 = new Date().getTime();

    gPKISvc.SOF_Ext_SymmDecrypt(symmAlg, symmKey, symmIV, inData, function(res){
		t2 = new Date().getTime();
		mainForm.elapse42.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
    		mainForm.symm_dec.value = res.Result;
			alert("解密成功");
		}else{
			ShowError(res);
		}
    });
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

    gPKISvc.SOF_Ext_SymmEncryptFile(symmAlg, symmKey, symmIV, inFilePath, outFilePath, function(res){
		t2 = new Date().getTime();
		mainForm.elapse34_1.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("加密成功");
		}else
			ShowError(res);
    });
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

    gPKISvc.SOF_Ext_SymmDecryptFile(symmAlg, symmKey, symmIV, inFilePath, outFilePath, function(res){
		t2 = new Date().getTime();
		mainForm.elapse34_2.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("解密成功");
		}else
			ShowError(res);
    });
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

    gPKISvc.SOF_Ext_CreateFile(gsSelectContainer, file_name, file_len, readRights, writeRights, function(res){
		t2 = new Date().getTime();
		mainForm.elapse35.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("创建成功");
		}else
			ShowError(res);
    });
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

    gPKISvc.SOF_Ext_EnumFile(gsSelectContainer, function(res){
		t2 = new Date().getTime();
		mainForm.elapse36.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			var FileNames = res.Result.FileNames;
			
		    if(FileNames.length > 0)
				g_file_list = FileNames.split("&&");

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
    });
}

function Test_GetFileAttr()
{
    if(!CheckUser())
       return;
       	
    var t1 = new Date().getTime();

    mainForm.elapse36.value = t2 - t1;
    
    gPKISvc.SOF_Ext_GetFileAttribute(gsSelectContainer, g_select_file_name, function(res){
		t2 = new Date().getTime();
		mainForm.elapse36.value = t2 - t1;
		
		var fileAttr = res.Result.FileAttr;
		
		if(res.ErrorCode == SOR_OK){
			mainForm.file_length.value = fileAttr.fileSize.toString();
			mainForm.file_read_rights.value = fileAttr.readRights.toString();
			mainForm.file_write_rights.value = fileAttr.writeRights.toString();
		}else
			ShowError(res);
    });
}

function Test_ReadFile()
{
	var file_name = mainForm.file_name_wr.value;
	var file_offset = parseInt(mainForm.file_offset.value, 10);
	var file_read_len = parseInt(mainForm.file_read_len.value, 10);
	
    if(!CheckUser())
       return;
       
    var t1 = new Date().getTime();

    gPKISvc.SOF_Ext_ReadFile(gsSelectContainer, file_name, file_offset, file_read_len, function(res){
		t2 = new Date().getTime();
		mainForm.elapse37.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			var fileData = res.Result.FileData;
			
			mainForm.file_read_data.value = fileData;
			mainForm.fdata_hex.value = CryptoJS.enc.Base64.parse(fileData).toString().toUpperCase();
			mainForm.fdata_base64_decode.value = gPKISvc.base64Decode(fileData);
		}else
			ShowError(res);
    });
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

	alert("写入长度: " + get_str_len(write_data, 3));
	
    var t1 = new Date().getTime();

    gPKISvc.SOF_Ext_WriteFile(gsSelectContainer, file_name, file_offset, fw_indata_fmt, write_data, function(res){
		t2 = new Date().getTime();
		mainForm.elapse37.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert('写入成功');
		}else
			ShowError(res);
    });
}

function Test_DeleteFile()
{
	var file_name = mainForm.file_name_wr.value;
	
    if(!CheckUser())
       return;
       
    var t1 = new Date().getTime();

    gPKISvc.SOF_Ext_DeleteFile(gsSelectContainer, file_name, function(res){
		t2 = new Date().getTime();
		mainForm.elapse37.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert('删除成功');
		}else
			ShowError(res);
    });
}

function Test_ExportPublicKey()
{
    if(!CheckUser())
       return;
       
	var keyUsage = parseInt(mainForm.key_usage.value, 10);
       
    var t1 = new Date().getTime();

    gPKISvc.SOF_Ext_ExportPublicKey(gsSelectContainer, keyUsage, function(res){
		t2 = new Date().getTime();
		mainForm.elapse38.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			mainForm.public_key.value = res.Result.pubKey;
			mainForm.pk_hex_str.value = CryptoJS.enc.Base64.parse(res.Result.pubKey).toString().toUpperCase();
		}else
			ShowError(res);
    });
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

    gPKISvc.SOF_Ext_AsymmEncryptData(in_data, pubkey, function(res){
		t2 = new Date().getTime();
		mainForm.elapse39.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			mainForm.asymm_enc_out.value = res.Result.EncryptData;
			alert("加密成功");
		}else
			ShowError(res);
    });
}

function Test_Ext_AsymmDecryptData()
{
    if(!CheckUser())
        return;
        
    var enc_data = mainForm.asymm_enc_out.value; 
    var t1 = new Date().getTime();

    gPKISvc.SOF_Ext_AsymmDecryptData(gsSelectContainer, enc_data, function(res){
		t2 = new Date().getTime();
		mainForm.elapse39.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			mainForm.asymm_dec_out.value = res.Result.DecryptData;
			alert("解密结束，解密长度: " + get_str_len(res.Result.DecryptData, 3));
		}else
			ShowError(res);
    });
}

function Test_EnumSeal(obj)
{
    if(!CheckUser())
        return;

    obj.disabled = true;
    var t1 = new Date().getTime();

    gPKISvc.SOF_Ext_EnumSeal(gsSelectContainer, function(res){
		t2 = new Date().getTime();
		mainForm.elapse40.value = t2 - t1;
		obj.disabled = false;

		if(res.ErrorCode == SOR_OK){
    		mainForm.seal_count.value = res.Result.sealCount;

    		if(res.Result.sealCount == 0)
    		    alert("Ukey中没有印章!");
		}else
			ShowError(res, obj, true);
    });
}

function Test_GetSealInfo()
{
    var seal_index = parseInt(mainForm.seal_index.value);
    var info_type = parseInt(mainForm.seal_info_type.value);
    
    if(!CheckUser())
        return;
        
    var t1 = new Date().getTime();

    gPKISvc.SOF_Ext_GetSeaInfo(gsSelectContainer, seal_index, info_type, function(res){
		t2 = new Date().getTime();
		mainForm.elapse40.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
            if(info_type == SOF_SEAL_BASIC_INFO){
                var sSealInfo = '';
                var sealInfo = res.Result;

                sSealInfo += '印章名称：' +　sealInfo.name + '\n';
                sSealInfo += '印章版本：' +　sealInfo.version + '\n';
                sSealInfo += '印章类型：' +　sealInfo.type + '\n';
                sSealInfo += '印章esID：' +　sealInfo.esID + '\n';
                sSealInfo += '印章ID：' +　sealInfo.id + '\n';
                sSealInfo += '印章vid：' +　sealInfo.vid + '\n';
                sSealInfo += '印章格式：' +　g_seal_format[sealInfo.format] + '\n';
                sSealInfo += '印章尺寸：' +　sealInfo.pic_width +'mm x ' + sealInfo.pic_height + 'mm' + '\n';
                sSealInfo += '图片格式：' +　pic_type_name[sealInfo.pic_type_parse].toUpperCase() + '\n';
                sSealInfo += '图片尺寸：' +　sealInfo.pic_width_pt +'px x ' + sealInfo.pic_height_pt + 'px' + '\n';
                sSealInfo += '印章起始日期：' +　sealInfo.validStart + '\n';
                sSealInfo += '印章终止日期：' +　sealInfo.validEnd + '\n';

                mainForm.seal_info.value = sSealInfo;
                
                document.getElementById("seal_img").src = "data:image/" + pic_type_name[sealInfo.pic_type_parse] + ";base64,"+ sealInfo.pic_data;
            }
            else
                mainForm.seal_info.value = res.Result;
		}else
			ShowError(res);
    });
}

function Test_Base64Encode()
{
    mainForm.base64_enc.value = CryptoJSUtil.base64Encode(mainForm.base64_in.value); 
}

function Test_Base64Decode()
{
    try{
        mainForm.base64_dec.value = CryptoJSUtil.base64Decode(mainForm.base64_enc.value); 
    }catch(e){
        console.log(e.message);
    }
    
    mainForm.base64_dec_hex.value = CryptoJS.enc.Base64.parse(mainForm.base64_enc.value).toString().toUpperCase();
}

function Test_ParseCSR()
{
    var csr = mainForm.csr_data.value; 
    
    var t1 = new Date().getTime();

    gPKISvc.SOF_Ext_ParseCSR(csr, function(res){
		t2 = new Date().getTime();
		mainForm.elapse43.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
            var csrInfo = res.Result;

            mainForm.csr_ver.value = csrInfo.version;
            mainForm.csr_cn.value = csrInfo.dn.cn;
            mainForm.csr_o.value = csrInfo.dn.o;
            mainForm.csr_ou.value = csrInfo.dn.ou;
            mainForm.csr_st.value = csrInfo.dn.st;
            mainForm.csr_l.value = csrInfo.dn.l;
            mainForm.csr_c.value = csrInfo.dn.c;
            mainForm.csr_e.value = csrInfo.dn.e;
            mainForm.csr_alg.value = (csrInfo.alg == 1)?'sm2':'rsa';
            mainForm.csr_pk.value = csrInfo.pubkey;
		}else
			ShowError(res);
    });
}

function Test_GetAdapterInfo(obj)
{
    var params = {};
    
	obj.disabled = true;
	t1 = new Date().getTime();

    gPKISvc.CommonCommand(Command.get_adapter_info, params, function(res){
		t2 = new Date().getTime();
		mainForm.elapse44.value = t2 - t1;
		obj.disabled = false;
		
		if(res.ErrorCode == SOR_OK){
    		var sysInfo = res.Result;

    		mainForm.sysInfo.value = '';

    		for (i = 0; i < sysInfo.length; i++){
        		var ipList = '[';
                ipList += sysInfo[i].ipList.join(', '),
        		ipList += ']';
        		
        		mainForm.sysInfo.value += '网卡名称：' + sysInfo[i].desc + '\n' + 'IP地址：' + ipList + '\n' + 'Mac地址：' + sysInfo[i].mac + '\n\n';
    		}
		}else
			ShowError(res, obj, true);
    });
}

function GetSystemInfo(obj, infoType)
{
    var params = {};
    
	obj.disabled = true;
	t1 = new Date().getTime();

    gPKISvc.CommonCommand(infoType, params, function(res){
		t2 = new Date().getTime();
		mainForm.elapse44.value = t2 - t1;
		obj.disabled = false;
		
    	mainForm.sysInfo.value = '';

		if(res.ErrorCode == SOR_OK){
    		mainForm.sysInfo.value = res.Result;
		}else
			ShowError(res, obj, true);
    });
}

function Test_GetSystemInfo(obj)
{
    var infoType = parseInt(mainForm.sys_info_type.value);

    switch (infoType) 
    {
        case Command.get_adapter_info:
            Test_GetAdapterInfo(obj);
            break;
            
        default:
            GetSystemInfo(obj, infoType);
            break;
    }
}

function Test_GetSealInfoEPoint(obj)
{
	obj.disabled = true;
	t1 = new Date().getTime();

    gPKISvc.SOF_Ext_GetSealInfoEPoint(gsSelectContainer, function(res){
		t2 = new Date().getTime();
		mainForm.elapse45.value = t2 - t1;
		obj.disabled = false;
		
    	mainForm.sealInfoEP.value = '';

		if(res.ErrorCode == SOR_OK){
    		mainForm.sealInfoEP.value = res.Result;
		}else
			ShowError(res, obj, true);
    });
}

function Test_Finalize()
{
    gPKISvc.SOF_Finalize(function(res){
		if(res.ErrorCode == SOR_OK){
			alert("清理成功");
		}else
			ShowError(res);
    });
}

function Test_NestCall()
{
    //枚举证书
	gPKISvc.SOF_GetUserList(function(res){
		if(res.ErrorCode == SOR_OK && res.Status == 1){

    		//解析容器名
            var user = res.Result[0];
            var userInfo = user.split("||");
            var containerName = userInfo[1];

            //导出签名证书
    	    gPKISvc.SOF_ExportUserCert(containerName, function(res){
    			if(res.ErrorCode == SOR_OK){

                    //解析证书信任服务号
                    gPKISvc.SOF_GetCertInfoByOid(res.Result.UserCert, OID_GDCA_TRUST_ID, function(res){
                		
                		if(res.ErrorCode == SOR_OK){
                			var info = gPKISvc.base64Decode(res.Result.Info);
                			
                			var trustId = trimOIDVal(info);

                            //登录
                            var userPin = mainForm.password.value;
                        	
                            gPKISvc.SOF_Login(containerName, userPin, function(res){
                        		if(res.ErrorCode == SOR_OK){
                                    //P1签名
        	                        var plainData = mainForm.SignPlainData.value;
        	
                                    gPKISvc.SOF_SignData(containerName, plainData, function(res){
                                		if(res.ErrorCode == SOR_OK){
                                			alert("P1签名成功!");
                                		}else
                                			ShowError(res);
                                    });
                        		}else
                        			ShowError(res);
                            });
                		}else{
                			mainForm.CertInfo2.value = "";
                			ShowError(res);
                		}
                    });
        			
    			}else
    				ShowError(res);
    	    });
		}else{
			if(res.ErrorCode == SOR_OK && res.Status == 0)
				alert("找不到证书！");
			else
				ShowError(res);
		}
	});
}

