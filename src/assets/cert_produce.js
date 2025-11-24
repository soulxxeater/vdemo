var gsSelectUser = '';
var gsSelectContainer = '';
var gUserList = [];
var g_DeviceInfoList = [];
var g_curDevName = '';
var gIsLogin = false;
var t1;
var t2;
var g_api_ver = '';
var g_timer_get_ver = '';
var g_enum_flags = 0;


function ClearListBox(obj_id) {
	$('#'+obj_id).html('');
}

var onPKIServiceNotify = function(event, arg){
    if(event == WUEvent.connect && arg){
    }else if(event == WUEvent.connect && !arg){
        alert('gdca_web_service服务未启动!');
    }else if(event == WUEvent.closed)
        alert('gdca_web_service连接已断开!');
};

window.onload=function(){
	mainForm.api_version.value = "";

    gdcaPKISvcEx.init(PROTO_AUTO, onPKIServiceNotify);
};

function timerCheckGetVer() {
	if(g_api_ver != ''){
		clearInterval(g_timer_get_ver);
		if(!xs_compare_ver(g_api_ver, "1.1.3")){
			alert('您的证书客户端版本太低，需要4.2.1或更高版本！');
		}
	}
}

function ShowError(e, obj, locked)
{
    //出错后需要释放锁
    if(locked != undefined && locked)
        gdcaPKISvcEx.SOF_Ext_UnLockDevice(gsSelectContainer, function(r){});

    if(obj != undefined)
        obj.disabled = false;
    
    if(e.ErrorMsg != undefined){
        alert("\n错误信息：" + e.ErrorMsg + "\n错误代码：0x" + e.ErrorCode.toString(16).toUpperCase() + " (" + gdcaPKISvcEx.SOF_GetErrMsg(e.ErrorCode) + ")");
    }
    else
        alert("Exception:\n" + e.ErrorMsg);
}

function OnCertSelected()
{
    gsSelectUser = "";
    gsSelectContainer = "";
    
    var Index = mainForm.UserList.options.selectedIndex;

    var sUser = gUserList[Index];

    var UserInfo = sUser.split("||");
    
    gsSelectUser = UserInfo[0];
    gsSelectContainer = UserInfo[1];
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

//获取接口版本号
function Test_GetVersion(obj)
{
	mainForm.api_version.value = '';
	
    if(obj != undefined)
        obj.disabled = true;

	t1 = new Date().getTime();
	
    gdcaPKISvcEx.SOF_GetVersion(function(res){
		t2 = new Date().getTime();

        if(obj != undefined)
            obj.disabled = false;
        	
		mainForm.elapse1.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			mainForm.api_version.value = res.Result.Version;
			g_api_ver = res.Result.Version;
		}else
			ShowError(res, obj, false);
    });
}

function Test_EnumCert(obj)
{
	document.getElementById("UserList").options.length = 0; 

    if(obj != undefined)
        obj.disabled = true;

	t1 = new Date().getTime();

    gdcaPKISvcEx.SOF_Config(SOF_SET_ENUM_NULL_CONTAINER, 1, function(res){
		if(res.ErrorCode == SOR_OK){
        	gdcaPKISvcEx.SOF_GetUserList(function(res){
        		t2 = new Date().getTime();

        		if(obj != undefined)
                    obj.disabled = false;
                
        		if(res.ErrorCode == SOR_OK && res.Status == 1){
        			
        			gUserList =	res.Result;
        			for (i = 0; i < res.Result.length; i++)
        	            mainForm.UserList.options.add(new Option(res.Result[i]), i);
        		
        			mainForm.UserList.options[0].selected=true;
        			
        			OnCertSelected();	
        		}else{
        			if(res.ErrorCode == SOR_OK && res.Status == 0)
        				alert("找不到证书！");
        			else
        				ShowError(res, obj, false);
        		}
        		
        		mainForm.elapse3.value = t2 - t1;
        	});
		}else
			ShowError(res, obj, false);
    });
}

function Test_ExternalAuth(obj)
{
    var authKey = mainForm.auth_key.value;

    gdcaPKISvcEx.SOF_Ext_ExternalAuth(gsSelectContainer, 1, authKey, function(res){
        if(res.ErrorCode == SOR_OK){
            alert('认证通过!');
        }else
    		ShowError(res, obj, true);
    });
}

function Test_FormatDevice(obj)
{
    obj.disabled = true;
    
    if (!confirm("格式化将清除ukey内所有数据，确认进行此操作吗！")) {
        obj.disabled = false;
        return;
    }

    var appName = mainForm.app_name.value;
    var superPin = mainForm.super_pin.value;
    var superPinRetryCount = parseInt(mainForm.super_pin_retry_count.value);
    var userPin = mainForm.user_pin.value;
    var userPinRetryCount = parseInt(mainForm.user_pin_retry_count.value);

    t1 = new Date().getTime();

    //耗时长的操作务必通过加锁来保证不被其它进程干扰
    gdcaPKISvcEx.SOF_Ext_LockDevice(gsSelectContainer, function(res){
		//格式化Token
		if(res.ErrorCode == SOR_OK){
    		var params = {};

    		params.appName = appName;
    		params.superPIN = superPin;
    		params.adminPinRetryCount = superPinRetryCount;
    		params.userPIN = userPin;
    		params.userPinRetryCount = userPinRetryCount;
    		params.createFileRights = SECURE_EVERYONE_ACCOUNT;

            gdcaPKISvcEx.SOF_Ext_FormatDevice(gsSelectContainer, FORMAT_SKF, params, function(res){
        		if(res.ErrorCode == SOR_OK){
            		gdcaPKISvcEx.SOF_Ext_UnLockDevice(gsSelectContainer, function(r){
                        t2 = new Date().getTime();
                        mainForm.elapse3.value = t2 - t1;
                		
                		alert('格式化成功!');
                		//格式化后需要更新容器名
                		gsSelectContainer = res.Result.containerName;
                		obj.disabled = false;
            		});
        		}else
        			ShowError(res, obj, true);
            });
		}else
			ShowError(res, obj, true);
    });
}

//用户登录
function Test_Login(obj)
{
    if(!CheckUser())
       return;
       
    var pin = mainForm.pin.value;
        
	t1 = new Date().getTime();
	
    gdcaPKISvcEx.SOF_Login(gsSelectContainer, pin, function(res){
		t2 = new Date().getTime();
		mainForm.elapse4.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			alert("登录成功");
		}else
			ShowError(res, obj, false);
    });
}

function Test_GenKeyPair(obj)
{
    var keyAlg = parseInt(mainForm.keypair_alg.value);
	obj.disabled = true;
	t1 = new Date().getTime();

    gdcaPKISvcEx.SOF_Ext_LockDevice(gsSelectContainer, function(res){
        gdcaPKISvcEx.SOF_Ext_GenKeyPair(gsSelectContainer, keyAlg, function(res){
    		t2 = new Date().getTime();
    		mainForm.elapse5.value = t2 - t1;
    		obj.disabled = false;
    		
    		if(res.ErrorCode == SOR_OK){
        		gdcaPKISvcEx.SOF_Ext_UnLockDevice(gsSelectContainer, function(r){
            		mainForm.sign_pk.value = res.Result.signPubkey;
            		//生成密钥对后容器就存在了，所以要更新容器名，后续都基于新的容器名进行操作
            		gsSelectContainer = res.Result.containerName;
        		});
    		}else
    			ShowError(res, obj, true);
        });
    });
}

function Test_GenCSR(obj)
{
	var dn = {};

    dn.cn = mainForm.cert_cn.value;
    dn.o = mainForm.cert_o.value;
    dn.ou = mainForm.cert_ou.value;
    dn.s = mainForm.cert_s.value;
    dn.l = mainForm.cert_l.value;
    dn.c = mainForm.cert_c.value;
    dn.e = mainForm.cert_e.value;

    gdcaPKISvcEx.SOF_Ext_GenCSR(gsSelectContainer, dn, function(res){
		t2 = new Date().getTime();
		obj.disabled = false;
		mainForm.elapse6.value = t2 - t1;
		
		if(res.ErrorCode == SOR_OK){
			mainForm.csr.value = res.Result;
		}else
			ShowError(res, obj, false);
    });
}

function Test_ImportKeyPair(obj)
{
    var kmType = 45;
    var keyPair = mainForm.cryptPrivKey.value;
    
	obj.disabled = true;
	t1 = new Date().getTime();

    gdcaPKISvcEx.SOF_Ext_LockDevice(gsSelectContainer, function(res){
        gdcaPKISvcEx.SOF_Ext_ImportKeyPair(gsSelectContainer, kmType, keyPair, function(res){
    		t2 = new Date().getTime();
    		mainForm.elapse7.value = t2 - t1;
    		obj.disabled = false;
    		
    		if(res.ErrorCode == SOR_OK){
        		gdcaPKISvcEx.SOF_Ext_UnLockDevice(gsSelectContainer, function(r){
        		    alert('导入成功');
        		});
    		}else
    			ShowError(res, obj, true);
        });
    });
}

function Test_ImportSignCert(obj)
{
    var cert = mainForm.signCert.value;
	obj.disabled = true;
	t1 = new Date().getTime();

    gdcaPKISvcEx.SOF_Ext_ImportCert(gsSelectContainer, CERT_TYPE_SIGN, cert, function(res){
		t2 = new Date().getTime();
		mainForm.elapse8.value = t2 - t1;
		obj.disabled = false;
		
		if(res.ErrorCode == SOR_OK){
    		alert('导入成功');
		}else
			ShowError(res, obj, false);
    });
}

function Test_ImportEncCert(obj)
{
    var cert = mainForm.encryptCert.value;
	obj.disabled = true;
	t1 = new Date().getTime();

    gdcaPKISvcEx.SOF_Ext_ImportCert(gsSelectContainer, CERT_TYPE_ENCRYPT, cert, function(res){
		t2 = new Date().getTime();
		mainForm.elapse8.value = t2 - t1;
		obj.disabled = false;
		
		if(res.ErrorCode == SOR_OK){
    		alert('导入成功');
		}else
			ShowError(res, obj, false);
    });
}

