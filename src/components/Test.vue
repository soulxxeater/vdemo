<template>
  <form name="mainForm" class="container">
    <div class="card">
      <h4 class="card-title">CA证书登录</h4>
      <div class="form-group password-group">
        <label class="pwdtext" for="password">证书密码：</label>
        <input 
          type="password" 
          id="password" 
          v-model="certPassword" 
          size="20"
          @input="validatePassword"
        >
      </div>
      <div class="login-btn-container">
        <button 
          class="btn login-btn" 
          @click="handleLogin"
          :disabled="isLoginDisabled"
        >
          {{ isLoading ? '登录中...' : '登录' }}
        </button>
      </div>
    </div>
    <div id="dev_evt" class="error-msg" v-text="errorMsg"></div>
</form>
</template>

<script>
export default {
  name: 'CaCertLogin',
  data() {
    return {
      certPassword: '123456', // 测试默认密码
      isLoading: false,
      isLoginDisabled: false,
      errorMsg: ''
    }
  },
  mounted() {
    // 验证依赖库加载（GDCA核心库需全局引入）
    if (!window.GDCAPKIService) {
      this.errorMsg = 'CA证书核心库加载失败，请检查文件路径'
    }
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
  },
  methods: {
    validatePassword() {
      this.errorMsg = ''
      this.isLoginDisabled = this.certPassword.trim().length < 6 // 密码长度校验
    },
    async handleLogin() {
      if (this.isLoginDisabled) return
      
      this.isLoading = true
      this.isLoginDisabled = true
      try {
        // 1. 调用GDCA库验证证书密码（需结合实际库API调整）
        console.log('aaaa',gPKISvc)
        const certValid = await window.GDCAPKIService.verifyCertPassword(this.certPassword)
        if (!certValid) throw new Error('证书密码验证失败')
        
        // 2. 密码验证通过后执行登录请求
        const loginRes = await this.$axios.post('/api/login/cert', {
          certInfo: window.GDCAPKIService.getCertInfo(), // 获取证书信息
          password: this.certPassword
        })
        
        if (loginRes.data.success) {
          // 3. 登录成功跳转（示例逻辑）
          this.$router.push('/home')
        } else {
          throw new Error(loginRes.data.msg || '登录失败')
        }
      } catch (err) {
        this.errorMsg = err.message
      } finally {
        this.isLoading = false
        this.isLoginDisabled = false
      }
    }
  }
}
</script>

<style scoped>
.container {
  max-width: 400px;
  margin: 0 auto;
  padding: 20px;
}
.card {
  background: #fff;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0,0,0,0.1);
  padding: 25px;
  margin-bottom: 30px;
  height: 340px;
}
.card-title {
  font-size: 18px;
  color: #2c3e50;
  border-bottom: 1px solid #eee;
  padding-bottom: 10px;
  margin: 0 0 20px;
}
.password-group {
  margin-top: 80px;
  text-align: center;
}
.pwdtext {
  color: #333;
  font-weight: bold;
  margin-right: 15px;
}
#password {
  width: 250px;
  padding: 6px 8px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 14px;
}
.login-btn-container {
  text-align: center;
  margin-top: 25px;
}
.btn {
  padding: 6px 15px;
  background: #3498db;
  color: #fff;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  transition: background 0.3s;
}
.login-btn {
  padding: 8px 25px;
  background: #2ecc71;
  font-size: 16px;
}
.login-btn:hover:not(:disabled) {
  background: #27ae60;
}
.btn:disabled {
  background: #bdc3c7;
  cursor: not-allowed;
}
.error-msg {
  color: #e74c3c;
  text-align: center;
  margin-top: 15px;
  font-size: 14px;
}
</style>
