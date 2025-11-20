<template>
  <div class="plain-js-example">
    <h2>Plain JS Usage Examples</h2>
    <div>
      <h3>Results:</h3>
      <ul>
        <li>Global variable APP_VERSION: {{ appVersion }}</li>
        <li>Window property appName: {{ windowAppName }}</li>
        <li>Show Message Result: {{ showMessageResult }}</li>
        <li>Calculate Area Result: {{ calculateAreaResult }}</li>
      </ul>
    </div>
  </div>
</template>

<script>
// 方式1: 直接引入，会执行文件中的代码
import '@/utils/plainUtils.js';

export default {
  name: 'PlainJSExample',
  data() {
    return {
      appVersion: '',
      windowAppName: '',
      showMessageResult: '',
      calculateAreaResult: 0
    };
  },
  mounted() {
    // 方式2: 访问挂载到window对象上的属性和方法
    this.appVersion = window.APP_VERSION || 'Not available';
    this.windowAppName = window.appName || 'Not available';
    
    // 调用挂载到window对象上的函数
    if (typeof window.showMessage === 'function') {
      this.showMessageResult = window.showMessage('Hello from plain JS!');
    }
    
    if (typeof window.calculateArea === 'function') {
      this.calculateAreaResult = window.calculateArea(10, 5);
    }
    
    // 打印结果到控制台
    console.log('APP_VERSION from global:', this.appVersion);
    console.log('appName from window:', this.windowAppName);
    console.log('Show message result:', this.showMessageResult);
    console.log('Calculate area result:', this.calculateAreaResult);
  }
};
</script>

<style scoped>
.plain-js-example {
  margin: 20px;
  padding: 20px;
  border: 1px solid #ccc;
  border-radius: 5px;
}
</style>