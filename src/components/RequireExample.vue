<template>
  <div class="require-example">
    <h2>Require-based Usage Example</h2>
    <button @click="loadAndUsePlainJS">Load and Use Plain JS</button>
    <div v-if="loaded">
      <h3>Results:</h3>
      <ul>
        <li>APP_VERSION: {{ appVersion }}</li>
        <li>appName: {{ appName }}</li>
        <li>Multiplication Result (6 × 7): {{ multiplicationResult }}</li>
      </ul>
    </div>
  </div>
</template>

<script>
export default {
  name: 'RequireExample',
  data() {
    return {
      loaded: false,
      appVersion: '',
      appName: '',
      multiplicationResult: 0
    };
  },
  methods: {
    loadAndUsePlainJS() {
      // 方式3: 使用require动态引入
      require('@/utils/plainUtils.js');
      
      // 使用引入后可用的全局变量和函数
      this.appVersion = window.APP_VERSION || 'Not available';
      
      if (window.appName) {
        this.appName = window.appName;
      }
      
      // 添加一个额外的函数来演示扩展性
      if (!window.multiply) {
        window.multiply = function(a, b) {
          return a * b;
        };
      }
      
      this.multiplicationResult = window.multiply(6, 7);
      this.loaded = true;
      
      // 打印结果到控制台
      console.log('Loaded using require method');
      console.log('APP_VERSION:', this.appVersion);
      console.log('appName:', this.appName);
      console.log('Multiplication result:', this.multiplicationResult);
    }
  }
};
</script>

<style scoped>
.require-example {
  margin: 20px;
  padding: 20px;
  border: 1px solid #42b983;
  border-radius: 5px;
}

button {
  padding: 10px 15px;
  background-color: #42b983;
  color: white;
  border: none;
  border-radius: 3px;
  cursor: pointer;
}

button:hover {
  background-color: #369870;
}
</style>