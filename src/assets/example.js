// 示例外部JS文件
export function greet(name) {
  return `Hello, ${name}!`;
}

export function calculateSum(a, b) {
  return a + b;
}

export function getCurrentTime() {
  return new Date().toLocaleString();
}

// 默认导出一个对象
export default {
  greet,
  calculateSum,
  getCurrentTime
};