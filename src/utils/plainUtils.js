// 这是一个没有export语句的普通JS文件
// 定义一些变量和函数

var appName = "My Vue App";

function showMessage(message) {
  console.log("Message from utils:", message);
  return message;
}

function calculateArea(width, height) {
  return width * height;
}

// 立即执行函数，设置一些全局变量或执行初始化操作
(function() {
  window.APP_VERSION = "1.0.0";
  console.log("Utils loaded - Version: " + window.APP_VERSION);
})();

// 添加到window对象，使其成为全局可用
window.appName = appName;
window.showMessage = showMessage;
window.calculateArea = calculateArea;

console.log("Plain JS file loaded successfully");