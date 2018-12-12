// var compiler = new Object();
// compiler.compile = function (source, optimize) {
//   var result = null;
//   BrowserSolc.loadSolcJson('./soljson_v2.0.js', function (compiler) {
//     result = compiler.compile(source, optimize);
//   })
//   return result;
// };
var compiler = new Object();
compiler.compile = function (source, optimize) {
  var solc = require(['solc/wrapper']);
  var comp = solc(undefined);
  var result = null;
  //result = comp.compile(source, optimize);
  return solc;
};