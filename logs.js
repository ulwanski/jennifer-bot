var colors = require('colors');
var moment = require('moment');

// Logs module, Marek Ulwanski <marek@ulwanski.pl>

module.exports = {

   get_time: function(){
      var timestamp = moment().format('YYYY-MM-DD HH:mm:ss');
         return "[".grey + timestamp.grey + "]".grey;
   },

   log: function(msg){
      console.log(this.get_time(), "[message]\t", colors.white(msg));
   },

   debug: function(msg){
      console.log(this.get_time(), "[debug]\t", colors.grey(msg));
   },

   info: function(msg){
      console.log(this.get_time(), "[info]\t", colors.blue(msg));
   },

   success: function(msg){
      console.log(this.get_time(), "[success]\t", colors.green(msg));
   },

   warn: function(msg){
      console.log(this.get_time(), "[warning]\t", colors.yellow(msg));
   },

   error: function(msg){
      console.log(this.get_time(), "[error]\t", colors.red(msg));
   }

};
