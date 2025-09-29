// activity_tracer.js
// Simple activity lifecycle tracer for authorized testing
Java.perform(function() {
  try {
    var Activity = Java.use('android.app.Activity');
    Activity.onResume.overload().implementation = function() {
      var name = this.getClass().getName();
      console.log('[FRIDA] Activity.onResume -> ' + name);
      return this.onResume();
    };
    Activity.onPause.overload().implementation = function() {
      var name = this.getClass().getName();
      console.log('[FRIDA] Activity.onPause -> ' + name);
      return this.onPause();
    };
  } catch (e) {
    console.log('[FRIDA] error: ' + e);
  }
});
