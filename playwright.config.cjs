const {defineConfig}=require('@playwright/test');
module.exports=defineConfig({
  testDir:'./tests/browser',workers:1,timeout:45000,
  use:{baseURL:'http://127.0.0.1:3100',headless:true,launchOptions:{executablePath:process.env.CHROMIUM_PATH||(require('node:fs').existsSync('/usr/bin/chromium')?'/usr/bin/chromium':undefined),args:['--no-sandbox']},trace:'retain-on-failure'},
  webServer:{command:'node tests/support/browser-server.cjs',url:'http://127.0.0.1:3100',reuseExistingServer:false,timeout:30000}
});
