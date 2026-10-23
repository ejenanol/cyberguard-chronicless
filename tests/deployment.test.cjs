const {test}=require('node:test');
const assert=require('node:assert/strict');
const config=require('../vercel.json');
test('review branch disables automatic Vercel deployments and publishes only public targets',()=>{
  assert.equal(config.git.deploymentEnabled['feat/phishing-soc-investigation'],false);
  assert.equal(config.git.deploymentEnabled['feat/soc-lab-workspace'],false);
  assert.deepEqual(config.builds.filter(b=>b.use==='@vercel/static').map(b=>b.src),['index.html','assets/**']);
  assert.equal(config.builds.find(b=>b.use==='@vercel/node').src,'api/*.js');
  assert.equal(config.routes.at(-1).status,404);
});
