const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync(require('node:path').join(__dirname, '../index.html'), 'utf8');
function setup({ recovery = false, callbackError = false, session = { user: { id: 'test', email: 'agent@example.com', user_metadata: { username: 'agent' } } }, progress, updateError } = {}) {
  let onChange;
  const updates = [];
  const ST = { resetPassword: 'new password', resetPasswordConfirm: 'new password' };
  const context = vm.createContext({ ST, window: {}, document: { getElementById() {} }, console: { error() {} }, render() {}, setTimeout,
    passwordRecovery: recovery, authCallbackError: callbackError,
    normalizeUsername: v => String(v || '').trim().toLowerCase(), validUsername: v => /^[a-z0-9_-]{3,20}$/.test(v),
    loadUserProgress: async () => progress ? progress() : null,
    sb: { auth: {
      getSession: async () => ({ data: { session }, error: null }),
      updateUser: async value => { updates.push(value); return { error: updateError }; },
      onAuthStateChange: fn => { onChange = fn; }
    } }
  });
  vm.runInContext(html.slice(html.indexOf('window.updatePassword ='), html.indexOf('window.logoutUser =')), context);
  vm.runInContext(html.slice(html.indexOf('async function initializeAuth()'), html.indexOf('// ─── CLEAR PROGRESS')), context);
  return { context, ST, updates, event: () => onChange('PASSWORD_RECOVERY', session) };
}
test('recovery callback takes priority over normal startup', async () => {
  const s = setup({ recovery: true });
  await s.context.initializeAuth();
  assert.equal(s.ST.screen, 'reset_password');
});
test('recovery event during profile loading is not overwritten', async () => {
  let release;
  let started;
  const loading = new Promise(resolve => { started = resolve; });
  const s = setup({ progress: () => new Promise(resolve => { release = resolve; started(); }) });
  const startup = s.context.initializeAuth();
  await loading;
  s.event();
  release({ profile: 'pro' });
  await startup;
  assert.equal(s.ST.screen, 'reset_password');
});
test('event before session read completes survives startup', async () => {
  const s = setup();
  const startup = s.context.initializeAuth();
  s.event();
  await startup;
  assert.equal(s.ST.screen, 'reset_password');
});
test('expired recovery session offers a new link', async () => {
  const s = setup({ recovery: true, session: null });
  await s.context.initializeAuth();
  assert.equal(s.ST.screen, 'forgot_password');
  assert.match(s.ST.authError, /expired/);
});
test('callback error offers a new link instead of normal login', async () => {
  const s = setup({ callbackError: true });
  await s.context.initializeAuth();
  assert.equal(s.ST.screen, 'forgot_password');
});
test('successful password update exits recovery and preserves session', async () => {
  const s = setup({ recovery: true });
  await s.context.initializeAuth();
  await s.context.window.updatePassword();
  assert.equal(s.updates[0].password, 'new password');
  assert.equal(s.ST.screen, 'age_select');
  assert.equal(s.ST.resetPassword, '');
});
test('failed password update stays on recovery form without claiming success', async () => {
  const s = setup({ recovery: true, updateError: { message: 'Password rejected' } });
  await s.context.initializeAuth();
  await s.context.window.updatePassword();
  assert.equal(s.ST.screen, 'reset_password');
  assert.equal(s.ST.authLoading, false);
  assert.equal(s.ST.authError, 'Password rejected');
});
