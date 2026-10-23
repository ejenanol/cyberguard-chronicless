const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const html = fs.readFileSync(require('node:path').join(__dirname, '../index.html'), 'utf8');
function setup({ error, fetchResponse, inputs = {} } = {}) {
  const calls = [];
  const ST = { loginIdentifier: 'agent@example.com', loginPassword: 'test password', authLoading: false };
  const context = vm.createContext({
    ST, window: {}, console: { error() {} }, render() {},
    document: { getElementById: id => inputs[id] },
    validUsername: value => /^[a-z0-9_-]{3,20}$/i.test(value),
    normalizeUsername: value => value.trim().toLowerCase(),
    fetch: async () => fetchResponse,
    sb: { auth: { signInWithPassword: async credentials => {
      calls.push(credentials);
      return { data: { user: { id: 'test-user', email: credentials.email } }, error };
    } } },
    initializeAuth: async () => { ST.authLoading = false; ST.screen = 'age_select'; }
  });
  vm.runInContext(html.slice(html.indexOf('function loginErrorMessage'), html.indexOf('window.signUpUser')), context);
  vm.runInContext(html.slice(html.indexOf('window.loginUser ='), html.indexOf('window.sendPasswordReset')), context);
  return { context, ST, calls };
}

test('reads autofilled credentials before render and normalizes email', async () => {
  const { context, ST, calls } = setup({ inputs: {
    'login-identifier': { value: ' Agent@Example.com ' },
    'login-password': { value: ' autofilled password ' }
  } });
  await context.window.loginUser();
  assert.equal(calls[0].email, 'agent@example.com');
  assert.equal(calls[0].password, ' autofilled password ');
  assert.equal(ST.loginPassword, '');
  assert.equal(ST.screen, 'age_select');
});

for (const [name, error, expected] of [
  ['credentials', { code: 'invalid_credentials' }, /Invalid email\/username or password/],
  ['legacy credentials', { message: 'Invalid login credentials' }, /Invalid email\/username or password/],
  ['confirmation', { code: 'email_not_confirmed' }, /Confirm your email/],
  ['legacy confirmation', { message: 'Email not confirmed' }, /Confirm your email/],
  ['rate limit', { status: 429 }, /Too many sign-in attempts/],
  ['network', { message: 'Failed to fetch' }, /Check your connection/],
  ['server', { status: 500, message: 'private internal details' }, /Check your connection/]
]) {
  test(`sign-in reports ${name} safely and releases loading state`, async () => {
    const { context, ST } = setup({ error });
    await context.window.loginUser();
    assert.match(ST.authError, expected);
    assert.equal(ST.authLoading, false);
  });
}

for (const [status, expected] of [[401, /Invalid email\/username or password/], [500, /Check your connection/], [429, /Too many/]]) {
  test(`username lookup status ${status} is classified correctly`, async () => {
    const { context, ST, calls } = setup({ fetchResponse: { ok: false, status } });
    ST.loginIdentifier = 'cyberagent';
    await context.window.loginUser();
    assert.match(ST.authError, expected);
    assert.equal(calls.length, 0);
  });
}

test('duplicate submissions do not call auth', async () => {
  const { context, ST, calls } = setup();
  ST.authLoading = true;
  await context.window.loginUser();
  assert.equal(calls.length, 0);
});
