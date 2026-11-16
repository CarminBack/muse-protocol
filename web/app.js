const $ = (id) => document.getElementById(id);
let poller;

async function api(path, options = {}) {
  const response = await fetch(path, { headers: { 'Content-Type': 'application/json' }, ...options });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `请求失败 (${response.status})`);
  return data;
}

function setMessage(text, kind = '') {
  const el = $('action-message');
  el.textContent = text;
  el.className = `message ${kind}`;
}

function formConfig() {
  return {
    email: $('email').value.trim(), proxy: $('proxy').value.trim(),
    first_name: $('first-name').value.trim(), last_name: $('last-name').value.trim(),
    date_of_birth: $('dob').value, invite_code: $('invite').value.trim(),
    lang: 'ja', impersonate: 'chrome142', send_caa: false, send_falco: false
  };
}

function renderConfig(data) {
  for (const [id, key] of [['email','email'],['first-name','first_name'],['last-name','last_name'],['dob','date_of_birth'],['invite','invite_code']]) {
    if (data[key] !== undefined) $(id).value = data[key] || '';
  }
}

function renderStatus(data) {
  const status = data.status || 'idle';
  const labels = { idle:'空闲', starting:'启动中', running:'运行中', waiting_otp:'等待验证码', stopping:'停止中', succeeded:'已完成', failed:'失败' };
  const badge = $('status-badge');
  badge.className = `status ${status}`;
  badge.innerHTML = `<span></span> ${labels[status] || status}`;
  $('run-label').textContent = (labels[status] || status).toUpperCase();
  $('start-button').disabled = ['starting','running','waiting_otp','stopping'].includes(status);
  $('stop-button').disabled = !['starting','running','waiting_otp'].includes(status);
  $('otp-panel').hidden = status !== 'waiting_otp';
  if (data.logs?.length) {
    $('logs').textContent = data.logs.join('\n');
    $('logs').scrollTop = $('logs').scrollHeight;
    $('log-count').textContent = `${data.logs.length} LINES`;
  }
}

async function refresh() {
  try { renderStatus(await api('/api/status')); } catch (error) { setMessage(error.message, 'error'); }
}

async function showApp() {
  $('login-view').hidden = true;
  $('app-view').hidden = false;
  try { renderConfig(await api('/api/config')); } catch (error) { setMessage(error.message, 'error'); }
  await refresh();
  clearInterval(poller); poller = setInterval(refresh, 1200);
}

$('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('login-error').textContent = '';
  try { await api('/api/login', { method:'POST', body:JSON.stringify({ password:$('login-password').value }) }); await showApp(); }
  catch (error) { $('login-error').textContent = error.message; }
});

$('config-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try { renderConfig(await api('/api/config', { method:'POST', body:JSON.stringify(formConfig()) })); setMessage('配置已保存到服务器', 'success'); }
  catch (error) { setMessage(error.message, 'error'); }
});

$('start-button').addEventListener('click', async () => {
  try { await api('/api/start', { method:'POST', body:'{}' }); setMessage('任务已启动，请等待邮箱验证码', 'success'); await refresh(); }
  catch (error) { setMessage(error.message, 'error'); }
});

$('otp-button').addEventListener('click', async () => {
  try { await api('/api/otp', { method:'POST', body:JSON.stringify({ code:$('otp').value }) }); $('otp').value = ''; setMessage('验证码已提交，正在继续', 'success'); await refresh(); }
  catch (error) { setMessage(error.message, 'error'); }
});

$('stop-button').addEventListener('click', async () => {
  if (!window.confirm('确定停止当前任务吗？')) return;
  try { await api('/api/stop', { method:'POST', body:'{}' }); setMessage('已请求停止任务'); await refresh(); }
  catch (error) { setMessage(error.message, 'error'); }
});

api('/api/session').then((data) => { if (data.authenticated) showApp(); });
