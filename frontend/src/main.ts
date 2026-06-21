import { SSHTerminal } from './terminal';
import { ConnectionForm } from './auth-form';
import { ServerList } from './server-list';

// ==================== 全局状态 ====================

const terminal = new SSHTerminal('terminal-container');
let connectionForm: ConnectionForm | null = null;
let serverList: ServerList | null = null;
let isLoggedIn = false;

// ==================== 页面切换 ====================

function showAuthSection(): void {
  document.getElementById('auth-section')!.classList.remove('hidden');
  document.getElementById('user-space-section')!.classList.add('hidden');
  document.getElementById('user-space-section')!.classList.remove('flex');
  document.getElementById('terminal-section')!.classList.add('hidden');
  document.getElementById('terminal-section')!.classList.remove('flex');
  document.getElementById('server-modal')!.classList.add('hidden');
  document.getElementById('server-modal')!.classList.remove('flex');

  if (!connectionForm) {
    connectionForm = new ConnectionForm(terminal);
  }
}

function showUserSpace(user: { id: number; github_id: number; username: string; avatar_url: string }): void {
  isLoggedIn = true;
  document.getElementById('auth-section')!.classList.add('hidden');
  document.getElementById('user-space-section')!.classList.remove('hidden');
  document.getElementById('user-space-section')!.classList.add('flex');
  document.getElementById('terminal-section')!.classList.add('hidden');
  document.getElementById('terminal-section')!.classList.remove('flex');

  serverList = new ServerList(
    user,
    // onConnect 回调
    (wsUrl: string, serverName: string) => {
      showTerminalFromServer(wsUrl, serverName);
    },
    // onLogout 回调
    () => {
      isLoggedIn = false;
      serverList = null;
      showAuthSection();
    }
  );
}

function showTerminalFromServer(wsUrl: string, serverName: string): void {
  document.getElementById('auth-section')!.classList.add('hidden');
  document.getElementById('user-space-section')!.classList.add('hidden');
  document.getElementById('user-space-section')!.classList.remove('flex');
  document.getElementById('terminal-section')!.classList.remove('hidden');
  document.getElementById('terminal-section')!.classList.add('flex');

  // 更新终端状态栏
  document.getElementById('term-host')!.textContent = `Server: ${serverName}`;
  document.getElementById('term-user')!.textContent = '';
  document.getElementById('term-port')!.textContent = '';

  terminal.mount();

  // 通过 wsUrl（含 one-time-token）建立连接
  const ws = new WebSocket(wsUrl);
  terminal.connectWithWebSocket(ws);
}

// ==================== 断开连接处理 ====================

document.getElementById('disconnect-btn')?.addEventListener('click', () => {
  terminal.disconnect();
  const termSection = document.getElementById('terminal-section')!;
  termSection.classList.add('hidden');
  termSection.classList.remove('flex');

  if (isLoggedIn) {
    // 已登录用户回到用户空间
    document.getElementById('user-space-section')!.classList.remove('hidden');
    document.getElementById('user-space-section')!.classList.add('flex');
  } else {
    // 匿名用户回到连接表单
    document.getElementById('auth-section')!.classList.remove('hidden');
  }

  document.getElementById('status-text')!.innerHTML = '<span class="w-2 h-2 bg-[#353534] inline-block"></span> STATUS: OFFLINE';
});

// ==================== 主题切换 ====================

document.getElementById('theme-selector')?.addEventListener('change', (e) => {
  const theme = (e.target as HTMLSelectElement).value as any;
  terminal.setTheme(theme);
});

// ==================== 初始化 ====================

async function init(): Promise<void> {
  // 设置版权年份
  const copyrightYearSpan = document.getElementById('copyright-year');
  if (copyrightYearSpan) {
    copyrightYearSpan.textContent = new Date().getFullYear().toString();
  }

  try {
    // 检查是否已登录
    const meRes = await fetch('/api/auth/me');
    if (meRes.ok) {
      const user = await meRes.json();
      showUserSpace(user);
      return;
    }
  } catch {
    // /api/auth/me 失败，继续显示匿名连接表单
  }

  // 未登录 → 显示匿名连接表单
  showAuthSection();
}

init();
