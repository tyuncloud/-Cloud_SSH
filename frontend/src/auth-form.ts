import { loadKnownFingerprint } from './terminal';
import type { TabManager } from './tab-manager';
import { populateRegionSelect } from './regions';

// ==================== Credential Encryption ====================

async function deriveKey(salt: Uint8Array): Promise<CryptoKey> {
  const raw = new TextEncoder().encode(
    `${window.location.origin}:cloudssh`
  );

  const baseKey = await crypto.subtle.importKey(
    'raw',
    raw,
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations: 100000,
      hash: 'SHA-256',
    },
    baseKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptCredentials(data: object): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(salt);

  const encoded = new TextEncoder().encode(JSON.stringify(data));

  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
      },
      key,
      encoded
    )
  );

  const combined = new Uint8Array(
    salt.length + iv.length + encrypted.length
  );

  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(encrypted, salt.length + iv.length);

  let binary = '';

  for (let index = 0; index < combined.length; index += 1) {
    binary += String.fromCharCode(combined[index]);
  }

  return btoa(binary);
}

interface StoredCredentials {
  host: string;
  port: string;
  username: string;
  password: string;
  privateKey?: string;
  authMethod?: string;
}

async function decryptCredentials(
  stored: string
): Promise<StoredCredentials | null> {
  try {
    const raw = Uint8Array.from(
      atob(stored),
      character => character.charCodeAt(0)
    );

    const salt = raw.slice(0, 16);
    const iv = raw.slice(16, 28);
    const data = raw.slice(28);
    const key = await deriveKey(salt);

    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv,
      },
      key,
      data
    );

    return JSON.parse(
      new TextDecoder().decode(decrypted)
    ) as StoredCredentials;
  } catch {
    return null;
  }
}

// ==================== Types ====================

export interface ConnectionFormOptions {
  getTabManager: () => TabManager;
}

interface RecentConnection {
  id: string;
  host: string;
  port: number;
  username: string;
  authMethod: 'password' | 'publickey';
  timestamp: number;
  encryptedCred?: string;
  region?: string;
}

// ==================== Connection Form ====================

export class ConnectionForm {
  private options: ConnectionFormOptions;

  private turnstileEnabled = false;

  private turnstileVerified = false;

  private turnstileWidgetId: string | null = null;

  private turnstileSitekey = '';

  private authMode: 'password' | 'key' = 'password';

  constructor(options: ConnectionFormOptions) {
    this.options = options;

    this.render();
    this.loadSavedCredentials();
    this.checkTurnstileConfig();
  }

  // ==================== Configuration ====================

  private async checkTurnstileConfig(): Promise<void> {
    try {
      const response = await fetch('/api/config');

      const config = (await response.json()) as {
        turnstileEnabled: boolean;
        sitekey: string;
        githubAuthEnabled: boolean;
      };

      this.turnstileEnabled = config.turnstileEnabled;
      this.turnstileSitekey = config.sitekey;

      if (this.turnstileEnabled && this.turnstileSitekey) {
        this.renderTurnstile();
      }

      if (config.githubAuthEnabled) {
        this.renderGitHubLoginButton();
      }
    } catch {
      // 配置接口不可用时，保持匿名 SSH 连接模式。
    }
  }

  // ==================== GitHub Login ====================

  private renderGitHubLoginButton(): void {
    const placeholder = document.getElementById(
      'github-login-placeholder'
    );

    if (!placeholder) {
      return;
    }

    placeholder.innerHTML = `
      <button
        type="button"
        id="github-login-btn"
        class="tyun-github-btn github-login-btn"
      >
        <svg
          width="16"
          height="16"
          viewBox="0 0 16 16"
          fill="currentColor"
          aria-hidden="true"
        >
          <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"></path>
        </svg>

        <span>GitHub 登录</span>
      </button>
    `;

    document
      .getElementById('github-login-btn')
      ?.addEventListener('click', () => {
        window.location.href = '/api/auth/github';
      });
  }

  // ==================== Turnstile ====================

  private renderTurnstile(): void {
    const container = document.getElementById(
      'turnstile-widget'
    );

    if (!container || !window.turnstile) {
      return;
    }

    const wrapper = document.getElementById(
      'turnstile-container'
    );

    if (wrapper) {
      wrapper.style.display = 'block';
    }

    this.turnstileWidgetId = window.turnstile.render(
      container,
      {
        sitekey: this.turnstileSitekey,
        theme: 'light',

        callback: async (token: string) => {
          try {
            const response = await fetch('/api/verify', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({ token }),
            });

            const result = (await response.json()) as {
              success: boolean;
            };

            if (result.success) {
              this.turnstileVerified = true;

              if (wrapper) {
                wrapper.style.display = 'none';
              }
            }
          } catch {
            this.turnstileVerified = false;
          }
        },

        'expired-callback': () => {
          this.turnstileVerified = false;
        },

        'error-callback': () => {
          this.turnstileVerified = false;
        },
      }
    );
  }

  // ==================== UI Rendering ====================

  private render(): void {
    const container = document.getElementById(
      'connection-form-container'
    );

    if (!container) {
      throw new Error(
        'Connection form container was not found.'
      );
    }

    container.innerHTML = `
      <form
        id="connection-form"
        class="tyun-login-form"
        autocomplete="on"
      >
        <section class="tyun-brand">
          <img
            src="/logo.png"
            alt="唐云 Cloud"
            class="tyun-logo"
          >

          <div class="tyun-brand-copy">
            <h1>唐云 CloudSSH</h1>
            <p>安全、稳定、便捷的 Web SSH 远程终端</p>
          </div>
        </section>

        <section class="tyun-card">
          <header class="tyun-card-header">
            <div>
              <span class="tyun-eyebrow">REMOTE TERMINAL</span>
              <h2>连接 SSH 服务器</h2>
              <p>请输入服务器信息以创建安全远程会话。</p>
            </div>

            <span class="tyun-security-badge">
              <span class="material-symbols-outlined">shield_lock</span>
              安全连接
            </span>
          </header>

          <div class="tyun-form-body">
            <div class="tyun-host-grid">
              <div class="tyun-field tyun-host-field">
                <label for="host">
                  服务器地址
                  <span>HOST</span>
                </label>

                <div class="tyun-input-box">
                  <span class="material-symbols-outlined">
                    dns
                  </span>

                  <input
                    id="host"
                    class="tyun-input"
                    placeholder="例如：192.168.1.10"
                    type="text"
                    autocomplete="hostname"
                    spellcheck="false"
                    required
                  >
                </div>
              </div>

              <div class="tyun-field tyun-port-field">
                <label for="port">
                  SSH 端口
                  <span>PORT</span>
                </label>

                <div class="tyun-input-box">
                  <span class="material-symbols-outlined">
                    numbers
                  </span>

                  <input
                    id="port"
                    class="tyun-input"
                    placeholder="22"
                    type="number"
                    value="22"
                    min="1"
                    max="65535"
                    inputmode="numeric"
                  >
                </div>
              </div>
            </div>

            <div class="tyun-field">
              <label for="username">
                登录用户名
                <span>USERNAME</span>
              </label>

              <div class="tyun-input-box">
                <span class="material-symbols-outlined">
                  person
                </span>

                <input
                  id="username"
                  class="tyun-input"
                  placeholder="例如：root"
                  type="text"
                  autocomplete="username"
                  spellcheck="false"
                  required
                >
              </div>
            </div>

            <div class="tyun-field">
              <label>
                认证方式
                <span>AUTHENTICATION</span>
              </label>

              <div class="tyun-auth-tabs">
                <button
                  type="button"
                  id="auth-tab-password"
                  class="auth-tab auth-tab-active"
                >
                  <span class="material-symbols-outlined">
                    password
                  </span>

                  密码登录
                </button>

                <button
                  type="button"
                  id="auth-tab-key"
                  class="auth-tab"
                >
                  <span class="material-symbols-outlined">
                    key
                  </span>

                  SSH 私钥
                </button>
              </div>

              <div id="auth-password-section">
                <div class="tyun-input-box">
                  <span class="material-symbols-outlined">
                    lock
                  </span>

                  <input
                    id="password"
                    class="tyun-input"
                    placeholder="请输入服务器密码"
                    type="password"
                    autocomplete="current-password"
                  >
                </div>
              </div>

              <div
                id="auth-key-section"
                style="display: none;"
              >
                <textarea
                  id="private-key"
                  class="tyun-input tyun-key-textarea"
                  rows="6"
                  placeholder="请粘贴 OpenSSH 格式的 Ed25519、RSA 或 ECDSA 私钥"
                  spellcheck="false"
                ></textarea>

                <div class="tyun-file-row">
                  <label
                    for="private-key-file"
                    class="tyun-file-button"
                  >
                    <span class="material-symbols-outlined">
                      upload_file
                    </span>

                    选择私钥文件
                  </label>

                  <input
                    type="file"
                    id="private-key-file"
                    accept=".pem,.key,.txt,.pub"
                    hidden
                  >

                  <span
                    id="file-name"
                    class="tyun-file-name"
                  ></span>
                </div>
              </div>
            </div>

            <div
              id="turnstile-container"
              class="tyun-turnstile"
              style="display: none;"
            >
              <div id="turnstile-widget"></div>
            </div>

            <div class="tyun-field">
              <label for="anon-region">
                连接区域
                <span>可选</span>
              </label>

              <div class="tyun-input-box tyun-select-box">
                <span class="material-symbols-outlined">
                  public
                </span>

                <select
                  id="anon-region"
                  class="tyun-input tyun-select"
                >
                  <option value="">自动选择最佳节点</option>
                </select>
              </div>

              <p class="tyun-field-help">
                建议选择距离目标 SSH 服务器最近的 Cloudflare 节点。
              </p>
            </div>

            <div class="tyun-options-row">
              <label class="tyun-check">
                <input
                  type="checkbox"
                  id="remember-me"
                >

                <span class="tyun-checkbox-box">
                  <span class="material-symbols-outlined">
                    check
                  </span>
                </span>

                <span>
                  保存本次连接信息
                  <small>凭据将在当前浏览器中加密保存</small>
                </span>
              </label>
            </div>

            <button
              id="connect-btn"
              class="tyun-connect-btn connect-btn"
              type="button"
            >
              <span class="material-symbols-outlined">
                terminal
              </span>

              <span>开始连接服务器</span>
            </button>

            <div class="tyun-status">
              <span
                id="status-text"
                class="tyun-status-text"
              >
                <span class="status-dot"></span>
                状态：未连接
              </span>

              <span id="github-login-placeholder"></span>
            </div>
          </div>

          <section
            id="recent-connections-section"
            class="recent-box hidden"
          >
            <div class="tyun-recent-header">
              <div>
                <span class="material-symbols-outlined">
                  history
                </span>

                <div>
                  <h3>最近连接</h3>
                  <p>选择一条记录可快速填写连接信息。</p>
                </div>
              </div>
            </div>

            <div
              id="recent-connections-list"
              class="tyun-recent-list custom-scrollbar"
            ></div>
          </section>
        </section>

        <footer class="tyun-login-footer">
          <span class="material-symbols-outlined">
            verified_user
          </span>

          <span>
            会话通过 Cloudflare Workers 安全转发
          </span>
        </footer>
      </form>
    `;

    document
      .getElementById('connect-btn')
      ?.addEventListener('click', () => {
        this.handleConnect();
      });

    document
      .getElementById('connection-form')
      ?.addEventListener('keydown', event => {
        if (
          event.key === 'Enter' &&
          !event.shiftKey &&
          !(event.target instanceof HTMLTextAreaElement)
        ) {
          event.preventDefault();
          this.handleConnect();
        }
      });

    const anonRegionSelect = document.getElementById(
      'anon-region'
    ) as HTMLSelectElement | null;

    if (anonRegionSelect) {
      populateRegionSelect(anonRegionSelect, '');
    }

    document
      .getElementById('auth-tab-password')
      ?.addEventListener('click', () => {
        this.setAuthMode('password');
      });

    document
      .getElementById('auth-tab-key')
      ?.addEventListener('click', () => {
        this.setAuthMode('key');
      });

    const fileInput = document.getElementById(
      'private-key-file'
    ) as HTMLInputElement | null;

    const fileNameSpan = document.getElementById(
      'file-name'
    );

    fileInput?.addEventListener(
      'change',
      async event => {
        const file = (
          event.target as HTMLInputElement
        ).files?.[0];

        if (!file) {
          return;
        }

        try {
          const content = await file.text();

          const privateKeyTextarea =
            document.getElementById(
              'private-key'
            ) as HTMLTextAreaElement | null;

          if (privateKeyTextarea) {
            privateKeyTextarea.value = content;
          }

          if (fileNameSpan) {
            fileNameSpan.textContent =
              `已选择：${file.name}`;
          }
        } catch (error) {
          alert(
            `读取密钥文件失败：${
              error instanceof Error
                ? error.message
                : '未知错误'
            }`
          );
        }

        fileInput.value = '';
      }
    );
  }

  // ==================== Authentication Mode ====================

  private setAuthMode(
    mode: 'password' | 'key'
  ): void {
    this.authMode = mode;

    const passwordTab = document.getElementById(
      'auth-tab-password'
    );

    const keyTab = document.getElementById(
      'auth-tab-key'
    );

    const passwordSection = document.getElementById(
      'auth-password-section'
    );

    const keySection = document.getElementById(
      'auth-key-section'
    );

    passwordTab?.classList.toggle(
      'auth-tab-active',
      mode === 'password'
    );

    keyTab?.classList.toggle(
      'auth-tab-active',
      mode === 'key'
    );

    if (passwordSection) {
      passwordSection.style.display =
        mode === 'password' ? '' : 'none';
    }

    if (keySection) {
      keySection.style.display =
        mode === 'key' ? '' : 'none';
    }
  }

  // ==================== Recent Connections ====================

  private getRecentConnections(): RecentConnection[] {
    const raw = localStorage.getItem(
      'cloudssh_recent_connections'
    );

    try {
      const parsed = raw
        ? (JSON.parse(raw) as RecentConnection[])
        : [];

      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  private renderRecentConnections(): void {
    const section = document.getElementById(
      'recent-connections-section'
    );

    const list = document.getElementById(
      'recent-connections-list'
    );

    if (!section || !list) {
      return;
    }

    const recent = this.getRecentConnections();

    if (recent.length === 0) {
      section.classList.add('hidden');
      list.innerHTML = '';
      return;
    }

    section.classList.remove('hidden');
    list.innerHTML = '';

    recent.forEach((item, index) => {
      const itemElement = document.createElement('div');

      itemElement.className = 'tyun-history-item';

      const authenticationLabel =
        item.authMethod === 'publickey'
          ? '私钥'
          : '密码';

      const labelText =
        `${item.username}@${item.host}:${item.port}`;

      itemElement.innerHTML = `
        <button
          type="button"
          class="tyun-history-main"
          title="${labelText}"
        >
          <span class="tyun-history-icon">
            <span class="material-symbols-outlined">
              terminal
            </span>
          </span>

          <span class="tyun-history-content">
            <strong>${item.host}</strong>

            <span>
              ${item.username} · 端口 ${item.port}
            </span>
          </span>

          <span class="tyun-history-auth">
            ${authenticationLabel}
          </span>
        </button>

        <button
          type="button"
          class="delete-history-btn history-delete"
          title="删除这条记录"
          aria-label="删除这条连接记录"
        >
          <span class="material-symbols-outlined">
            close
          </span>
        </button>
      `;

      itemElement
        .querySelector('.tyun-history-main')
        ?.addEventListener('click', () => {
          this.fillConnection(item);
        });

      itemElement
        .querySelector('.delete-history-btn')
        ?.addEventListener('click', event => {
          event.stopPropagation();
          this.deleteConnection(index);
        });

      list.appendChild(itemElement);
    });
  }

  private async fillConnection(
    item: RecentConnection
  ): Promise<void> {
    const hostInput = document.getElementById(
      'host'
    ) as HTMLInputElement | null;

    const portInput = document.getElementById(
      'port'
    ) as HTMLInputElement | null;

    const usernameInput = document.getElementById(
      'username'
    ) as HTMLInputElement | null;

    const passwordInput = document.getElementById(
      'password'
    ) as HTMLInputElement | null;

    const privateKeyInput = document.getElementById(
      'private-key'
    ) as HTMLTextAreaElement | null;

    const rememberInput = document.getElementById(
      'remember-me'
    ) as HTMLInputElement | null;

    const regionSelect = document.getElementById(
      'anon-region'
    ) as HTMLSelectElement | null;

    if (hostInput) {
      hostInput.value = item.host || '';
    }

    if (portInput) {
      portInput.value = String(item.port || 22);
    }

    if (usernameInput) {
      usernameInput.value = item.username || '';
    }

    if (regionSelect) {
      regionSelect.value = item.region || '';
    }

    this.setAuthMode(
      item.authMethod === 'publickey'
        ? 'key'
        : 'password'
    );

    if (item.encryptedCred) {
      const credentials = await decryptCredentials(
        item.encryptedCred
      );

      if (credentials) {
        if (passwordInput) {
          passwordInput.value =
            credentials.password || '';
        }

        if (privateKeyInput) {
          privateKeyInput.value =
            credentials.privateKey || '';
        }

        if (rememberInput) {
          rememberInput.checked = true;
        }

        return;
      }
    }

    if (passwordInput) {
      passwordInput.value = '';
    }

    if (privateKeyInput) {
      privateKeyInput.value = '';
    }

    if (rememberInput) {
      rememberInput.checked = false;
    }
  }

  private deleteConnection(index: number): void {
    const recent = this.getRecentConnections();

    if (index < 0 || index >= recent.length) {
      return;
    }

    recent.splice(index, 1);

    localStorage.setItem(
      'cloudssh_recent_connections',
      JSON.stringify(recent)
    );

    this.renderRecentConnections();
  }

  private async loadSavedCredentials(): Promise<void> {
    const recent = this.getRecentConnections();

    const oldCredential = localStorage.getItem(
      'cloudssh_cred'
    );

    if (recent.length === 0 && oldCredential) {
      const credentials = await decryptCredentials(
        oldCredential
      );

      if (credentials) {
        const migratedItem: RecentConnection = {
          id: `${credentials.username}@${credentials.host}:${credentials.port}`,
          host: credentials.host,
          port: Number.parseInt(
            credentials.port,
            10
          ) || 22,
          username: credentials.username,
          authMethod:
            credentials.authMethod === 'publickey'
              ? 'publickey'
              : 'password',
          timestamp: Date.now(),
          encryptedCred: oldCredential,
        };

        recent.push(migratedItem);

        localStorage.setItem(
          'cloudssh_recent_connections',
          JSON.stringify(recent)
        );

        localStorage.removeItem('cloudssh_cred');
      }
    }

    this.renderRecentConnections();

    if (recent.length > 0) {
      await this.fillConnection(recent[0]);
    }
  }

  // ==================== SSH Connection ====================

  private async handleConnect(): Promise<void> {
    const hostInput = document.getElementById(
      'host'
    ) as HTMLInputElement | null;

    const portInput = document.getElementById(
      'port'
    ) as HTMLInputElement | null;

    const usernameInput = document.getElementById(
      'username'
    ) as HTMLInputElement | null;

    const passwordInput = document.getElementById(
      'password'
    ) as HTMLInputElement | null;

    const privateKeyInput = document.getElementById(
      'private-key'
    ) as HTMLTextAreaElement | null;

    const rememberInput = document.getElementById(
      'remember-me'
    ) as HTMLInputElement | null;

    const regionSelect = document.getElementById(
      'anon-region'
    ) as HTMLSelectElement | null;

    const host = (
      hostInput?.value || ''
    )
      .replace(/^\[|\]$/g, '')
      .trim();

    const port =
      Number.parseInt(
        portInput?.value || '22',
        10
      ) || 22;

    const username =
      usernameInput?.value.trim() || '';

    const password =
      passwordInput?.value || '';

    const privateKey =
      privateKeyInput?.value || '';

    const remember =
      rememberInput?.checked || false;

    const regionValue =
      regionSelect?.value || '';

    if (!host || !username) {
      alert('请填写服务器地址和登录用户名。');
      return;
    }

    if (
      !Number.isInteger(port) ||
      port < 1 ||
      port > 65535
    ) {
      alert('请输入有效的 SSH 端口。');
      return;
    }

    if (
      this.authMode === 'password' &&
      !password
    ) {
      alert('请输入服务器密码。');
      return;
    }

    if (
      this.authMode === 'key' &&
      !privateKey.trim()
    ) {
      alert('请粘贴或上传 SSH 私钥。');
      return;
    }

    if (
      this.turnstileEnabled &&
      !this.turnstileVerified
    ) {
      alert('请先完成人机验证。');
      return;
    }

    let encryptedCredential:
      | string
      | undefined;

    if (remember) {
      encryptedCredential =
        await encryptCredentials({
          host,
          port: String(port),
          username,
          password,
          privateKey:
            this.authMode === 'key'
              ? privateKey
              : undefined,
          authMethod:
            this.authMode === 'key'
              ? 'publickey'
              : 'password',
        });
    }

    let recent = this.getRecentConnections();

    const id = `${username}@${host}:${port}`;

    const newRecord: RecentConnection = {
      id,
      host,
      port,
      username,
      authMethod:
        this.authMode === 'key'
          ? 'publickey'
          : 'password',
      timestamp: Date.now(),
      ...(regionValue
        ? { region: regionValue }
        : {}),
      ...(encryptedCredential
        ? {
            encryptedCred:
              encryptedCredential,
          }
        : {}),
    };

    recent = recent.filter(
      record => record.id !== id
    );

    recent.unshift(newRecord);

    if (recent.length > 5) {
      recent = recent.slice(0, 5);
    }

    localStorage.setItem(
      'cloudssh_recent_connections',
      JSON.stringify(recent)
    );

    this.renderRecentConnections();

    const tabManager =
      this.options.getTabManager();

    const displayLabel =
      `${username}@${host}`;

    document
      .getElementById('auth-section')
      ?.classList.add('hidden');

    const terminalSection =
      document.getElementById(
        'terminal-section'
      );

    terminalSection?.classList.remove('hidden');
    terminalSection?.classList.add('flex');

    const tab = tabManager.createTab(
      displayLabel,
      {
        host,
        port,
        username,
      }
    );

    const terminal = tab.terminal;

    terminal.mount();

    try {
      const expectedFingerprint =
        await loadKnownFingerprint(
          host,
          port
        );

      await terminal.connect({
        host,
        port,
        username,
        password,
        authMethod:
          this.authMode === 'key'
            ? 'publickey'
            : 'password',
        privateKey,
        expectedFingerprint:
          expectedFingerprint || undefined,
        locationHint:
          regionValue || undefined,
      });
    } catch {
      tabManager.closeTab(tab.id);

      const statusText =
        document.getElementById(
          'status-text'
        );

      if (statusText) {
        statusText.innerHTML = `
          <span class="status-dot"></span>
          状态：连接失败
        `;
      }
    }
  }
}
