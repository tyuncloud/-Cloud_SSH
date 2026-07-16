import { loadKnownFingerprint } from './terminal';
import type { TabManager } from './tab-manager';
import { populateRegionSelect } from './regions';


export interface ConnectionFormOptions {
  getTabManager: () => TabManager;
}


export class ConnectionForm {

  private options: ConnectionFormOptions;

  private turnstileEnabled = false;

  private turnstileVerified = false;

  private turnstileWidgetId:
    string | null = null;

  private turnstileSitekey = '';

  private authMode:
    'password' | 'key' = 'password';



  constructor(options: ConnectionFormOptions) {

    this.options = options;

    this.render();

    this.checkTurnstileConfig();

  }




  // ====================
  // Cloudflare Turnstile
  // ====================


  private async checkTurnstileConfig(): Promise<void>{

    try{


      const response =
        await fetch('/api/config');


      const config =
        await response.json() as {

          turnstileEnabled:boolean;

          sitekey:string;

          githubAuthEnabled:boolean;

        };



      this.turnstileEnabled =
        config.turnstileEnabled;


      this.turnstileSitekey =
        config.sitekey;



      if(
        this.turnstileEnabled &&
        this.turnstileSitekey
      ){

        this.renderTurnstile();

      }



      if(config.githubAuthEnabled){

        this.renderGitHubLoginButton();

      }


    }catch{


      // 保持匿名连接模式


    }

  }





  private renderGitHubLoginButton():void{


    const placeholder =
      document.getElementById(
        'github-login-placeholder'
      );


    if(!placeholder)return;



    placeholder.innerHTML = `

      <button
        id="github-login-btn"
        class="tyun-github-btn"
        type="button"
      >

        GitHub 登录

      </button>

    `;



    document
      .getElementById(
        'github-login-btn'
      )
      ?.addEventListener(
        'click',
        ()=>{

          window.location.href =
          '/api/auth/github';

        }
      );


  }





  private renderTurnstile():void{


    const container =
      document.getElementById(
        'turnstile-widget'
      );


    if(
      !container ||
      !window.turnstile
    ){

      return;

    }



    const wrapper =
      document.getElementById(
        'turnstile-container'
      );


    if(wrapper){

      wrapper.style.display='block';

    }



    this.turnstileWidgetId =
      window.turnstile.render(

        container,

        {

          sitekey:
            this.turnstileSitekey,


          theme:'light',


          callback:
            async(token:string)=>{


              try{


                const response =
                  await fetch(
                    '/api/verify',
                    {

                      method:'POST',

                      headers:{
                        'Content-Type':
                        'application/json'
                      },


                      body:
                      JSON.stringify({
                        token
                      })

                    }
                  );


                const result =
                  await response.json()
                  as {
                    success:boolean
                  };


                this.turnstileVerified =
                  result.success;



                if(result.success && wrapper){

                  wrapper.style.display='none';

                }



              }catch{


                this.turnstileVerified=false;


              }


            }

        }

      );


  }
  // ====================
  // UI Render
  // ====================

  private render():void {


    const container =
      document.getElementById(
        'connection-form-container'
      );


    if(!container){

      throw new Error(
        'Connection form container missing'
      );

    }



    container.innerHTML = `

    <form
      id="connection-form"
      class="tyun-login-layout"
    >


      <!-- 左侧品牌 -->

      <section class="tyun-side-brand">


        <img
          src="/logo.png"
          class="tyun-large-logo"
          alt="Tyun Cloud"
        >


        <h1>
          唐云 CloudSSH
        </h1>


        <p>
          企业级 Web SSH 远程管理平台
        </p>


        <div class="tyun-feature-list">


          <div>
            <span>
              ✓
            </span>

            安全 SSH 加密连接
          </div>



          <div>
            <span>
              ✓
            </span>

            Cloudflare 全球节点
          </div>



          <div>
            <span>
              ✓
            </span>

            无需安装客户端
          </div>


        </div>


      </section>





      <!-- 右侧登录 -->

      <section
        class="tyun-card"
      >


        <header
          class="tyun-card-header"
        >

          <h2>
            连接 SSH 服务器
          </h2>


          <p>
            输入服务器信息开始安全连接
          </p>


        </header>





        <div
          class="tyun-field"
        >

          <label>
            服务器地址
          </label>


          <div
            class="tyun-input-box"
          >

            <span
              class="material-symbols-outlined"
            >
              dns
            </span>


            <input

              id="host"

              class="tyun-input"

              placeholder="例如 192.168.1.10"

              type="text"

              required

            >

          </div>


        </div>





        <div
          class="tyun-grid"
        >


          <div
            class="tyun-field"
          >

            <label>
              SSH端口
            </label>


            <div
              class="tyun-input-box"
            >

              <input

                id="port"

                class="tyun-input"

                value="22"

                type="number"

              >

            </div>


          </div>





          <div
            class="tyun-field"
          >

            <label>
              用户名
            </label>


            <div
              class="tyun-input-box"
            >


              <input

                id="username"

                class="tyun-input"

                value="root"

                type="text"

                required

              >


            </div>


          </div>


        </div>







        <div
          class="tyun-field"
        >

          <label>
            认证方式
          </label>



          <div
            class="tyun-auth-tabs"
          >


            <button

              type="button"

              id="auth-tab-password"

              class="
              auth-tab
              auth-tab-active
              "

            >

              密码登录

            </button>




            <button

              type="button"

              id="auth-tab-key"

              class="auth-tab"

            >

              SSH密钥

            </button>


          </div>




          <div
            id="auth-password-section"
          >

            <div
              class="tyun-input-box"
            >

              <span
                class="material-symbols-outlined"
              >
                lock
              </span>


              <input

                id="password"

                class="tyun-input"

                placeholder="请输入服务器密码"

                type="password"

              >

            </div>


          </div>





          <div

            id="auth-key-section"

            style="display:none"

          >


            <textarea

              id="private-key"

              class="tyun-input"

              rows="5"

              placeholder="
              -----BEGIN OPENSSH PRIVATE KEY-----
              "

            ></textarea>



            <label
              class="tyun-file-button"
              for="private-key-file"
            >

              上传私钥文件

            </label>


            <input

              id="private-key-file"

              type="file"

              hidden

              accept=".pem,.key,.txt"

            >



            <span
              id="file-name"
            ></span>



          </div>


        </div>





        <div
          id="turnstile-container"

          style="display:none"

        >

          <div
            id="turnstile-widget"
          ></div>


        </div>





        <div
          class="tyun-field"
        >

          <label>
            节点区域
          </label>


          <div
            class="tyun-input-box"
          >

            <select
              id="anon-region"
              class="tyun-input"
            >

              <option value="">
                自动选择最佳节点
              </option>

            </select>


          </div>


        </div>






        <button

          id="connect-btn"

          type="button"

          class="tyun-connect-btn"

        >

          🚀 开始连接服务器

        </button>






        <div
          class="tyun-security-box"
        >

          🔒 安全提示

          <br>

          本系统不会保存服务器信息

          <br>

          密码仅用于当前 SSH 会话


        </div>






        <div
          class="tyun-status"
        >

          <span
            id="status-text"
          >

            <span
              class="status-dot"
            ></span>

            状态：未连接


          </span>


          <span
            id="github-login-placeholder"
          ></span>


        </div>



      </section>


    </form>

    `;





    document
      .getElementById(
        'connect-btn'
      )
      ?.addEventListener(
        'click',
        ()=>{

          this.handleConnect();

        }
      );





    const region =
      document.getElementById(
        'anon-region'
      )
      as HTMLSelectElement|null;



    if(region){

      populateRegionSelect(
        region,
        ''
      );

    }




    document
      .getElementById(
        'auth-tab-password'
      )
      ?.addEventListener(
        'click',
        ()=>{

          this.setAuthMode(
            'password'
          );

        }
      );




    document
      .getElementById(
        'auth-tab-key'
      )
      ?.addEventListener(
        'click',
        ()=>{

          this.setAuthMode(
            'key'
          );

        }
      );

    const fileInput =
      document.getElementById(
        'private-key-file'
      ) as HTMLInputElement | null;


    const fileName =
      document.getElementById(
        'file-name'
      );



    fileInput?.addEventListener(
      'change',
      async(event)=>{


        const file =
          (event.target as HTMLInputElement)
          .files?.[0];


        if(!file){

          return;

        }



        try{


          const content =
            await file.text();



          const textarea =
            document.getElementById(
              'private-key'
            ) as HTMLTextAreaElement | null;



          if(textarea){

            textarea.value =
              content;

          }



          if(fileName){

            fileName.textContent =
              `已选择：${file.name}`;

          }


        }catch(error){


          alert(
            '读取私钥文件失败'
          );


        }



        fileInput.value='';



      }
    );


  }





  // ====================
  // Authentication Mode
  // ====================


  private setAuthMode(
    mode:'password'|'key'
  ):void{


    this.authMode =
      mode;



    const passwordTab =
      document.getElementById(
        'auth-tab-password'
      );


    const keyTab =
      document.getElementById(
        'auth-tab-key'
      );



    const passwordBox =
      document.getElementById(
        'auth-password-section'
      );


    const keyBox =
      document.getElementById(
        'auth-key-section'
      );




    passwordTab?.classList.toggle(

      'auth-tab-active',

      mode==='password'

    );



    keyTab?.classList.toggle(

      'auth-tab-active',

      mode==='key'

    );




    if(passwordBox){

      passwordBox.style.display =
        mode==='password'
        ? ''
        : 'none';

    }




    if(keyBox){

      keyBox.style.display =
        mode==='key'
        ? ''
        : 'none';

    }


  }

  // ====================
  // SSH Connection
  // ====================


  private async handleConnect():Promise<void>{



    const hostInput =
      document.getElementById(
        'host'
      ) as HTMLInputElement | null;



    const portInput =
      document.getElementById(
        'port'
      ) as HTMLInputElement | null;



    const usernameInput =
      document.getElementById(
        'username'
      ) as HTMLInputElement | null;



    const passwordInput =
      document.getElementById(
        'password'
      ) as HTMLInputElement | null;



    const privateKeyInput =
      document.getElementById(
        'private-key'
      ) as HTMLTextAreaElement | null;




    const regionSelect =
      document.getElementById(
        'anon-region'
      ) as HTMLSelectElement | null;





    const host =
      (
        hostInput?.value || ''
      )
      .replace(/^\[|\]$/g,'')
      .trim();




    const port =
      Number.parseInt(
        portInput?.value || '22',
        10
      ) || 22;




    const username =
      usernameInput?.value.trim()
      || 'root';




    const password =
      passwordInput?.value || '';




    const privateKey =
      privateKeyInput?.value || '';




    const region =
      regionSelect?.value || '';






    if(!host){


      alert(
        '请输入服务器地址'
      );


      return;

    }





    if(
      !Number.isInteger(port)
      ||
      port < 1
      ||
      port > 65535
    ){

      alert(
        'SSH端口错误'
      );


      return;

    }






    if(
      this.authMode === 'password'
      &&
      !password
    ){

      alert(
        '请输入服务器密码'
      );


      return;

    }





    if(
      this.authMode === 'key'
      &&
      !privateKey.trim()
    ){

      alert(
        '请输入SSH私钥'
      );


      return;

    }







    if(
      this.turnstileEnabled
      &&
      !this.turnstileVerified
    ){

      alert(
        '请完成人机验证'
      );


      return;

    }







    const tabManager =
      this.options.getTabManager();





    const displayLabel =
      `${username}@${host}`;







    document
      .getElementById(
        'auth-section'
      )
      ?.classList.add(
        'hidden'
      );





    const terminalSection =
      document.getElementById(
        'terminal-section'
      );



    terminalSection
      ?.classList.remove(
        'hidden'
      );



    terminalSection
      ?.classList.add(
        'flex'
      );






    const tab =
      tabManager.createTab(

        displayLabel,

        {

          host,

          port,

          username

        }

      );






    const terminal =
      tab.terminal;





    terminal.mount();





    try{



      const fingerprint =
        await loadKnownFingerprint(
          host,
          port
        );





      await terminal.connect(

        {

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
            fingerprint || undefined,



          locationHint:
            region || undefined


        }

      );





      const status =
        document.getElementById(
          'status-text'
        );



      if(status){


        status.innerHTML = `

          <span class="status-dot status-online">
          </span>

          状态：连接成功

        `;


      }





    }catch(error){



      tabManager.closeTab(
        tab.id
      );




      const status =
        document.getElementById(
          'status-text'
        );



      if(status){


        status.innerHTML = `

          <span class="status-dot">
          </span>

          状态：连接失败

        `;


      }





    }



  }


}
