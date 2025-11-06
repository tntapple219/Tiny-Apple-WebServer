document.addEventListener('DOMContentLoaded', () => {

    // --- DICTIONARY & CONSTANTS ---
    const translations = {
        en: {
            pageTitle: "Tiny Apple WebServer", mainTitle: "Tiny Apple WebServer", subtitle: "Easily manage your domain configurations.", themeLabel: "Theme:", addNewDomainTitle: "➕ Add New Domain", domainLabel: "🌐 Domain", typeLabel: "⚙️ Type", selectTypeOption: "-- Select Type --", fileServerOption: "📁 File Server (Static Files)", phpServerOption: "🐘 PHP Server", reverseProxyOption: "🔄 Reverse Proxy", rootDirLabel: "📂 Root Directory", phpSocketLabel: "🐘 PHP-FPM Socket", proxyUrlLabel: "🎯 Proxy Target URL", sslModeLabel: "🔒 SSL Mode", sslNoneOption: "No Certificate (HTTP Only)", sslLetsEncryptOption: "Let's Encrypt (Auto)", sslCustomOption: "Use Custom Certificate Files", sslSelfSignedOption: "Self-Signed (for Dev)", sslCertPathLabel: "📜 Certificate File Path (.crt/.pem)", sslKeyPathLabel: "🔑 Private Key File Path (.key)", addDomainBtn: "✨ Add Domain", configuredDomainsTitle: "🌍 Configured Domains", deleteBtn: "Delete", emptyStateText: "No domains configured yet.<br>Add your first one!", confirmDelete: "Are you sure you want to delete", alertSuccess: "✅ Success!", alertAddSuccess: "✅ Domain added successfully!", alertDeleteSuccess: "✅ Domain deleted successfully!", alertAddFailed: "❌ Failed to add domain:", alertDeleteFailed: "❌ Failed to delete domain!", proxyInsecureLabel: "Ignore self-signed SSL certificate on the target",insecureSkipVerifyText: "Insecure Skip Verify", alertFetchFailed: "Failed to fetch domains. Please check if the server is running."
        },
        zh: {
            pageTitle: "小蘋果網頁伺-服器", mainTitle: "小蘋果網頁伺服器", subtitle: "輕鬆管理你的域名配置。", themeLabel: "主題:", addNewDomainTitle: "➕ 添加新域名", domainLabel: "🌐 域名", typeLabel: "⚙️ 類型", selectTypeOption: "-- 選擇類型 --", fileServerOption: "📁 檔案伺服器 (靜態文件)", phpServerOption: "🐘 PHP 伺服器", reverseProxyOption: "🔄 反向代理", rootDirLabel: "📂 根目錄", phpSocketLabel: "🐘 PHP-FPM Socket", proxyUrlLabel: "🎯 代理目標 URL", sslModeLabel: "🔒 SSL 模式", sslNoneOption: "無證書 (僅 HTTP)", sslLetsEncryptOption: "Let's Encrypt (自動)", sslCustomOption: "使用自己的證書檔案", sslSelfSignedOption: "自簽發證書 (開發用)", sslCertPathLabel: "📜 證書檔案路徑 (.crt/.pem)", sslKeyPathLabel: "🔑 私鑰檔案路徑 (.key)", addDomainBtn: "✨ 添加域名", configuredDomainsTitle: "🌍 已配置域名", deleteBtn: "刪除", emptyStateText: "還沒有配置任何域名<br>快來添加第一個吧!", confirmDelete: "確定要刪除", alertSuccess: "✅ 操作成功!", alertAddSuccess: "✅ 域名添加成功!", alertDeleteSuccess: "✅ 域名刪除成功!", alertAddFailed: "❌ 添加域名失敗:", alertDeleteFailed: "❌ 刪除域名失敗!",proxyInsecureLabel: "忽略目標的自簽發 SSL 證書",insecureSkipVerifyText: "忽略證書驗證",alertFetchFailed: "讀取域名失敗，請檢查後端服務是否正常。"
        }
    };
    const appleFacts = {
        en: [ "The smallest commercial fresh apple in the world is the Rockit™ apple.", "You can craft TNT and APPLE in Minecraft, but not TNTAPPLE.", "An apple a day keeps the doctor away.", "This web server is called Tiny Apple, not TNTAPPLE.", "Apples are about 85% water, which is why they float.", "The science of growing apples is called pomology." ],
        zh: [ "世界上最小的商業化鮮食蘋果是Rockit蘋果。", "你可以在Minecraft中製作TNT跟APPLE，但不能製作TNTAPPLE。", "一天一蘋果，醫生遠離我。", "這個WebServer叫做Tiny Apple而不是TNTAPPLE。", "蘋果含有約 85% 的水，因此能夠漂浮在水上。", "種植蘋果的科學被稱為「果樹學」（pomology）。" ]
    };
    let currentLang = 'en';

    // --- DOM ELEMENT REFERENCES ---
    const themeToggle = document.getElementById('theme-toggle');
    const appleIcon = document.getElementById('apple-icon');
    const appleTooltip = document.getElementById('apple-tooltip');
    const addForm = document.getElementById('addForm');

    // --- FUNCTION DEFINITIONS ---

    const setLanguage = (lang) => {
        if (!translations[lang]) return;
        currentLang = lang;
        localStorage.setItem('language', lang);
        document.documentElement.lang = lang;

        document.querySelectorAll('[data-translate-key]').forEach(el => {
            const key = el.getAttribute('data-translate-key');
            if (translations[lang][key]) {
                el.innerHTML = translations[lang][key];
            }
        });
        
        document.getElementById('lang-en').classList.toggle('active', lang === 'en');
        document.getElementById('lang-zh').classList.toggle('active', lang === 'zh');
        
        loadDomains(); // Reload domains to get translated text like the "Delete" button
    };
    
    // Made global for HTML onchange attribute
    window.updateFields = () => {
        const type = document.getElementById('type').value;
        const sslMode = document.getElementById('sslMode').value;
        document.querySelectorAll('.conditional-fields').forEach(el => el.classList.remove('show'));

        if (type === 'file_server') document.getElementById('fileFields').classList.add('show');
        else if (type === 'php') document.getElementById('phpFields').classList.add('show');
        else if (type === 'reverse_proxy') document.getElementById('proxyFields').classList.add('show');
        
        if (sslMode === 'custom') document.getElementById('customSslFields').classList.add('show');
    };

    const loadDomains = async () => {
        try {
            const res = await fetch('/api/domains');
            if (!res.ok) throw new Error('Failed to fetch domains');
            const domains = await res.json();
            const list = document.getElementById('domainList');

            if (!domains || domains.length === 0) {
                list.innerHTML = `<div class="empty-state"><p>${translations[currentLang].emptyStateText}</p></div>`;
                return;
            }

            list.innerHTML = domains.map(d => {
                let typeText = "File Server", typeClass = 'type-file';
                if (d.type === 'php') { typeClass = 'type-php'; typeText = "PHP"; }
                if (d.type === 'reverse_proxy') {
                    let insecureText = '';
                    if (d.proxy_insecure_skip_verify) {
                        insecureText = ` <b class="insecure">(${translations[currentLang].insecureSkipVerifyText})</b>`;
                    }
                    info = `<div class="domain-info"><b>Target:</b> ${d.proxy_url || 'N/A'}${insecureText}</div>`;
                }
                
                let sslText = "None", sslClass = 'ssl-none';
                if (d.ssl_mode === 'lets_encrypt') { sslClass = 'ssl-lets_encrypt'; sslText = "Let's Encrypt"; }
                if (d.ssl_mode === 'custom') { sslClass = 'ssl-custom'; sslText = "Custom"; }
                if (d.ssl_mode === 'self_signed') { sslClass = 'ssl-self_signed'; sslText = 'Self-Signed'; }

                let info = '';
                if (d.type === 'file_server') info = `<div class="domain-info"><b>Root:</b> ${d.root || 'N/A'}</div>`;
                if (d.type === 'php') info = `<div class="domain-info"><b>Root:</b> ${d.root || 'N/A'}</div><div class="domain-info"><b>Socket:</b> ${d.php_socket || 'N/A'}</div>`;
                if (d.type === 'reverse_proxy') info = `<div class="domain-info"><b>Target:</b> ${d.proxy_url || 'N/A'}</div>`;

                return `
                <div class="domain-card">
                    <div class="domain-header">
                        <div>
                            <div class="domain-name">${d.domain}</div>
                            <div class="domain-meta">
                               <span class="domain-type ${typeClass}">${typeText}</span>
                               <span class="domain-ssl ${sslClass}">${sslText}</span>
                            </div>
                        </div>
                        <button class="btn btn-danger" onclick="deleteDomain('${d.domain}')">${translations[currentLang].deleteBtn}</button>
                    </div>
                    ${info}
                </div>`;
            }).join('');
        } catch (error) {
            console.error('Error loading domains:', error);
            document.getElementById('domainList').innerHTML = `<div class="empty-state"><p>${translations[currentLang].alertFetchFailed}</p></div>`;
        }
    };

    // Made global for HTML onclick attribute
    window.deleteDomain = async (domain) => {
        if (!confirm(`${translations[currentLang].confirmDelete} ${domain}?`)) return;
        const res = await fetch('/api/domains/' + encodeURIComponent(domain), { method: 'DELETE' });
        if (res.ok) {
            alert(translations[currentLang].alertDeleteSuccess);
            loadDomains();
        } else {
            alert(translations[currentLang].alertDeleteFailed);
        }
    };

    // --- EVENT LISTENERS ---

    themeToggle.addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
    });

    document.getElementById('lang-en').addEventListener('click', () => setLanguage('en'));
    document.getElementById('lang-zh').addEventListener('click', () => setLanguage('zh'));

    appleIcon.addEventListener('mouseover', () => {
        const facts = appleFacts[currentLang];
        const randomFact = facts[Math.floor(Math.random() * facts.length)];
        appleTooltip.textContent = randomFact;
    });

    addForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const type = document.getElementById('type').value;
        const data = {
            domain: document.getElementById('domain').value,
            type: type,
            ssl_mode: document.getElementById('sslMode').value,
        };

        if (type === 'file_server') data.root = document.getElementById('root').value;
        else if (type === 'php') {
            data.root = document.getElementById('phpRoot').value;
            data.php_socket = document.getElementById('phpSocket').value;
        } else if (type === 'reverse_proxy') {
            data.proxy_url = document.getElementById('proxyUrl').value;
            data.proxy_insecure_skip_verify = document.getElementById('proxyInsecure').checked;
        }

        if (data.ssl_mode === 'custom') {
            data.ssl_cert_file = document.getElementById('sslCertFile').value;
            data.ssl_key_file = document.getElementById('sslKeyFile').value;
        }

        const res = await fetch('/api/domains', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });

        if (res.ok) {
            alert(translations[currentLang].alertAddSuccess);
            e.target.reset();
            updateFields();
            loadDomains();
        } else {
            const text = await res.text();
            alert(`${translations[currentLang].alertAddFailed} ${text}`);
        }
    });

    // --- INITIALIZATION ---
    
    // 1. Set theme
    const storedTheme = localStorage.getItem('theme');
    const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    document.documentElement.setAttribute('data-theme', storedTheme || (systemPrefersDark ? 'dark' : 'light'));

    // 2. Set language (this will also trigger the first loadDomains call)
    const storedLang = localStorage.getItem('language');
    const browserLang = navigator.language.startsWith('zh') ? 'zh' : 'en';
    setLanguage(storedLang || browserLang);

    // 3. Set initial state for conditional fields
    updateFields();
});