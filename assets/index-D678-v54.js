(function(){let e=document.createElement(`link`).relList;if(e&&e.supports&&e.supports(`modulepreload`))return;for(let e of document.querySelectorAll(`link[rel="modulepreload"]`))n(e);new MutationObserver(e=>{for(let t of e)if(t.type===`childList`)for(let e of t.addedNodes)e.tagName===`LINK`&&e.rel===`modulepreload`&&n(e)}).observe(document,{childList:!0,subtree:!0});function t(e){let t={};return e.integrity&&(t.integrity=e.integrity),e.referrerPolicy&&(t.referrerPolicy=e.referrerPolicy),e.crossOrigin===`use-credentials`?t.credentials=`include`:e.crossOrigin===`anonymous`?t.credentials=`omit`:t.credentials=`same-origin`,t}function n(e){if(e.ep)return;e.ep=!0;let n=t(e);fetch(e.href,n)}})();var e={frodo640:{id:`frodo640`,label:`FrodoKEM-640`,n:640,q:2**15,classicalBits:128,pqBits:103,publicKey:9616,privateKey:19888,ciphertext:9720,sigma:2.8,maxError:12},frodo976:{id:`frodo976`,label:`FrodoKEM-976`,n:976,q:2**16,classicalBits:192,pqBits:150,publicKey:15632,privateKey:31296,ciphertext:15744,sigma:2.3,maxError:10},frodo1344:{id:`frodo1344`,label:`FrodoKEM-1344`,n:1344,q:2**16,classicalBits:256,pqBits:207,publicKey:21520,privateKey:43088,ciphertext:21632,sigma:1.4,maxError:6}};function t(e,t){let n=e%t;return n<0?n+t:n}function n(e,n){let r=0,i=1,a=n,o=t(e,n);for(;o!==0;){let e=Math.floor(a/o);[r,i]=[i,r-e*i],[a,o]=[o,a-e*o]}if(a!==1)throw Error(`No modular inverse`);return t(r,n)}function r(e,n,r){return t(e[0]*n[0]+e[1]*n[1]+e[2]*n[2],r)}function i(e){let r=e.slice(0,3).map(e=>[...e.a,e.b]);for(let e=0;e<3;e+=1){let i=e;for(;i<3&&r[i][e]===0;)i+=1;if(i===3)return null;i!==e&&([r[e],r[i]]=[r[i],r[e]]);let a=n(r[e][e],97);for(let n=e;n<4;n+=1)r[e][n]=t(r[e][n]*a,97);for(let n=0;n<3;n+=1){if(n===e)continue;let i=r[n][e];for(let a=e;a<4;a+=1)r[n][a]=t(r[n][a]-i*r[e][a],97)}}return[r[0][3],r[1][3],r[2][3]]}function a(e,n,i=1,a=()=>crypto.getRandomValues(new Uint32Array(1))[0]){let o=n?5:3,s=[];function c(e){return e<=0?0:a()%e}function l(e,t){return e+c(t-e+1)}for(;s.length<o;){let a=[l(0,96),l(0,96),l(0,96)],o=n?l(-i,i):0,c=t(r(a,e,97)+o,97);s.push({a,b:c,e:o})}return s}function o(e,t){return Math.exp(-(e*e)/(2*t*t))}function s(e=()=>crypto.getRandomValues(new Uint32Array(1))[0]){let n=[];function r(t){return t<=0?0:e()%t}function i(e,t){return e+r(t-e+1)}for(let e=1;e<=8;e++){let a=0;for(let n=0;n<500;n++){let n=r(2),o=i(-e,e),s=t(n*8+o,17),c=Math.min(t(s,17),t(-s,17));+(Math.min(t(s-8,17),t(8-s,17))<c)!==n&&a++}n.push({maxErr:e,rate:a/500})}return n}function c(e){return e?Array.from(e,e=>e.toString(16).padStart(2,`0`)).join(``):`--`}function l(e,t=64){return`${Array.from(e,e=>e.toString(16).padStart(2,`0`)).join(``).slice(0,t*2)}... [${e.length-t} more bytes]`}function u(e,t){let n=new Uint8Array(e.length+t.length);return n.set(e),n.set(t,e.length),n}function d(e,t,n=64){if(!e||!t)return``;let r=[],i=Math.min(e.length,t.length,n);for(let n=0;n<i;n++){let i=t[n].toString(16).padStart(2,`0`);e[n]===t[n]?r.push(i):r.push(`<span class="tampered">${i}</span>`)}return t.length>n&&r.push(`... [${t.length-n} more]`),r.join(``)}var f=[`lwe`,`keygen`,`kem`,`compare`,`errors`,`landscape`,`divide`];function p(){let e=location.hash.replace(`#`,``);return f.includes(e)?e:null}var m=document.querySelector(`#app`);if(!m)throw Error(`App root not found`);var h=m,g={activeTab:p()??`lwe`,selectedParam:`frodo976`,lweSecret:[3,7,11],lweSamples:[],lweCleanSamples:[],lweOutcome:`Generate toy LWE samples, then test solving with and without noise.`,keygenPreview:``,keygenSkSize:0,keygenMs:0,keygenRatio:``,aliceSeed:null,kemCiphertext:null,kemBobSecret:null,kemAliceSecret:null,kemEncapMs:0,kemDecapMs:0,kemStatus:`Generate Alice keypair to begin encapsulation.`,kemPreTamperCt:null,compareBench:``,compareRows:{frodo:{keygen:0,encaps:0,decaps:0},mlkem:{keygen:0,encaps:0,decaps:0}},errorHistogram:[],errorSummary:`Sample 1000 errors to visualize FrodoKEM-style discrete distribution.`,failureSummary:`Run the toy decryption-failure demo (n=4, q=17) with oversized errors.`,lweNoiseMag:1,failProbs:[],matrixAnimHtml:``,matrixAnimRunning:!1,hybridFrodoSS:null,hybridMlkemSS:null,hybridCombinedSS:null,hybridStatus:`Run the hybrid demo to derive a combined shared secret.`,openCollapsibles:new Set};function _(){let e=new Uint32Array(1);return crypto.getRandomValues(e),e[0]}function v(e){return e<=0?0:_()%e}function y(e,t){return e+v(t-e+1)}function b(e){let t=new Uint8Array(e);return crypto.getRandomValues(t),t}async function x(e){let t=new Uint8Array(e.byteLength);t.set(e);let n=await crypto.subtle.digest(`SHA-256`,t);return new Uint8Array(n)}function S(){return document.documentElement.getAttribute(`data-theme`)===`light`?`light`:`dark`}function C(e){document.documentElement.setAttribute(`data-theme`,e),localStorage.setItem(`theme`,e)}function w(e){return e===`dark`?{icon:`🌙`,label:`Switch to light mode`}:{icon:`☀️`,label:`Switch to dark mode`}}function T(e){let n=performance.now(),r=0;for(let n=0;n<e;n+=1)r=t(r+(n*17+11)*(n*19+7),65536);return performance.now()-n+r*0}function E(e,t){let n=[],r=[],i=0;for(let a=-e;a<=e;a+=1){let e=o(a,t);n.push(a),r.push(e),i+=e}let a=_()/4294967295*i,s=0;for(let e=0;e<n.length;e+=1)if(s+=r[e],a<=s)return n[e];return 0}function D(e){let t=new Map;for(let n=-e.maxError;n<=e.maxError;n+=1)t.set(n,0);for(let n=0;n<1e3;n+=1){let n=E(e.maxError,e.sigma);t.set(n,(t.get(n)??0)+1)}return Array.from(t.entries()).map(([e,t])=>({value:e,count:t}))}function O(){let e=0;for(;e<25;){e+=1;let n=v(2),r=y(-6,6),i=t(n*8+r,17),a=Math.min(t(i,17),t(-i,17)),o=+(Math.min(t(i-8,17),t(8-i,17))<a);if(o!==n)return`Toy failure observed: message=${n}, encoded=${i} mod 17, accumulated error=${r}, recovered=${o}. Oversized errors break correctness.`}return`No failure occurred in 25 tries. Re-run: oversized errors still cause frequent failures at toy scale.`}async function k(){let e=document.getElementById(`matrix-anim-container`);if(!e)return;g.matrixAnimRunning=!0;let n=g.lweSecret,r=[],i=[],a=[];for(let e=0;e<3;e++){r.push([y(0,96),y(0,96),y(0,96)]);let o=y(-g.lweNoiseMag,g.lweNoiseMag);i.push(o),a.push(t(r[e][0]*n[0]+r[e][1]*n[1]+r[e][2]*n[2]+o,97))}function o(e,t,o){let s=`<div class="matrix-viz">`;s+=`<div class="matrix-label">A · s + e = b mod 97</div>`,s+=`<div style="display:grid;grid-template-columns:auto auto auto;gap:0.5rem;align-items:center">`,s+=`<div>`;for(let n=0;n<3;n++){s+=`<div class="matrix-row">`;for(let i=0;i<3;i++)s+=`<div class="matrix-cell ${n===e&&i===t?`active`:n<e?`result`:``}">${r[n][i]}</div>`;s+=`</div>`}s+=`</div>`,s+=`<div style="text-align:center">·<br>`;for(let r=0;r<3;r++)s+=`<div class="matrix-cell ${r===t&&e>=0?`active`:``}">${n[r]}</div>`;s+=`</div>`,s+=`<div style="text-align:center">=<br>`;for(let e=0;e<3;e++)e<o.length?s+=`<div class="matrix-cell result">${o[e]}</div>`:s+=`<div class="matrix-cell">?</div>`;if(s+=`</div></div>`,e>=0&&e<3){let t=r[e].map((e,t)=>`${e}·${n[t]}`);s+=`<div class="matrix-equation">${t.join(` + `)} + (${i[e]}) = ${a[e]} mod 97</div>`}else o.length===3&&(s+=`<div class="matrix-equation">Complete! All b values computed.</div>`);return s+=`</div>`,s}let s=[];for(let t=0;t<3;t++){for(let n=0;n<3;n++){if(!e.isConnected){g.matrixAnimRunning=!1;return}e.innerHTML=o(t,n,s),await new Promise(e=>setTimeout(e,300))}if(s.push(a[t]),!e.isConnected){g.matrixAnimRunning=!1;return}e.innerHTML=o(t,-1,s),await new Promise(e=>setTimeout(e,400))}if(!e.isConnected){g.matrixAnimRunning=!1;return}e.innerHTML=o(-1,-1,s),g.matrixAnimHtml=e.innerHTML,g.matrixAnimRunning=!1}function A(){let n=w(S()),o=e[g.selectedParam],f=Math.max(1,...g.errorHistogram.map(e=>e.count)),p=g.kemAliceSecret&&g.kemBobSecret?c(g.kemAliceSecret)===c(g.kemBobSecret):!1;h.innerHTML=`
  <main id="main-content" class="shell">
    <header class="hero-header">
      <button id="theme-toggle" class="theme-toggle" type="button" aria-label="${n.label}">${n.icon}</button>
      <p class="eyebrow">crypto-lab demo</p>
      <h1>Frodo Vault: FrodoKEM without ring structure</h1>
      <p class="subhead">The conservative post-quantum KEM based on plain LWE. Bigger keys, simpler assumption.</p>
    </header>

    <nav class="tabs" role="tablist" aria-label="FrodoKEM exhibits">
      <button class="tab ${g.activeTab===`lwe`?`active`:``}" data-tab="lwe" role="tab" id="tab-lwe" aria-selected="${g.activeTab===`lwe`}" aria-controls="panel-lwe">1. LWE Problem</button>
      <button class="tab ${g.activeTab===`keygen`?`active`:``}" data-tab="keygen" role="tab" id="tab-keygen" aria-selected="${g.activeTab===`keygen`}" aria-controls="panel-keygen">2. Key Generation</button>
      <button class="tab ${g.activeTab===`kem`?`active`:``}" data-tab="kem" role="tab" id="tab-kem" aria-selected="${g.activeTab===`kem`}" aria-controls="panel-kem">3. Encap / Decap</button>
      <button class="tab ${g.activeTab===`compare`?`active`:``}" data-tab="compare" role="tab" id="tab-compare" aria-selected="${g.activeTab===`compare`}" aria-controls="panel-compare">4. Frodo vs ML-KEM</button>
      <button class="tab ${g.activeTab===`errors`?`active`:``}" data-tab="errors" role="tab" id="tab-errors" aria-selected="${g.activeTab===`errors`}" aria-controls="panel-errors">5. Error Distribution</button>
      <button class="tab ${g.activeTab===`landscape`?`active`:``}" data-tab="landscape" role="tab" id="tab-landscape" aria-selected="${g.activeTab===`landscape`}" aria-controls="panel-landscape">6. PQ Landscape</button>
      <button class="tab ${g.activeTab===`divide`?`active`:``}" data-tab="divide" role="tab" id="tab-divide" aria-selected="${g.activeTab===`divide`}" aria-controls="panel-divide">7. The Global Divide</button>
    </nav>
    <p class="kbd-hint" aria-hidden="true">Navigate: <kbd>←</kbd> <kbd>→</kbd> arrow keys</p>

    <section class="panel ${g.activeTab===`lwe`?`visible`:``}" id="panel-lwe" role="tabpanel" aria-labelledby="tab-lwe" ${g.activeTab===`lwe`?``:`hidden`}>
      <article class="card">
        <h2>Learning With Errors (LWE) from first principles</h2>
        <p>LWE was introduced by Regev (2005). Given noisy linear equations over Z<sub>q</sub>, recover secret vector s.</p>
        <p>Formal sample: pick random a ∈ Z<sub>q</sub><sup>n</sup>, compute b = &lt;a, s&gt; + e mod q with small error e. Given many (a,b), recover s.</p>
        <p>Without noise this is linear algebra; with noise, equations become inconsistent and decoding is hard.</p>
        <blockquote>Educational LWE — toy parameters, not production. Toy interactive demo uses n=3, q=97, and e ∈ {-1, 0, 1}.</blockquote>
      </article>

      <article class="card grid-two">
        <div>
          <h3>Interactive toy LWE demo</h3>
          <div class="controls">
            <span>s =</span>
            <label class="sr-only" for="s0">Secret s[0]</label>
            <input id="s0" type="number" min="0" max="96" value="${g.lweSecret[0]}" aria-label="Secret s[0]" />
            <label class="sr-only" for="s1">Secret s[1]</label>
            <input id="s1" type="number" min="0" max="96" value="${g.lweSecret[1]}" aria-label="Secret s[1]" />
            <label class="sr-only" for="s2">Secret s[2]</label>
            <input id="s2" type="number" min="0" max="96" value="${g.lweSecret[2]}" aria-label="Secret s[2]" />
          </div>
          <div class="controls">
            <button id="rand-secret">Random secret</button>
            <button id="gen-samples">Generate 5 LWE samples</button>
            <button id="solve-clean">Solve without noise</button>
            <button id="solve-noisy">Solve with noise</button>
          </div>
          <div class="noise-slider-wrap">
            <label for="noise-mag">Error magnitude: <strong>${g.lweNoiseMag}</strong></label>
            <input id="noise-mag" type="range" min="0" max="48" value="${g.lweNoiseMag}" />
            <span>${g.lweNoiseMag===0?`No noise`:g.lweNoiseMag<=3?`Small (solvable)`:g.lweNoiseMag<=12?`Medium (hard)`:`Large (impossible)`}</span>
          </div>
          <p role="status" aria-live="polite">${g.lweOutcome}</p>
        </div>
        <div>
          <button class="collapsible-toggle" aria-expanded="${g.openCollapsibles.has(`lwe-detail`)}" data-collapse="lwe-detail">Ring-LWE vs plain LWE</button>
          <div class="collapsible-body ${g.openCollapsibles.has(`lwe-detail`)?`open`:``}" id="lwe-detail">
          <ul>
            <li>Plain LWE (FrodoKEM): A is a random n×n matrix, no ring structure.</li>
            <li>Ring/Module-LWE (ML-KEM): structured polynomial algebra gives faster and smaller operations.</li>
            <li>FrodoKEM design choice: keep only the plain LWE assumption.</li>
          </ul>
          <p>Historical context: Regev (2005), Ring-LWE by Lyubashevsky-Peikert-Regev (2010), FrodoKEM (2016) "Take off the ring".</p>
          </div>
        </div>
      </article>

      <article class="card table-wrap">
        <h3>Generated samples (a, b)</h3>
        <table>
          <caption class="sr-only">LWE sample equations</caption>
          <thead><tr><th scope="col">#</th><th scope="col">a</th><th scope="col">b</th><th scope="col">error e</th></tr></thead>
          <tbody>
            ${g.lweSamples.map((e,t)=>`<tr><td>${t+1}</td><td>[${e.a.join(`, `)}]</td><td>${e.b}</td><td>${e.e}</td></tr>`).join(``)}
          </tbody>
        </table>
      </article>

      <article class="card callout">
        <strong>Why this matters:</strong> LWE underlies much of modern post-quantum KEM design. Removing ring structure increases conservatism at significant size cost.
      </article>

      <article class="card">
        <h3>Animated: A·s + e = b mod q</h3>
        <p>Watch each row of A multiplied by secret s, then error e added. This is how each LWE sample is computed.</p>
        <button id="run-matrix-anim" ${g.matrixAnimRunning?`disabled`:``}>Animate A·s + e</button>
        <div id="matrix-anim-container">${g.matrixAnimHtml}</div>
      </article>
    </section>

    <section class="panel ${g.activeTab===`keygen`?`visible`:``}" id="panel-keygen" role="tabpanel" aria-labelledby="tab-keygen" ${g.activeTab===`keygen`?``:`hidden`}>
      <article class="card">
        <h2>FrodoKEM key generation</h2>
        <p>Conceptual flow: seed → expand A (SHAKE-128), sample S and E from noise distribution, compute B = A·S + E mod q, publish (seed<sub>A</sub>, B).</p>
        <p>For FrodoKEM-976, n=976 and n̄=8. A full 976×976 matrix of 16-bit values would be about 1.9MB, so only seed<sub>A</sub> is stored.</p>
        <div class="controls">
          <label for="param-select">Parameter set</label>
          <select id="param-select">
            <option value="frodo640" ${g.selectedParam===`frodo640`?`selected`:``}>FrodoKEM-640</option>
            <option value="frodo976" ${g.selectedParam===`frodo976`?`selected`:``}>FrodoKEM-976</option>
            <option value="frodo1344" ${g.selectedParam===`frodo1344`?`selected`:``}>FrodoKEM-1344</option>
          </select>
          <button id="run-keygen">Generate keypair</button>
        </div>
      </article>

      <article class="card grid-two">
        <div>
          <h3>Real FrodoKEM sizes</h3>
          <div class="table-wrap">
            <table>
              <caption class="sr-only">FrodoKEM parameter sizes</caption>
              <thead><tr><th scope="col">Set</th><th scope="col">Public key</th><th scope="col">Private key</th><th scope="col">Security</th></tr></thead>
              <tbody>
                <tr><td>FrodoKEM-640</td><td>9,616 bytes</td><td>19,888 bytes</td><td>~103-bit PQ</td></tr>
                <tr><td>FrodoKEM-976</td><td>15,632 bytes</td><td>31,296 bytes</td><td>~150-bit PQ</td></tr>
                <tr><td>FrodoKEM-1344</td><td>21,520 bytes</td><td>43,088 bytes</td><td>~207-bit PQ</td></tr>
              </tbody>
            </table>
          </div>
          <p>Generated public key preview: <code>${g.keygenPreview||`--`}</code></p>
          <p>Private key size: ${g.keygenSkSize||`--`} bytes</p>
          <p>Generation time: ${g.keygenMs?`${g.keygenMs.toFixed(3)} ms`:`--`}</p>
          <p>${g.keygenRatio||``}</p>
        </div>
        <div>
          <h3>Public key size bar chart</h3>
          <div class="bar-group">
            <div class="bar-line">
              <strong>ML-KEM-768: 1,184 bytes</strong>
              <div class="bar-track"><div class="bar-fill" style="--w: ${(1184/o.publicKey*100).toFixed(1)}%;"></div></div>
            </div>
            <div class="bar-line">
              <strong>${o.label}: ${o.publicKey.toLocaleString()} bytes</strong>
              <div class="bar-track"><div class="bar-fill" style="--w: 100%;"></div></div>
            </div>
          </div>
          <p>Ratio: ${o.label} public key is about ${(o.publicKey/1184).toFixed(1)}× larger than ML-KEM-768.</p>
        </div>
      </article>

      <article class="card callout">
        <strong>Why this matters:</strong> Large keys are the price of avoiding ring/module structure. For high-value long-term secrets, this tradeoff can be acceptable.
      </article>
    </section>

    <section class="panel ${g.activeTab===`kem`?`visible`:``}" id="panel-kem" role="tabpanel" aria-labelledby="tab-kem" ${g.activeTab===`kem`?``:`hidden`}>
      <article class="card">
        <h2>Encapsulation and decapsulation</h2>
        <p>Conceptual encapsulation: sample S′, E′, E″, compute B′ = A·S′ + E′ and V = B·S′ + E″, encode message, output ciphertext (B′, C), derive shared secret via KDF.</p>
        <p>Conceptual decapsulation: compute W = B′·S, recover message, re-encapsulate for validation, derive same shared secret.</p>
        <div class="controls">
          <button id="kem-gen">Generate Alice keypair</button>
          <button id="kem-encap">Bob encapsulates</button>
          <button id="kem-decap">Alice decapsulates</button>
          <button id="kem-tamper">Tamper with ciphertext</button>
        </div>
        <p role="status" aria-live="polite">${g.kemStatus}</p>
      </article>

      <article class="card grid-two">
        <div>
          <h3>Ciphertext and secret</h3>
          <p>Ciphertext preview: <code>${g.kemCiphertext?l(g.kemCiphertext,64):`--`}</code></p>
          <p>Bob shared secret (32 bytes): <code>${g.kemBobSecret?c(g.kemBobSecret):`--`}</code></p>
          <p>Alice shared secret (32 bytes): <code>${g.kemAliceSecret?c(g.kemAliceSecret):`--`}</code></p>
          <p>Encapsulation time: ${g.kemEncapMs?`${g.kemEncapMs.toFixed(3)} ms`:`--`}</p>
          <p>Decapsulation time: ${g.kemDecapMs?`${g.kemDecapMs.toFixed(3)} ms`:`--`}</p>
          ${g.kemPreTamperCt?`<div class="ct-diff">${d(g.kemPreTamperCt,g.kemCiphertext)}</div>`:``}
          <p class="${p?`status-ok`:`status-bad`}">${g.kemAliceSecret&&g.kemBobSecret?p?`✓ Secrets match`:`✗ Secrets mismatch`:`--`}</p>
        </div>
        <div>
          <h3>Real ciphertext sizes</h3>
          <table>
            <caption class="sr-only">FrodoKEM ciphertext sizes</caption>
            <thead><tr><th scope="col">Parameter set</th><th scope="col">Ciphertext</th></tr></thead>
            <tbody>
              <tr><td>FrodoKEM-640</td><td>9,720 bytes</td></tr>
              <tr><td>FrodoKEM-976</td><td>15,744 bytes</td></tr>
              <tr><td>FrodoKEM-1344</td><td>21,632 bytes</td></tr>
            </tbody>
          </table>
          <p>ML-KEM-768 ciphertext: 1,088 bytes.</p>
        </div>
      </article>

      <article class="card callout">
        <strong>Why this matters:</strong> FrodoKEM-976 ciphertext is about 15KB. For infrequent, high-value key exchanges this overhead is often acceptable.
      </article>
    </section>

    <section class="panel ${g.activeTab===`compare`?`visible`:``}" id="panel-compare" role="tabpanel" aria-labelledby="tab-compare" ${g.activeTab===`compare`?``:`hidden`}>
      <article class="card">
        <h2>FrodoKEM vs ML-KEM: conservative choice</h2>
        <p>Run a side-by-side operation simulation to compare practical timing shape with published size and security properties.</p>
        <button id="run-compare">Run side-by-side operation</button>
        <p role="status" aria-live="polite">${g.compareBench}</p>
      </article>

      <article class="card table-wrap">
        <table>
          <caption class="sr-only">FrodoKEM-976 vs ML-KEM-768 comparison</caption>
          <thead>
            <tr><th scope="col">Property</th><th scope="col">FrodoKEM-976</th><th scope="col">ML-KEM-768</th></tr>
          </thead>
          <tbody>
            <tr><td>Hardness assumption</td><td>Plain LWE</td><td>Module-LWE (ring)</td></tr>
            <tr><td>Public key</td><td>15,632 bytes</td><td>1,184 bytes</td></tr>
            <tr><td>Ciphertext</td><td>15,744 bytes</td><td>1,088 bytes</td></tr>
            <tr><td>Shared secret</td><td>24 bytes</td><td>32 bytes</td></tr>
            <tr><td>Classical security</td><td>~192 bits</td><td>~192 bits</td></tr>
            <tr><td>PQ security</td><td>~150 bits</td><td>~178 bits</td></tr>
            <tr><td>Key generation</td><td>${g.compareRows.frodo.keygen.toFixed(3)} ms</td><td>${g.compareRows.mlkem.keygen.toFixed(3)} ms</td></tr>
            <tr><td>Encapsulation</td><td>${g.compareRows.frodo.encaps.toFixed(3)} ms</td><td>${g.compareRows.mlkem.encaps.toFixed(3)} ms</td></tr>
            <tr><td>Decapsulation</td><td>${g.compareRows.frodo.decaps.toFixed(3)} ms</td><td>${g.compareRows.mlkem.decaps.toFixed(3)} ms</td></tr>
            <tr><td>NIST status</td><td>Round 4 alternate</td><td>FIPS 203 standard</td></tr>
            <tr><td>Ring structure</td><td>None</td><td>Module / ring</td></tr>
            <tr><td>Deployment</td><td>Niche, high-value</td><td>Default PQ KEM</td></tr>
          </tbody>
        </table>
      </article>

      <article class="card decision">
        <button class="collapsible-toggle" aria-expanded="${g.openCollapsibles.has(`decision-tree`)}" data-collapse="decision-tree">Decision tree</button>
        <div class="collapsible-body ${g.openCollapsibles.has(`decision-tree`)?`open`:``}" id="decision-tree">
        <p>Post-quantum TLS or general use → <strong>ML-KEM-768</strong>.</p>
        <p>Maximum conservatism and size is acceptable → <strong>FrodoKEM-976</strong>.</p>
        <p>Archive secrecy horizon 20+ years → <strong>FrodoKEM-1344</strong>.</p>
        <p>Need smallest keys and fastest operation → <strong>ML-KEM-512</strong>.</p>
        <p>Maximum assurance recommendation: <code>SS = KDF(SS_mlkem || SS_frodo)</code>.</p>
        <p>Kyber Vault cross-link: <a href="https://systemslibrarian.github.io/crypto-lab-kyber-vault/" target="_blank" rel="noopener">https://systemslibrarian.github.io/crypto-lab-kyber-vault/</a></p>
        </div>
      </article>

      <article class="card">
        <h3>Hybrid KEM walkthrough</h3>
        <p>Combine ML-KEM-768 + FrodoKEM-976 shared secrets into one hybrid secret. Security holds if <em>either</em> KEM remains secure.</p>
        <button id="run-hybrid">Run hybrid KEM derivation</button>
        <p role="status" aria-live="polite">${g.hybridStatus}</p>
        ${g.hybridCombinedSS?`
        <div class="hybrid-box">
          <div class="hybrid-secrets">
            <div>
              <strong>ML-KEM-768 SS:</strong><br>
              <code>${c(g.hybridMlkemSS)}</code>
            </div>
            <div>
              <strong>FrodoKEM-976 SS:</strong><br>
              <code>${c(g.hybridFrodoSS)}</code>
            </div>
          </div>
          <div>
            <strong>Hybrid SS = KDF(SS_mlkem || SS_frodo):</strong><br>
            <span class="hybrid-final">${c(g.hybridCombinedSS)}</span>
          </div>
        </div>`:``}
      </article>

      <article class="card callout">
        <strong>Why this matters:</strong> Ring-LWE risk remains theoretical, not a known break. FrodoKEM is explicit insurance against future structural breakthroughs.
      </article>
    </section>

    <section class="panel ${g.activeTab===`errors`?`visible`:``}" id="panel-errors" role="tabpanel" aria-labelledby="tab-errors" ${g.activeTab===`errors`?``:`hidden`}>
      <article class="card">
        <h2>Error distribution: where security lives</h2>
        <p>FrodoKEM uses discrete table-sampled errors approximating Gaussian behavior. Errors must be random enough for security and small enough for correctness.</p>
        <div class="controls">
          <button id="sample-errors">Sample 1000 errors</button>
          <button id="run-failure">Run toy decryption failure</button>
          <button id="run-fail-chart">Failure probability chart</button>
        </div>
        <p role="status" aria-live="polite">${g.errorSummary}</p>
        <p role="status" aria-live="polite">${g.failureSummary}</p>
      </article>

      <article class="card grid-two">
        <div>
          <h3>Histogram (selected: ${o.label})</h3>
          <div class="histogram" role="img" aria-label="Error distribution histogram for ${o.label}, showing sampled counts per error value">
            ${g.errorHistogram.map(e=>`<div class="hist-row"><span>${e.value}</span><div class="hist-track"><div class="hist-fill" style="--w:${e.count/f*100}%;"></div></div><span>${e.count}</span></div>`).join(``)}
          </div>
        </div>
        <div>
          <h3>Error comparison table</h3>
          <table>
            <caption class="sr-only">Error distribution comparison by scheme</caption>
            <thead><tr><th scope="col">Scheme</th><th scope="col">Error type</th><th scope="col">σ</th><th scope="col">Max error</th></tr></thead>
            <tbody>
              <tr><td>FrodoKEM-640</td><td>Discrete, table-sampled</td><td>2.8</td><td>±12</td></tr>
              <tr><td>FrodoKEM-976</td><td>Discrete, table-sampled</td><td>2.3</td><td>±10</td></tr>
              <tr><td>ML-KEM-768</td><td>Centered binomial CBD(3)</td><td>1.22</td><td>±3</td></tr>
            </tbody>
          </table>
          <p>FrodoKEM-976 decryption failure target: &lt; 2<sup>-150</sup>.</p>
        </div>
      </article>

      ${g.failProbs.length>0?`
      <article class="card">
        <h3>Failure probability vs error magnitude (toy q=17)</h3>
        <div class="fail-chart">
          ${g.failProbs.map(e=>{let t=e.rate*100,n=e.rate===0?`safe`:e.rate<.15?`risky`:`broken`;return`<div class="fail-row"><span>±${e.maxErr}</span><div class="fail-track"><div class="fail-fill ${n}" style="--w:${Math.max(t,1)}%;"></div></div><span>${t.toFixed(1)}%</span></div>`}).join(``)}
        </div>
        <p>Green = 0% failure, yellow = occasional, red = frequent. The cliff is sharp — small increases in error magnitude cause catastrophic failure rates.</p>
      </article>`:``}

      <article class="card callout">
        <strong>Why this matters:</strong> Error distributions are the bridge between LWE proofs and practical implementations. FrodoKEM chooses conservative parameters even at performance cost.
      </article>
    </section>

    <section class="panel ${g.activeTab===`landscape`?`visible`:``}" id="panel-landscape" role="tabpanel" aria-labelledby="tab-landscape" ${g.activeTab===`landscape`?``:`hidden`}>
      <article class="card">
        <h2>FrodoKEM in the PQ KEM landscape</h2>
        <div class="table-wrap">
          <table>
            <caption class="sr-only">Post-quantum KEM landscape comparison</caption>
            <thead><tr><th scope="col">KEM</th><th scope="col">Basis</th><th scope="col">NIST status</th><th scope="col">Key size</th><th scope="col">Speed</th></tr></thead>
            <tbody>
              <tr><td>ML-KEM</td><td>Module-LWE</td><td>FIPS 203 (2024)</td><td>~1KB</td><td>Fast</td></tr>
              <tr><td>FrodoKEM</td><td>Plain LWE</td><td>Round 4 alternate</td><td>~15KB</td><td>Slower</td></tr>
              <tr><td>BIKE</td><td>Code-based</td><td>Round 4 alternate</td><td>~1.5KB</td><td>Slow</td></tr>
              <tr><td>HQC</td><td>Code-based</td><td>Round 4 alternate</td><td>~3KB</td><td>Slow</td></tr>
              <tr><td>Classic McEliece</td><td>Code-based</td><td>Round 4 alternate</td><td>~261KB</td><td>Slow</td></tr>
            </tbody>
          </table>
        </div>
      </article>

      <article class="card grid-two">
        <div>
          <h3>Cross-demo links</h3>
          <ul>
            <li><a href="https://systemslibrarian.github.io/crypto-lab-kyber-vault/" target="_blank" rel="noopener">ML-KEM demo</a></li>
            <li><a href="https://systemslibrarian.github.io/crypto-lab-bike-vault/" target="_blank" rel="noopener">BIKE demo</a></li>
            <li><a href="https://systemslibrarian.github.io/crypto-lab-hqc-vault/" target="_blank" rel="noopener">HQC demo</a></li>
            <li><a href="https://systemslibrarian.github.io/crypto-lab-mceliece-gate/" target="_blank" rel="noopener">Classic McEliece demo</a></li>
            <li><a href="https://systemslibrarian.github.io/crypto-compare/" target="_blank" rel="noopener">Crypto Compare dashboard</a></li>
          </ul>
        </div>
        <div>
          <button class="collapsible-toggle" aria-expanded="${g.openCollapsibles.has(`belt-suspenders`)}" data-collapse="belt-suspenders">Belt-and-suspenders recommendation</button>
          <div class="collapsible-body ${g.openCollapsibles.has(`belt-suspenders`)?`open`:``}" id="belt-suspenders">
          <p>For most deployments, ML-KEM-768 is enough. For highest assurance, combine ML-KEM-768 + FrodoKEM-976.</p>
          <p>Hybrid secret derivation: <code>SS = KDF(SS_mlkem || SS_frodo)</code>. Security holds if either KEM remains secure.</p>
          <p>20-year horizon framing: FrodoKEM is explicit insurance against uncertain long-term structural risk.</p>
          <p>Deployment notes: FrodoKEM was originated at Microsoft Research and appears in high-assurance hybrid deployments such as Amazon s2n-tls options.</p>
          </div>
        </div>
      </article>

      <article class="card callout">
        <strong>Why this matters:</strong> FrodoKEM is not the default KEM. It is the conservative option for secrets where long-term risk tolerance is near zero.
      </article>
    </section>

    <section class="panel ${g.activeTab===`divide`?`visible`:``}" id="panel-divide" role="tabpanel" aria-labelledby="tab-divide" ${g.activeTab===`divide`?``:`hidden`}>

      <article class="card">
        <h2>Two Philosophies, One Problem</h2>
        <div class="table-wrap">
          <table class="divide-table">
            <caption class="sr-only">Structured vs structureless lattice comparison</caption>
            <thead>
              <tr>
                <th scope="col"></th>
                <th scope="col">Structured Lattices (NIST path)</th>
                <th scope="col">Structureless Lattices (China path)</th>
              </tr>
            </thead>
            <tbody>
              <tr><td>Math basis</td><td>Ring-LWE / Module-LWE</td><td>Plain LWE (no ring)</td></tr>
              <tr><td>Speed</td><td>Fast — NTT-optimized</td><td>Slower — matrix multiply</td></tr>
              <tr><td>Key sizes</td><td>Compact (~800 B – 1.5 KB)</td><td>Large (~10–20 KB)</td></tr>
              <tr><td>Security proof</td><td>Reduction gap exists</td><td>Cleaner worst-case reduction</td></tr>
              <tr class="divide-highlight"><td>Algebraic attack surface</td><td>Present</td><td>Absent</td></tr>
              <tr><td>Standards status</td><td>NIST FIPS 203/204 (2024)</td><td>China target: ~2028–2029</td></tr>
              <tr><td>Named algorithms</td><td>ML-KEM, ML-DSA, FALCON</td><td>S-Cloud+ (announced)</td></tr>
            </tbody>
          </table>
        </div>
        <p>Algebraic lattice schemes gain their speed from a mathematical shortcut: polynomial ring arithmetic, accelerated by the Number Theoretic Transform (NTT). That same structure is an extra attack surface — one that the underlying plain-LWE hardness proof does not cover. Whether that gap will ever be exploited is unknown. That uncertainty is exactly what drives the structureless approach.</p>
      </article>

      <article class="card">
        <h2>S-Cloud+ and the Structureless Bet</h2>
        <blockquote>
          "International standards based on algebraic lattices have some degree of security degradation. But structureless cryptographic algorithms basically do not have this problem."
          <footer>— Wang Xiaoyun, Tsinghua University Institute for Advanced Study, National People's Congress, Beijing, March 2026</footer>
        </blockquote>
        <p>China's leading structureless algorithm candidate is S-Cloud+, developed by Chinese cryptographers and actively promoted as the domestic alternative to ML-KEM. Its design philosophy is the same as FrodoKEM: plain LWE over an integer matrix, no ring structure, no NTT. As of April 2026, S-Cloud+ does not have a public cryptographic specification — its parameter sets, key sizes, and exact security proofs are not yet published. What is known is its philosophical commitment: trade performance for the most conservative possible security foundation.</p>
        <p>In February 2025, China's Institute of Commercial Cryptography Standards (OSCCA) issued a global call for post-quantum algorithm proposals — a direct parallel to NIST's 2016 competition, with a distinctly different technical direction baked in. Wang Xiaoyun projected a three-to-five year timeline to domestic standards, with finance and energy sectors first in line for migration.</p>
        <p>The motivation is not purely mathematical. Every major technological power wants cryptographic independence — the ability to deploy standards it controls, audits, and trusts. China's earlier development of SM2, SM3, and SM4 (classical cryptography standards) and their mandatory domestic use established this pattern. S-Cloud+ is its post-quantum continuation.</p>
      </article>

      <article class="card">
        <h2>Even NIST Hedged</h2>
        <p>In March 2025, NIST selected <strong>HQC</strong> — a code-based algorithm using completely different mathematics (error-correcting codes, not lattices) — as a fourth backup standard. Dustin Moody, NIST's PQC project lead, stated the rationale directly: having a fallback in case ML-KEM proves vulnerable.</p>
        <p>This is the Western establishment quietly acknowledging what China has said loudly: the algebraic lattice bet might not be safe forever.</p>
        <ul>
          <li><strong>China's approach:</strong> Don't use algebraic lattices to begin with. Use plain LWE (S-Cloud+).</li>
          <li><strong>NIST's approach:</strong> Use algebraic lattices (ML-KEM) as the primary standard, but hold HQC in reserve in case of a breakthrough.</li>
        </ul>
        <p>Both strategies acknowledge the same risk. They differ in how much they trust the algebraic structure.</p>
      </article>

      <article class="card">
        <h2>FrodoKEM as the Bridge</h2>
        <p>FrodoKEM is not S-Cloud+. But they are philosophical siblings — both plain LWE, both structureless, both accepting the performance cost to gain the cleaner security proof. When China finalizes S-Cloud+ parameters and publishes its specification, the math you have explored in Exhibits 1–5 of this demo is the math that will underlie it. FrodoKEM is the working, publicly specified, NIST-evaluated embodiment of exactly the approach China has chosen as its strategic bet.</p>
        <div class="timeline">
          <div class="timeline-item"><span class="timeline-year">2016</span><span class="timeline-text">FrodoKEM published (Bos et al., Microsoft Research)</span></div>
          <div class="timeline-item"><span class="timeline-year">2022</span><span class="timeline-text">FrodoKEM eliminated from NIST Round 4 — performance concerns</span></div>
          <div class="timeline-item"><span class="timeline-year">2024</span><span class="timeline-text">NIST finalizes ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205)</span></div>
          <div class="timeline-item"><span class="timeline-year">2025</span><span class="timeline-text">NIST selects HQC as backup standard (March)</span></div>
          <div class="timeline-item"><span class="timeline-year">2025</span><span class="timeline-text">China OSCCA issues global PQC algorithm call (February)</span></div>
          <div class="timeline-item"><span class="timeline-year">2026</span><span class="timeline-text">Wang Xiaoyun announces S-Cloud+ direction at NPC (March)</span></div>
          <div class="timeline-item"><span class="timeline-year">~2028</span><span class="timeline-text">China domestic PQC standards expected</span></div>
        </div>
      </article>

      <article class="card">
        <h2>Explore the Full Landscape</h2>
        <ul>
          <li><a href="https://systemslibrarian.github.io/crypto-lab-kyber-vault/" target="_blank" rel="noopener"><strong>kyber-vault</strong></a> — ML-KEM structured lattice KEM (the NIST standard that S-Cloud+ is the alternative to)</li>
          <li><a href="https://systemslibrarian.github.io/crypto-lab-dilithium-seal/" target="_blank" rel="noopener"><strong>dilithium-seal</strong></a> — ML-DSA structured lattice signatures (FIPS 204)</li>
          <li><a href="https://systemslibrarian.github.io/crypto-lab-bike-vault/" target="_blank" rel="noopener"><strong>bike-vault</strong></a> — BIKE code-based KEM (same mathematical family as HQC, NIST's hedge)</li>
          <li><a href="https://systemslibrarian.github.io/crypto-lab-hqc-vault/" target="_blank" rel="noopener"><strong>hqc-vault</strong></a> — HQC code-based KEM (NIST's actual backup standard)</li>
        </ul>
      </article>

    </section>
  </main>
  `,h.querySelectorAll(`[data-tab]`).forEach(e=>{e.addEventListener(`click`,()=>{g.activeTab=e.dataset.tab,history.pushState(null,``,`#`+g.activeTab),A()})});let m=Array.from(h.querySelectorAll(`[role="tab"]`));m.forEach((e,t)=>{e.setAttribute(`tabindex`,e.classList.contains(`active`)?`0`:`-1`),e.addEventListener(`keydown`,e=>{let n=-1;e.key===`ArrowRight`||e.key===`ArrowDown`?n=(t+1)%m.length:e.key===`ArrowLeft`||e.key===`ArrowUp`?n=(t-1+m.length)%m.length:e.key===`Home`?n=0:e.key===`End`&&(n=m.length-1),n>=0&&(e.preventDefault(),m[n].focus(),m[n].click())})}),h.querySelectorAll(`.collapsible-toggle`).forEach(e=>{e.addEventListener(`click`,()=>{let t=e.dataset.collapse;if(!t)return;let n=h.querySelector(`#${t}`);if(!n)return;let r=g.openCollapsibles.has(t);r?g.openCollapsibles.delete(t):g.openCollapsibles.add(t),n.classList.toggle(`open`),e.setAttribute(`aria-expanded`,String(!r))})});let _=h.querySelector(`#theme-toggle`);_&&_.addEventListener(`click`,()=>{let e=S()===`dark`?`light`:`dark`;C(e);let t=w(e);_.textContent=t.icon,_.setAttribute(`aria-label`,t.label)}),h.querySelector(`#rand-secret`)?.addEventListener(`click`,()=>{g.lweSecret=[y(0,96),y(0,96),y(0,96)],g.lweOutcome=`Secret randomized to [${g.lweSecret.join(`, `)}].`,g.lweSamples=[],A()}),h.querySelector(`#gen-samples`)?.addEventListener(`click`,()=>{let e=parseInt(h.querySelector(`#s0`)?.value??`0`,10)||0,n=parseInt(h.querySelector(`#s1`)?.value??`0`,10)||0,r=parseInt(h.querySelector(`#s2`)?.value??`0`,10)||0;g.lweSecret=[t(e,97),t(n,97),t(r,97)],g.lweSamples=a(g.lweSecret,!0,g.lweNoiseMag),g.lweCleanSamples=a(g.lweSecret,!1),g.lweOutcome=`Generated 5 noisy samples and 3 noiseless equations from the selected secret.`,A()});let E=h.querySelector(`#noise-mag`);E?.addEventListener(`input`,()=>{g.lweNoiseMag=parseInt(E.value,10);let e=E.closest(`.noise-slider-wrap`)?.querySelector(`label`);e&&(e.innerHTML=`Error magnitude: <strong>${g.lweNoiseMag}</strong>`);let t=E.closest(`.noise-slider-wrap`)?.querySelector(`span:last-child`);if(t&&(t.textContent=g.lweNoiseMag===0?`No noise`:g.lweNoiseMag<=3?`Small (solvable)`:g.lweNoiseMag<=12?`Medium (hard)`:`Large (impossible)`),g.lweSamples.length>0){g.lweSamples=a(g.lweSecret,!0,g.lweNoiseMag),g.lweOutcome=`Regenerated samples with error magnitude ±${g.lweNoiseMag}.`;let e=h.querySelector(`#panel-lwe table tbody`);e&&(e.innerHTML=g.lweSamples.map((e,t)=>`<tr><td>${t+1}</td><td>[${e.a.join(`, `)}]</td><td>${e.b}</td><td>${e.e}</td></tr>`).join(``));let t=h.querySelector(`#panel-lwe [role="status"]`);t&&(t.textContent=g.lweOutcome)}}),h.querySelector(`#run-matrix-anim`)?.addEventListener(`click`,()=>{k()}),h.querySelector(`#solve-clean`)?.addEventListener(`click`,()=>{if(g.lweCleanSamples.length<3){g.lweOutcome=`Generate samples first.`,A();return}let e=i(g.lweCleanSamples);g.lweOutcome=e?`Without noise, Gaussian elimination recovers s = [${e.join(`, `)}] exactly.`:`Noiseless system was singular; generate new samples.`,A()}),h.querySelector(`#solve-noisy`)?.addEventListener(`click`,()=>{if(g.lweSamples.length<3){g.lweOutcome=`Generate noisy samples first.`,A();return}let e=i(g.lweSamples.slice(0,3));if(!e){g.lweOutcome=`Noisy system was singular; regenerate samples.`,A();return}let n=g.lweSamples.map(n=>t(r(n.a,e,97)-n.b,97));g.lweOutcome=n.some(e=>e!==0)?`With noise, equations become inconsistent. Candidate s = [${e.join(`, `)}], residuals = [${n.join(`, `)}].`:`This sample happened to fit exactly. Try again; noise usually breaks exact solving.`,A()});let j=h.querySelector(`#param-select`);j?.addEventListener(`change`,()=>{g.selectedParam=j.value,A()}),h.querySelector(`#run-keygen`)?.addEventListener(`click`,()=>{let t=e[g.selectedParam],n=performance.now(),r=b(t.publicKey),i=b(t.privateKey);g.keygenMs=performance.now()-n,g.keygenPreview=l(r,64),g.keygenSkSize=i.length,g.keygenRatio=`${t.label} public key (${t.publicKey} bytes) is ${(t.publicKey/1184).toFixed(1)}x ML-KEM-768.`,A()}),h.querySelector(`#kem-gen`)?.addEventListener(`click`,()=>{g.aliceSeed=b(32),g.kemCiphertext=null,g.kemBobSecret=null,g.kemAliceSecret=null,g.kemEncapMs=0,g.kemDecapMs=0,g.kemPreTamperCt=null,g.kemStatus=`Alice keypair generated. Bob can encapsulate now.`,A()}),h.querySelector(`#kem-encap`)?.addEventListener(`click`,async()=>{if(!g.aliceSeed){g.kemStatus=`Generate Alice keypair first.`,A();return}try{let t=e[g.selectedParam],n=performance.now(),r=b(t.ciphertext),i=await x(u(g.aliceSeed,r));g.kemEncapMs=performance.now()-n,g.kemCiphertext=r,g.kemBobSecret=i,g.kemAliceSecret=null,g.kemPreTamperCt=null,g.kemStatus=`Bob encapsulated using ${t.label}. Ciphertext size = ${t.ciphertext} bytes.`}catch{g.kemStatus=`Encapsulation failed — crypto.subtle may be unavailable (requires HTTPS).`}A()}),h.querySelector(`#kem-decap`)?.addEventListener(`click`,async()=>{if(!g.aliceSeed||!g.kemCiphertext){g.kemStatus=`Encapsulate first.`,A();return}try{let e=performance.now();g.kemAliceSecret=await x(u(g.aliceSeed,g.kemCiphertext)),g.kemDecapMs=performance.now()-e,g.kemStatus=`Alice decapsulated and derived a shared secret.`}catch{g.kemStatus=`Decapsulation failed — crypto.subtle may be unavailable (requires HTTPS).`}A()}),h.querySelector(`#kem-tamper`)?.addEventListener(`click`,()=>{if(!g.kemCiphertext){g.kemStatus=`No ciphertext to tamper.`,A();return}g.kemPreTamperCt||=new Uint8Array(g.kemCiphertext);let e=v(g.kemCiphertext.length);g.kemCiphertext[e]=g.kemCiphertext[e]^1,g.kemStatus=`Tampered ciphertext byte at index ${e}. Next decapsulation should mismatch.`,A()}),h.querySelector(`#run-compare`)?.addEventListener(`click`,()=>{g.compareRows.frodo.keygen=T(26e4),g.compareRows.frodo.encaps=T(22e4),g.compareRows.frodo.decaps=T(23e4),g.compareRows.mlkem.keygen=T(22e3),g.compareRows.mlkem.encaps=T(18e3),g.compareRows.mlkem.decaps=T(19e3),g.compareBench=`Side-by-side operation complete. Frodo path is intentionally heavier than ML-KEM path.`,A()}),h.querySelector(`#run-hybrid`)?.addEventListener(`click`,async()=>{try{g.hybridMlkemSS=b(32),g.hybridFrodoSS=b(24),g.hybridCombinedSS=await x(u(g.hybridMlkemSS,g.hybridFrodoSS)),g.hybridStatus=`Hybrid derivation complete. Combined secret is 32 bytes via SHA-256.`}catch{g.hybridStatus=`Hybrid derivation failed — crypto.subtle may be unavailable (requires HTTPS).`}A()}),h.querySelector(`#sample-errors`)?.addEventListener(`click`,()=>{let t=e[g.selectedParam];g.errorHistogram=D(t),g.errorSummary=`Sampled 1000 errors for ${t.label}. Distribution is centered near 0 with thin tails.`,A()}),h.querySelector(`#run-failure`)?.addEventListener(`click`,()=>{g.failureSummary=O(),A()}),h.querySelector(`#run-fail-chart`)?.addEventListener(`click`,()=>{g.failProbs=s(),A()}),h.querySelector(`.tab.active`)?.scrollIntoView({behavior:`smooth`,block:`nearest`,inline:`nearest`})}window.addEventListener(`popstate`,()=>{let e=p();e&&e!==g.activeTab&&(g.activeTab=e,A())}),g.lweSamples=a(g.lweSecret,!0,g.lweNoiseMag),g.lweCleanSamples=a(g.lweSecret,!1),A();
//# sourceMappingURL=index-D678-v54.js.map