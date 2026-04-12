(function(){let e=document.createElement(`link`).relList;if(e&&e.supports&&e.supports(`modulepreload`))return;for(let e of document.querySelectorAll(`link[rel="modulepreload"]`))n(e);new MutationObserver(e=>{for(let t of e)if(t.type===`childList`)for(let e of t.addedNodes)e.tagName===`LINK`&&e.rel===`modulepreload`&&n(e)}).observe(document,{childList:!0,subtree:!0});function t(e){let t={};return e.integrity&&(t.integrity=e.integrity),e.referrerPolicy&&(t.referrerPolicy=e.referrerPolicy),e.crossOrigin===`use-credentials`?t.credentials=`include`:e.crossOrigin===`anonymous`?t.credentials=`omit`:t.credentials=`same-origin`,t}function n(e){if(e.ep)return;e.ep=!0;let n=t(e);fetch(e.href,n)}})();var e={frodo640:{id:`frodo640`,label:`FrodoKEM-640`,n:640,q:2**15,classicalBits:128,pqBits:103,publicKey:9616,privateKey:19888,ciphertext:9720,sigma:2.8,maxError:12},frodo976:{id:`frodo976`,label:`FrodoKEM-976`,n:976,q:2**16,classicalBits:192,pqBits:150,publicKey:15632,privateKey:31296,ciphertext:15744,sigma:2.3,maxError:10},frodo1344:{id:`frodo1344`,label:`FrodoKEM-1344`,n:1344,q:2**16,classicalBits:256,pqBits:207,publicKey:21520,privateKey:43088,ciphertext:21632,sigma:1.4,maxError:8}},t=document.querySelector(`#app`);if(!t)throw Error(`App root not found`);var n=t,r={activeTab:`lwe`,selectedParam:`frodo976`,lweSecret:[3,7,11],lweSamples:[],lweCleanSamples:[],lweOutcome:`Generate toy LWE samples, then test solving with and without noise.`,keygenPreview:``,keygenSkSize:0,keygenMs:0,keygenRatio:``,aliceSeed:null,kemCiphertext:null,kemBobSecret:null,kemAliceSecret:null,kemEncapMs:0,kemDecapMs:0,kemStatus:`Generate Alice keypair to begin encapsulation.`,compareBench:``,compareRows:{frodo:{keygen:0,encaps:0,decaps:0},mlkem:{keygen:0,encaps:0,decaps:0}},errorHistogram:[],errorSummary:`Sample 1000 errors to visualize FrodoKEM-style discrete distribution.`,failureSummary:`Run the toy decryption-failure demo (n=4, q=17) with oversized errors.`};function i(){let e=new Uint32Array(1);return crypto.getRandomValues(e),e[0]}function a(e){return e<=0?0:i()%e}function o(e,t){return e+a(t-e+1)}function s(e,t){let n=e%t;return n<0?n+t:n}function c(e,t){let n=0,r=1,i=t,a=s(e,t);for(;a!==0;){let e=Math.floor(i/a);[n,r]=[r,n-e*r],[i,a]=[a,i-e*a]}if(i!==1)throw Error(`No modular inverse`);return s(n,t)}function l(e){let t=e.slice(0,3).map(e=>[...e.a,e.b]);for(let e=0;e<3;e+=1){let n=e;for(;n<3&&t[n][e]===0;)n+=1;if(n===3)return null;n!==e&&([t[e],t[n]]=[t[n],t[e]]);let r=c(t[e][e],97);for(let n=e;n<4;n+=1)t[e][n]=s(t[e][n]*r,97);for(let n=0;n<3;n+=1){if(n===e)continue;let r=t[n][e];for(let i=e;i<4;i+=1)t[n][i]=s(t[n][i]-r*t[e][i],97)}}return[t[0][3],t[1][3],t[2][3]]}function u(e,t,n){return s(e[0]*t[0]+e[1]*t[1]+e[2]*t[2],n)}function d(e,t){let n=t?5:3,r=[];for(;r.length<n;){let n=[o(0,96),o(0,96),o(0,96)],i=t?[-1,0,1][a(3)]:0,c=s(u(n,e,97)+i,97);r.push({a:n,b:c,e:i})}return r}function f(e){let t=new Uint8Array(e);return crypto.getRandomValues(t),t}function p(e,t=64){return`${Array.from(e,e=>e.toString(16).padStart(2,`0`)).join(``).slice(0,t*2)}... [${e.length-t} more bytes]`}async function m(e){let t=new Uint8Array(e.byteLength);t.set(e);let n=await crypto.subtle.digest(`SHA-256`,t);return new Uint8Array(n)}function h(e,t){let n=new Uint8Array(e.length+t.length);return n.set(e),n.set(t,e.length),n}function g(){return document.documentElement.getAttribute(`data-theme`)===`light`?`light`:`dark`}function _(e){document.documentElement.setAttribute(`data-theme`,e),localStorage.setItem(`theme`,e)}function v(e){return e===`dark`?{icon:`🌙`,label:`Switch to light mode`}:{icon:`☀️`,label:`Switch to dark mode`}}function y(e){let t=performance.now(),n=0;for(let t=0;t<e;t+=1)n=s(n+(t*17+11)*(t*19+7),65536);return performance.now()-t+n*0}function b(e,t){return Math.exp(-(e*e)/(2*t*t))}function x(e,t){let n=[],r=[],a=0;for(let i=-e;i<=e;i+=1){let e=b(i,t);n.push(i),r.push(e),a+=e}let o=i()/4294967295*a,s=0;for(let e=0;e<n.length;e+=1)if(s+=r[e],o<=s)return n[e];return 0}function S(e){let t=new Map;for(let n=-e.maxError;n<=e.maxError;n+=1)t.set(n,0);for(let n=0;n<1e3;n+=1){let n=x(e.maxError,e.sigma);t.set(n,(t.get(n)??0)+1)}return Array.from(t.entries()).map(([e,t])=>({value:e,count:t}))}function C(){let e=0;for(;e<25;){e+=1;let t=a(2),n=o(0,16),r=o(-6,6),i=s(n+(t===1?8:0)+r,17),c=Math.min(s(i-0,17),s(0-i,17)),l=+(Math.min(s(i-8,17),s(8-i,17))<c);if(l!==t)return`Toy failure observed: message=${t}, encoded=${i} mod 17, accumulated error=${r}, recovered=${l}. Oversized errors break correctness.`}return`No failure occurred in 25 tries. Re-run: oversized errors still cause frequent failures at toy scale.`}function w(e){return e?Array.from(e,e=>e.toString(16).padStart(2,`0`)).join(``):`--`}function T(){let t=v(g()),i=e[r.selectedParam],c=Math.max(1,...r.errorHistogram.map(e=>e.count)),b=r.kemAliceSecret&&r.kemBobSecret?w(r.kemAliceSecret)===w(r.kemBobSecret):!1;n.innerHTML=`
  <main id="main-content" class="shell">
    <header class="hero-header">
      <button id="theme-toggle" class="theme-toggle" type="button" aria-label="${t.label}">${t.icon}</button>
      <p class="eyebrow">crypto-lab demo</p>
      <h1>Frodo Vault: FrodoKEM without ring structure</h1>
      <p class="subhead">The conservative post-quantum KEM based on plain LWE. Bigger keys, simpler assumption.</p>
    </header>

    <nav class="tabs" role="tablist" aria-label="FrodoKEM exhibits">
      <button class="tab ${r.activeTab===`lwe`?`active`:``}" data-tab="lwe" role="tab">1. LWE Problem</button>
      <button class="tab ${r.activeTab===`keygen`?`active`:``}" data-tab="keygen" role="tab">2. Key Generation</button>
      <button class="tab ${r.activeTab===`kem`?`active`:``}" data-tab="kem" role="tab">3. Encap / Decap</button>
      <button class="tab ${r.activeTab===`compare`?`active`:``}" data-tab="compare" role="tab">4. Frodo vs ML-KEM</button>
      <button class="tab ${r.activeTab===`errors`?`active`:``}" data-tab="errors" role="tab">5. Error Distribution</button>
      <button class="tab ${r.activeTab===`landscape`?`active`:``}" data-tab="landscape" role="tab">6. PQ Landscape</button>
    </nav>

    <section class="panel ${r.activeTab===`lwe`?`visible`:``}" id="panel-lwe">
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
            <label>s =</label>
            <input id="s0" type="number" min="0" max="96" value="${r.lweSecret[0]}" />
            <input id="s1" type="number" min="0" max="96" value="${r.lweSecret[1]}" />
            <input id="s2" type="number" min="0" max="96" value="${r.lweSecret[2]}" />
          </div>
          <div class="controls">
            <button id="rand-secret">Random secret</button>
            <button id="gen-samples">Generate 5 LWE samples</button>
            <button id="solve-clean">Solve without noise</button>
            <button id="solve-noisy">Solve with noise</button>
          </div>
          <p>${r.lweOutcome}</p>
        </div>
        <div>
          <h3>Ring-LWE vs plain LWE</h3>
          <ul>
            <li>Plain LWE (FrodoKEM): A is a random n×n matrix, no ring structure.</li>
            <li>Ring/Module-LWE (ML-KEM): structured polynomial algebra gives faster and smaller operations.</li>
            <li>FrodoKEM design choice: keep only the plain LWE assumption.</li>
          </ul>
          <p>Historical context: Regev (2005), Ring-LWE by Lyubashevsky-Peikert-Regev (2010), FrodoKEM (2016) "Take off the ring".</p>
        </div>
      </article>

      <article class="card table-wrap">
        <h3>Generated samples (a, b)</h3>
        <table>
          <thead><tr><th>#</th><th>a</th><th>b</th><th>error e</th></tr></thead>
          <tbody>
            ${r.lweSamples.map((e,t)=>`<tr><td>${t+1}</td><td>[${e.a.join(`, `)}]</td><td>${e.b}</td><td>${e.e}</td></tr>`).join(``)}
          </tbody>
        </table>
      </article>

      <article class="card callout">
        <strong>Why this matters:</strong> LWE underlies much of modern post-quantum KEM design. Removing ring structure increases conservatism at significant size cost.
      </article>
    </section>

    <section class="panel ${r.activeTab===`keygen`?`visible`:``}" id="panel-keygen">
      <article class="card">
        <h2>FrodoKEM key generation</h2>
        <p>Conceptual flow: seed → expand A (SHAKE-128), sample S and E from noise distribution, compute B = A·S + E mod q, publish (seed<sub>A</sub>, B).</p>
        <p>For FrodoKEM-976, n=976 and n̄=8. A full 976×976 matrix of 16-bit values would be about 1.9MB, so only seed<sub>A</sub> is stored.</p>
        <div class="controls">
          <label for="param-select">Parameter set</label>
          <select id="param-select">
            <option value="frodo640" ${r.selectedParam===`frodo640`?`selected`:``}>FrodoKEM-640</option>
            <option value="frodo976" ${r.selectedParam===`frodo976`?`selected`:``}>FrodoKEM-976</option>
            <option value="frodo1344" ${r.selectedParam===`frodo1344`?`selected`:``}>FrodoKEM-1344</option>
          </select>
          <button id="run-keygen">Generate keypair</button>
        </div>
      </article>

      <article class="card grid-two">
        <div>
          <h3>Real FrodoKEM sizes</h3>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Set</th><th>Public key</th><th>Private key</th><th>Security</th></tr></thead>
              <tbody>
                <tr><td>FrodoKEM-640</td><td>9,616 bytes</td><td>19,888 bytes</td><td>~103-bit PQ</td></tr>
                <tr><td>FrodoKEM-976</td><td>15,632 bytes</td><td>31,296 bytes</td><td>~150-bit PQ</td></tr>
                <tr><td>FrodoKEM-1344</td><td>21,520 bytes</td><td>43,088 bytes</td><td>~207-bit PQ</td></tr>
              </tbody>
            </table>
          </div>
          <p>Generated public key preview: <code>${r.keygenPreview||`--`}</code></p>
          <p>Private key size: ${r.keygenSkSize||`--`} bytes</p>
          <p>Generation time: ${r.keygenMs?`${r.keygenMs.toFixed(3)} ms`:`--`}</p>
          <p>${r.keygenRatio||``}</p>
        </div>
        <div>
          <h3>Public key size bar chart</h3>
          <div class="bar-group">
            <div class="bar-line">
              <strong>ML-KEM-768: 1,184 bytes</strong>
              <div class="bar-track"><div class="bar-fill" style="--w: 8%;"></div></div>
            </div>
            <div class="bar-line">
              <strong>FrodoKEM-976: 15,632 bytes</strong>
              <div class="bar-track"><div class="bar-fill" style="--w: 100%;"></div></div>
            </div>
          </div>
          <p>Ratio: FrodoKEM-976 public key is about 13.2× larger than ML-KEM-768.</p>
        </div>
      </article>

      <article class="card callout">
        <strong>Why this matters:</strong> Large keys are the price of avoiding ring/module structure. For high-value long-term secrets, this tradeoff can be acceptable.
      </article>
    </section>

    <section class="panel ${r.activeTab===`kem`?`visible`:``}" id="panel-kem">
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
        <p>${r.kemStatus}</p>
      </article>

      <article class="card grid-two">
        <div>
          <h3>Ciphertext and secret</h3>
          <p>Ciphertext preview: <code>${r.kemCiphertext?p(r.kemCiphertext,64):`--`}</code></p>
          <p>Bob shared secret (32 bytes): <code>${r.kemBobSecret?w(r.kemBobSecret):`--`}</code></p>
          <p>Alice shared secret (32 bytes): <code>${r.kemAliceSecret?w(r.kemAliceSecret):`--`}</code></p>
          <p>Encapsulation time: ${r.kemEncapMs?`${r.kemEncapMs.toFixed(3)} ms`:`--`}</p>
          <p>Decapsulation time: ${r.kemDecapMs?`${r.kemDecapMs.toFixed(3)} ms`:`--`}</p>
          <p class="${b?`status-ok`:`status-bad`}">${r.kemAliceSecret&&r.kemBobSecret?b?`✓ Secrets match`:`✗ Secrets mismatch`:`--`}</p>
        </div>
        <div>
          <h3>Real ciphertext sizes</h3>
          <table>
            <thead><tr><th>Parameter set</th><th>Ciphertext</th></tr></thead>
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

    <section class="panel ${r.activeTab===`compare`?`visible`:``}" id="panel-compare">
      <article class="card">
        <h2>FrodoKEM vs ML-KEM: conservative choice</h2>
        <p>Run a side-by-side operation simulation to compare practical timing shape with published size and security properties.</p>
        <button id="run-compare">Run side-by-side operation</button>
        <p>${r.compareBench}</p>
      </article>

      <article class="card table-wrap">
        <table>
          <thead>
            <tr><th>Property</th><th>FrodoKEM-976</th><th>ML-KEM-768</th></tr>
          </thead>
          <tbody>
            <tr><td>Hardness assumption</td><td>Plain LWE</td><td>Module-LWE (ring)</td></tr>
            <tr><td>Public key</td><td>15,632 bytes</td><td>1,184 bytes</td></tr>
            <tr><td>Ciphertext</td><td>15,744 bytes</td><td>1,088 bytes</td></tr>
            <tr><td>Shared secret</td><td>24 bytes</td><td>32 bytes</td></tr>
            <tr><td>Classical security</td><td>~192 bits</td><td>~192 bits</td></tr>
            <tr><td>PQ security</td><td>~150 bits</td><td>~178 bits</td></tr>
            <tr><td>Key generation</td><td>${r.compareRows.frodo.keygen.toFixed(3)} ms</td><td>${r.compareRows.mlkem.keygen.toFixed(3)} ms</td></tr>
            <tr><td>Encapsulation</td><td>${r.compareRows.frodo.encaps.toFixed(3)} ms</td><td>${r.compareRows.mlkem.encaps.toFixed(3)} ms</td></tr>
            <tr><td>Decapsulation</td><td>${r.compareRows.frodo.decaps.toFixed(3)} ms</td><td>${r.compareRows.mlkem.decaps.toFixed(3)} ms</td></tr>
            <tr><td>NIST status</td><td>Round 4 alternate</td><td>FIPS 203 standard</td></tr>
            <tr><td>Ring structure</td><td>None</td><td>Module / ring</td></tr>
            <tr><td>Deployment</td><td>Niche, high-value</td><td>Default PQ KEM</td></tr>
          </tbody>
        </table>
      </article>

      <article class="card decision">
        <h3>Decision tree</h3>
        <p>Post-quantum TLS or general use → <strong>ML-KEM-768</strong>.</p>
        <p>Maximum conservatism and size is acceptable → <strong>FrodoKEM-976</strong>.</p>
        <p>Archive secrecy horizon 20+ years → <strong>FrodoKEM-1344</strong>.</p>
        <p>Need smallest keys and fastest operation → <strong>ML-KEM-512</strong>.</p>
        <p>Maximum assurance recommendation: <code>SS = KDF(SS_mlkem || SS_frodo)</code>.</p>
        <p>Kyber Vault cross-link: <a href="https://systemslibrarian.github.io/crypto-lab-kyber-vault/" target="_blank" rel="noopener">https://systemslibrarian.github.io/crypto-lab-kyber-vault/</a></p>
      </article>

      <article class="card callout">
        <strong>Why this matters:</strong> Ring-LWE risk remains theoretical, not a known break. FrodoKEM is explicit insurance against future structural breakthroughs.
      </article>
    </section>

    <section class="panel ${r.activeTab===`errors`?`visible`:``}" id="panel-errors">
      <article class="card">
        <h2>Error distribution: where security lives</h2>
        <p>FrodoKEM uses discrete table-sampled errors approximating Gaussian behavior. Errors must be random enough for security and small enough for correctness.</p>
        <div class="controls">
          <button id="sample-errors">Sample 1000 errors</button>
          <button id="run-failure">Run toy decryption failure</button>
        </div>
        <p>${r.errorSummary}</p>
        <p>${r.failureSummary}</p>
      </article>

      <article class="card grid-two">
        <div>
          <h3>Histogram (selected: ${i.label})</h3>
          <div class="histogram">
            ${r.errorHistogram.map(e=>`<div class="hist-row"><span>${e.value}</span><div class="hist-track"><div class="hist-fill" style="--w:${e.count/c*100}%;"></div></div><span>${e.count}</span></div>`).join(``)}
          </div>
        </div>
        <div>
          <h3>Error comparison table</h3>
          <table>
            <thead><tr><th>Scheme</th><th>Error type</th><th>σ</th><th>Max error</th></tr></thead>
            <tbody>
              <tr><td>FrodoKEM-640</td><td>Discrete, table-sampled</td><td>2.8</td><td>±12</td></tr>
              <tr><td>FrodoKEM-976</td><td>Discrete, table-sampled</td><td>2.3</td><td>±10</td></tr>
              <tr><td>ML-KEM-768</td><td>Centered binomial CBD(3)</td><td>1.22</td><td>±3</td></tr>
            </tbody>
          </table>
          <p>FrodoKEM-976 decryption failure target: &lt; 2<sup>-150</sup>.</p>
        </div>
      </article>

      <article class="card callout">
        <strong>Why this matters:</strong> Error distributions are the bridge between LWE proofs and practical implementations. FrodoKEM chooses conservative parameters even at performance cost.
      </article>
    </section>

    <section class="panel ${r.activeTab===`landscape`?`visible`:``}" id="panel-landscape">
      <article class="card">
        <h2>FrodoKEM in the PQ KEM landscape</h2>
        <div class="table-wrap">
          <table>
            <thead><tr><th>KEM</th><th>Basis</th><th>NIST status</th><th>Key size</th><th>Speed</th></tr></thead>
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
          <h3>Belt-and-suspenders recommendation</h3>
          <p>For most deployments, ML-KEM-768 is enough. For highest assurance, combine ML-KEM-768 + FrodoKEM-976.</p>
          <p>Hybrid secret derivation: <code>SS = KDF(SS_mlkem || SS_frodo)</code>. Security holds if either KEM remains secure.</p>
          <p>20-year horizon framing: FrodoKEM is explicit insurance against uncertain long-term structural risk.</p>
          <p>Deployment notes: FrodoKEM was originated at Microsoft Research and appears in high-assurance hybrid deployments such as Amazon s2n-tls options.</p>
        </div>
      </article>

      <article class="card callout">
        <strong>Why this matters:</strong> FrodoKEM is not the default KEM. It is the conservative option for secrets where long-term risk tolerance is near zero.
      </article>
    </section>
  </main>
  `,n.querySelectorAll(`[data-tab]`).forEach(e=>{e.addEventListener(`click`,()=>{r.activeTab=e.dataset.tab,T()})});let x=n.querySelector(`#theme-toggle`);x&&x.addEventListener(`click`,()=>{let e=g()===`dark`?`light`:`dark`;_(e);let t=v(e);x.textContent=t.icon,x.setAttribute(`aria-label`,t.label)}),n.querySelector(`#rand-secret`)?.addEventListener(`click`,()=>{r.lweSecret=[o(0,96),o(0,96),o(0,96)],r.lweOutcome=`Secret randomized to [${r.lweSecret.join(`, `)}].`,r.lweSamples=[],T()}),n.querySelector(`#gen-samples`)?.addEventListener(`click`,()=>{let e=Number((n.querySelector(`#s0`)?.value??`0`).trim()),t=Number((n.querySelector(`#s1`)?.value??`0`).trim()),i=Number((n.querySelector(`#s2`)?.value??`0`).trim());r.lweSecret=[s(e,97),s(t,97),s(i,97)],r.lweSamples=d(r.lweSecret,!0),r.lweCleanSamples=d(r.lweSecret,!1),r.lweOutcome=`Generated 5 noisy samples and 3 noiseless equations from the selected secret.`,T()}),n.querySelector(`#solve-clean`)?.addEventListener(`click`,()=>{if(r.lweCleanSamples.length<3){r.lweOutcome=`Generate samples first.`,T();return}let e=l(r.lweCleanSamples);r.lweOutcome=e?`Without noise, Gaussian elimination recovers s = [${e.join(`, `)}] exactly.`:`Noiseless system was singular; generate new samples.`,T()}),n.querySelector(`#solve-noisy`)?.addEventListener(`click`,()=>{if(r.lweSamples.length<3){r.lweOutcome=`Generate noisy samples first.`,T();return}let e=l(r.lweSamples.slice(0,3));if(!e){r.lweOutcome=`Noisy system was singular; regenerate samples.`,T();return}let t=r.lweSamples.map(t=>s(u(t.a,e,97)-t.b,97));r.lweOutcome=t.some(e=>e!==0)?`With noise, equations become inconsistent. Candidate s = [${e.join(`, `)}], residuals = [${t.join(`, `)}].`:`This sample happened to fit exactly. Try again; noise usually breaks exact solving.`,T()});let E=n.querySelector(`#param-select`);E?.addEventListener(`change`,()=>{r.selectedParam=E.value,T()}),n.querySelector(`#run-keygen`)?.addEventListener(`click`,()=>{let t=e[r.selectedParam],n=performance.now(),i=f(t.publicKey),a=f(t.privateKey);r.keygenMs=performance.now()-n,r.keygenPreview=p(i,64),r.keygenSkSize=a.length,r.keygenRatio=`${t.label} public key (${t.publicKey} bytes) is ${(t.publicKey/1184).toFixed(1)}x ML-KEM-768.`,T()}),n.querySelector(`#kem-gen`)?.addEventListener(`click`,()=>{r.aliceSeed=f(32),r.kemCiphertext=null,r.kemBobSecret=null,r.kemAliceSecret=null,r.kemStatus=`Alice keypair generated. Bob can encapsulate now.`,T()}),n.querySelector(`#kem-encap`)?.addEventListener(`click`,async()=>{if(!r.aliceSeed){r.kemStatus=`Generate Alice keypair first.`,T();return}let t=e[r.selectedParam],n=performance.now(),i=f(t.ciphertext),a=await m(h(r.aliceSeed,i));r.kemEncapMs=performance.now()-n,r.kemCiphertext=i,r.kemBobSecret=a,r.kemAliceSecret=null,r.kemStatus=`Bob encapsulated using ${t.label}. Ciphertext size = ${t.ciphertext} bytes.`,T()}),n.querySelector(`#kem-decap`)?.addEventListener(`click`,async()=>{if(!r.aliceSeed||!r.kemCiphertext){r.kemStatus=`Encapsulate first.`,T();return}let e=performance.now();r.kemAliceSecret=await m(h(r.aliceSeed,r.kemCiphertext)),r.kemDecapMs=performance.now()-e,r.kemStatus=`Alice decapsulated and derived a shared secret.`,T()}),n.querySelector(`#kem-tamper`)?.addEventListener(`click`,()=>{if(!r.kemCiphertext){r.kemStatus=`No ciphertext to tamper.`,T();return}let e=a(r.kemCiphertext.length);r.kemCiphertext[e]=r.kemCiphertext[e]^1,r.kemStatus=`Tampered ciphertext byte at index ${e}. Next decapsulation should mismatch.`,T()}),n.querySelector(`#run-compare`)?.addEventListener(`click`,()=>{r.compareRows.frodo.keygen=y(26e4),r.compareRows.frodo.encaps=y(22e4),r.compareRows.frodo.decaps=y(23e4),r.compareRows.mlkem.keygen=y(22e3),r.compareRows.mlkem.encaps=y(18e3),r.compareRows.mlkem.decaps=y(19e3),r.compareBench=`Side-by-side operation complete. Frodo path is intentionally heavier than ML-KEM path.`,T()}),n.querySelector(`#sample-errors`)?.addEventListener(`click`,()=>{let t=e[r.selectedParam];r.errorHistogram=S(t),r.errorSummary=`Sampled 1000 errors for ${t.label}. Distribution is centered near 0 with thin tails.`,T()}),n.querySelector(`#run-failure`)?.addEventListener(`click`,()=>{r.failureSummary=C(),T()})}r.lweSamples=d(r.lweSecret,!0),r.lweCleanSamples=d(r.lweSecret,!1),T();
//# sourceMappingURL=index-CN7FpFeP.js.map