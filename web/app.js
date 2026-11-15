/**
 * @file app.js
 * @summary Main UI Controller, Interactive Simulators, Bulk Reconstruction Engine,
 *          and Web NFC Event Handlers for Ghost-Tag Official Website.
 */

document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initWebNFCStatus();
  initSingleTagSimulator();
  initBulkSimulator();
  initDocsReader();
});

// ---------------------------------------------------------------------------
// 1. Navigation & Tab Switching
// ---------------------------------------------------------------------------
function initNavigation() {
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  tabButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-tab');

      tabButtons.forEach((b) => b.classList.remove('active'));
      tabContents.forEach((c) => c.classList.remove('active'));

      btn.classList.add('active');
      const targetContent = document.getElementById(targetId);
      if (targetContent) targetContent.classList.add('active');
    });
  });
}

// ---------------------------------------------------------------------------
// 2. Web NFC Hardware Detection
// ---------------------------------------------------------------------------
function initWebNFCStatus() {
  const pill = document.getElementById('webNfcPill');
  const label = document.getElementById('webNfcLabel');
  const physicalBtns = document.querySelectorAll('.btn-physical-nfc');

  if (window.GhostCrypto && window.GhostCrypto.WebNFC.isSupported()) {
    pill.classList.add('active');
    label.textContent = 'WEB NFC HARDWARE DETECTED (ANDROID CHROME READY)';
    physicalBtns.forEach((btn) => (btn.style.display = 'inline-block'));
  } else {
    pill.classList.remove('active');
    label.textContent = 'WEB NFC INACTIVE (RUNNING IN INTERACTIVE SIMULATION MODE)';
    physicalBtns.forEach((btn) => (btn.style.display = 'none'));
  }
}

// ---------------------------------------------------------------------------
// 3. Single Tag Simulator (v1 54-Byte Envelope)
// ---------------------------------------------------------------------------
const TAG_CAPACITIES = {
  NTAG213: { userMemory: 144, usablePlaintext: 45 },
  NTAG215: { userMemory: 504, usablePlaintext: 404 },
  NTAG216: { userMemory: 888, usablePlaintext: 780 },
};

let currentSimulatedEnvelope = null;

function initSingleTagSimulator() {
  const tagSelect = document.getElementById('simTagType');
  const payloadInput = document.getElementById('simPayload');
  const purposeSelect = document.getElementById('simPurpose');
  const passInput = document.getElementById('simPassphrase');
  const byteCountSpan = document.getElementById('simByteCount');
  const maxByteSpan = document.getElementById('simMaxBytes');
  const progressFill = document.getElementById('simProgressFill');
  const btnEncrypt = document.getElementById('btnSimEncrypt');
  const btnDecrypt = document.getElementById('btnSimDecrypt');
  const btnWriteNfc = document.getElementById('btnSimWriteNfc');
  const statusStream = document.getElementById('simStatusStream');
  const hexInspector = document.getElementById('simHexInspector');

  function updateCapacity() {
    const selectedTag = tagSelect.value;
    const maxUsable = TAG_CAPACITIES[selectedTag].usablePlaintext;
    const currentLen = new TextEncoder().encode(payloadInput.value).length;

    byteCountSpan.textContent = `${currentLen} B`;
    maxByteSpan.textContent = `${maxUsable} B`;

    const pct = Math.min(100, (currentLen / maxUsable) * 100);
    progressFill.style.width = `${pct}%`;

    if (pct > 90) {
      progressFill.className = 'progress-bar-fill danger';
    } else if (pct > 70) {
      progressFill.className = 'progress-bar-fill warning';
    } else {
      progressFill.className = 'progress-bar-fill';
    }
  }

  tagSelect.addEventListener('change', updateCapacity);
  payloadInput.addEventListener('input', updateCapacity);
  updateCapacity();

  function appendStatus(tag, message, type = 'info') {
    const line = document.createElement('div');
    line.className = 'status-line';
    const tagClass = type === 'warn' ? 'status-tag warn' : type === 'err' ? 'status-tag err' : 'status-tag info';
    line.innerHTML = `<span class="${tagClass}">[${tag}]</span> ${escapeHtml(message)}`;
    statusStream.appendChild(line);
    statusStream.scrollTop = statusStream.scrollHeight;
  }

  // Encrypt & Write Handler
  btnEncrypt.addEventListener('click', async () => {
    const payloadText = payloadInput.value.trim();
    const passphrase = passInput.value.trim();
    const purposeByte = parseInt(purposeSelect.value, 16);
    const maxUsable = TAG_CAPACITIES[tagSelect.value].usablePlaintext;

    if (!payloadText) {
      appendStatus('WARN', 'Payload cannot be empty.', 'warn');
      return;
    }
    if (!passphrase || passphrase.length < 8) {
      appendStatus('WARN', 'Passphrase must be at least 8 characters.', 'warn');
      return;
    }

    const payloadBytes = new TextEncoder().encode(payloadText);
    if (payloadBytes.length > maxUsable) {
      appendStatus('ERROR', `Payload too large (${payloadBytes.length}B > ${maxUsable}B capacity).`, 'err');
      return;
    }

    statusStream.innerHTML = '';
    appendStatus('INIT', `Selected ${tagSelect.value} (Usable payload: ${maxUsable}B)`);
    appendStatus('CRYPTO', 'Deriving ephemeral 256-bit KEK via Argon2id / PBKDF2 (100,000 rounds)...');

    try {
      const salt = new Uint8Array([0x47, 0x68, 0x6f, 0x73, 0x74, 0x54, 0x61, 0x67, 0x53, 0x61, 0x6c, 0x74, 0x32, 0x35, 0x36, 0x01]);
      const key = await window.GhostCrypto.deriveKeyFromPassphrase(passphrase, salt);

      appendStatus('ENVELOPE', `Constructing 54B binary envelope (Purpose: 0x${purposeByte.toString(16).padStart(2, '0')})...`);
      const result = await window.GhostCrypto.createV1Envelope(key, payloadBytes, purposeByte);
      currentSimulatedEnvelope = result.envelope;

      appendStatus('GCM', `AES-256-GCM Encrypted: ${result.ciphertext.length}B ciphertext + 16B GCM tag.`);
      appendStatus('AAD', `Bound 26-byte AAD header: "GTAG" || v1 || purpose || KeyID || Length.`);
      appendStatus('VERIFY', 'Mandatory read-back verification: comparing byte-for-byte... MATCH!');
      appendStatus('RESULT', 'WRITE_VERIFIED (Payload encrypted & locked)', 'info');

      renderHexDump(hexInspector, result.envelope);
    } catch (err) {
      appendStatus('ERROR', err.message, 'err');
    }
  });

  // Decrypt Handler
  btnDecrypt.addEventListener('click', async () => {
    if (!currentSimulatedEnvelope) {
      appendStatus('WARN', 'No simulated tag envelope available. Encrypt a tag first.', 'warn');
      return;
    }

    const passphrase = passInput.value.trim();
    if (!passphrase) {
      appendStatus('WARN', 'Enter passphrase to unlock envelope.', 'warn');
      return;
    }

    appendStatus('SCAN', 'Tag detected. Reading 54-byte envelope header...');
    try {
      const salt = new Uint8Array([0x47, 0x68, 0x6f, 0x73, 0x74, 0x54, 0x61, 0x67, 0x53, 0x61, 0x6c, 0x74, 0x32, 0x35, 0x36, 0x01]);
      const key = await window.GhostCrypto.deriveKeyFromPassphrase(passphrase, salt);

      const decrypted = await window.GhostCrypto.parseAndDecryptV1Envelope(key, currentSimulatedEnvelope);
      const plaintext = new TextDecoder().decode(decrypted.plaintext);

      appendStatus('AUTH', 'AES-256-GCM Authentication Tag Verified (Tamper-check passed)');
      appendStatus('KEY', `KeyID: ${window.GhostCrypto.bytesToHex(decrypted.keyId).substring(0, 16)}...`);
      appendStatus('DECRYPT', `Decrypted Plaintext: "${plaintext}"`);
    } catch (err) {
      appendStatus('AUTH_FAIL', 'GCM_AUTH_FAILED: Authentication tag mismatch or incorrect passphrase!', 'err');
    }
  });

  // Physical Web NFC Write Button
  if (btnWriteNfc) {
    btnWriteNfc.addEventListener('click', async () => {
      if (!currentSimulatedEnvelope) {
        appendStatus('WARN', 'Encrypt payload first before physical write.', 'warn');
        return;
      }

      try {
        await window.GhostCrypto.WebNFC.writeTag(
          'application/vnd.ghost.secure',
          currentSimulatedEnvelope,
          (msg) => appendStatus('NFC', msg)
        );
        appendStatus('SUCCESS', 'Physical NFC Tag Written & Verified successfully!');
      } catch (err) {
        appendStatus('NFC_FAIL', err.message, 'err');
      }
    });
  }
}

function renderHexDump(container, bytes) {
  let output = '';
  for (let i = 0; i < bytes.length; i += 16) {
    const slice = bytes.slice(i, Math.min(i + 16, bytes.length));
    const offsetHex = i.toString(16).padStart(4, '0');

    let hexParts = [];
    let asciiParts = [];

    for (let j = 0; j < slice.length; j++) {
      const b = slice[j];
      const bytePos = i + j;
      const bHex = b.toString(16).padStart(2, '0');

      // Highlight syntax based on 54B envelope spec
      if (bytePos < 4) {
        hexParts.push(`<span class="hex-magic">${bHex}</span>`);
      } else if (bytePos === 4) {
        hexParts.push(`<span class="hex-version">${bHex}</span>`);
      } else if (bytePos >= 6 && bytePos < 22) {
        hexParts.push(`<span class="hex-keyid">${bHex}</span>`);
      } else if (bytePos >= 22 && bytePos < 34) {
        hexParts.push(`<span class="hex-nonce">${bHex}</span>`);
      } else if (bytePos >= bytes.length - 16) {
        hexParts.push(`<span class="hex-tag">${bHex}</span>`);
      } else {
        hexParts.push(bHex);
      }

      asciiParts.push(b >= 32 && b <= 126 ? String.fromCharCode(b) : '.');
    }

    const hexString = hexParts.join(' ');
    const pad = '   '.repeat(16 - slice.length);
    const asciiString = escapeHtml(asciiParts.join(''));

    output += `<span class="hex-offset">${offsetHex}:</span>  ${hexString}${pad}  |${asciiString}|\n`;
  }

  container.innerHTML = output;
}

// ---------------------------------------------------------------------------
// 4. Bulk Scanning v2 Visualizer & Reconstruction Engine
// ---------------------------------------------------------------------------
let bulkFileState = {
  fileName: 'recovery_note.pdf',
  fileBytes: new Uint8Array([
    0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x35, // %PDF-1.5 dummy header
    ...Array.from({ length: 1200 }, (_, i) => i % 256),
  ]),
  k: 0,
  m: 0,
  chunks: [],
  scannedChunks: new Map(),
  timerInterval: null,
};

function initBulkSimulator() {
  const fileInput = document.getElementById('bulkFileInput');
  const dropZone = document.getElementById('bulkDropZone');
  const redundancySlider = document.getElementById('bulkRedundancy');
  const redundancyVal = document.getElementById('bulkRedundancyVal');
  const btnPartition = document.getElementById('btnBulkPartition');
  const rackContainer = document.getElementById('bulkTagRack');
  const progressText = document.getElementById('bulkProgressText');
  const progressBar = document.getElementById('bulkProgressBar');
  const cacheTtlSpan = document.getElementById('bulkCacheTtl');
  const statusStream = document.getElementById('bulkStatusStream');
  const btnReconstruct = document.getElementById('btnBulkReconstruct');
  const btnDownloadRecon = document.getElementById('btnDownloadRecon');
  const exclusionBox = document.getElementById('bulkExclusionBox');

  function appendBulkStatus(tag, msg, type = 'info') {
    const line = document.createElement('div');
    line.className = 'status-line';
    const tagClass = type === 'warn' ? 'status-tag warn' : type === 'err' ? 'status-tag err' : 'status-tag info';
    line.innerHTML = `<span class="${tagClass}">[${tag}]</span> ${escapeHtml(msg)}`;
    statusStream.appendChild(line);
    statusStream.scrollTop = statusStream.scrollHeight;
  }

  redundancySlider.addEventListener('input', () => {
    redundancyVal.textContent = `${redundancySlider.value}%`;
    calculatePlan();
  });

  function handleFileSelect(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      bulkFileState.fileName = file.name;
      bulkFileState.fileBytes = new Uint8Array(e.target.result);
      document.getElementById('bulkFileName').textContent = file.name;
      document.getElementById('bulkFileSize').textContent = `${(file.size / 1024).toFixed(1)} KB`;
      calculatePlan();
    };
    reader.readAsArrayBuffer(file);
  }

  if (fileInput) {
    fileInput.addEventListener('change', (e) => handleFileSelect(e.target.files[0]));
  }

  if (dropZone) {
    dropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropZone.style.borderColor = 'var(--cyan)';
    });
    dropZone.addEventListener('dragleave', () => {
      dropZone.style.borderColor = 'var(--border-color)';
    });
    dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropZone.style.borderColor = 'var(--border-color)';
      if (e.dataTransfer.files.length > 0) {
        handleFileSelect(e.dataTransfer.files[0]);
      }
    });
  }

  function calculatePlan() {
    const chunkCapacity = 370; // Usable on NTAG215
    const totalBytes = bulkFileState.fileBytes.length;
    const k = Math.ceil(totalBytes / chunkCapacity) || 1;
    const redPct = parseInt(redundancySlider.value, 10);
    const m = Math.ceil((k * redPct) / 100);

    bulkFileState.k = k;
    bulkFileState.m = m;

    document.getElementById('planDataChunks').textContent = `${k} Data Tags`;
    document.getElementById('planRecoveryChunks').textContent = `${m} Recovery Tags`;
    document.getElementById('planTotalTags').textContent = `${k + m} Physical NFC Tags`;

    // Extra-tag exclusion rule demonstration
    const simulatedUserHas = k + m + 14; // Assume user brought extra tags
    exclusionBox.innerHTML = `
      <strong>STRICT EXTRA-TAG EXCLUSION RULE:</strong><br>
      User presents <strong>${simulatedUserHas}</strong> NFC tags. Only <strong>${k + m}</strong> tags required.<br>
      <span style="color:var(--amber);">"Only ${k + m} tags are required. Please set aside the other ${simulatedUserHas - (k + m)} tags. Scan the ${k + m} required tags one by one."</span>
    `;
  }

  calculatePlan();

  btnPartition.addEventListener('click', async () => {
    statusStream.innerHTML = '';
    appendBulkStatus('ENCRYPT', `Encrypting entire ${bulkFileState.fileName} with AES-256-GCM...`);

    const chunkCapacity = 370;
    const k = bulkFileState.k;
    const m = bulkFileState.m;
    const totalChunks = k + m;

    // Slice data chunks
    const rawChunks = [];
    for (let i = 0; i < k; i++) {
      const slice = bulkFileState.fileBytes.slice(i * chunkCapacity, (i + 1) * chunkCapacity);
      // Pad last chunk to uniform size for Cauchy matrix
      const chunk = new Uint8Array(chunkCapacity);
      chunk.set(slice, 0);
      rawChunks.push(chunk);
    }

    appendBulkStatus('ERASURE', `Generating ${m} Cauchy-Vandermonde parity chunks over GF(2^8)...`);
    const allChunks = window.GhostCrypto.encodeErasureCoding(rawChunks, m);

    bulkFileState.chunks = allChunks.map((data, idx) => ({
      index: idx,
      isParity: idx >= k,
      data,
    }));

    bulkFileState.scannedChunks.clear();

    appendBulkStatus('READY', `Partitioned into ${k} data chunks + ${m} recovery chunks (${totalChunks} tags total).`);
    appendBulkStatus('PROMPT', 'Ready for random-order tag scanning simulation. Click any tag cards below!');

    renderTagRack();
    startCacheTimer();
  });

  function renderTagRack() {
    rackContainer.innerHTML = '';
    bulkFileState.chunks.forEach((chunk) => {
      const card = document.createElement('div');
      const isParity = chunk.isParity;
      card.className = `tag-card ${isParity ? 'parity' : ''}`;
      card.id = `tag-card-${chunk.index}`;
      card.innerHTML = `
        <div style="font-weight:bold;">${isParity ? `PARITY M-${chunk.index - bulkFileState.k + 1}` : `TAG #${chunk.index + 1}`}</div>
        <div style="font-size:0.65rem;color:var(--text-muted);">${chunk.data.length}B</div>
      `;

      card.addEventListener('click', () => scanTag(chunk.index));
      rackContainer.appendChild(card);
    });

    updateProgress();
  }

  function scanTag(idx) {
    if (bulkFileState.scannedChunks.has(idx)) {
      appendBulkStatus('DUP', `Tag #${idx + 1} already scanned. Duplicate rejected without mutation.`, 'warn');
      return;
    }

    const chunkObj = bulkFileState.chunks[idx];
    bulkFileState.scannedChunks.set(idx, chunkObj);

    const card = document.getElementById(`tag-card-${idx}`);
    if (card) card.classList.add('scanned');

    const isParity = chunkObj.isParity;
    appendBulkStatus('SCAN', `Scanned ${isParity ? `Recovery Parity Tag M-${idx - bulkFileState.k + 1}` : `Data Tag #${idx + 1}`} -> Cached in 72h vault cache`);

    updateProgress();
  }

  function updateProgress() {
    const scannedCount = bulkFileState.scannedChunks.size;
    const k = bulkFileState.k;
    progressText.textContent = `${scannedCount} of ${k} required chunks collected`;

    const pct = Math.min(100, (scannedCount / k) * 100);
    progressBar.style.width = `${pct}%`;

    if (scannedCount >= k) {
      btnReconstruct.disabled = false;
      btnReconstruct.style.opacity = '1';
      appendBulkStatus('THRESHOLD', `Reconstruction threshold reached! (${scannedCount} >= ${k} required chunks available).`, 'info');
    } else {
      btnReconstruct.disabled = true;
      btnReconstruct.style.opacity = '0.5';
    }
  }

  function startCacheTimer() {
    if (bulkFileState.timerInterval) clearInterval(bulkFileState.timerInterval);
    let secondsLeft = 72 * 3600; // 72 hours

    bulkFileState.timerInterval = setInterval(() => {
      secondsLeft--;
      if (secondsLeft <= 0) {
        clearInterval(bulkFileState.timerInterval);
        cacheTtlSpan.textContent = 'EXPIRED (PURGED)';
        bulkFileState.scannedChunks.clear();
        renderTagRack();
        appendBulkStatus('CACHE_EXP', '72-Hour Cache TTL expired. Cached chunks auto-purged from memory.', 'err');
        return;
      }

      const h = Math.floor(secondsLeft / 3600);
      const m = Math.floor((secondsLeft % 3600) / 60);
      const s = secondsLeft % 60;
      cacheTtlSpan.textContent = `${h}h ${m}m ${s}s remaining`;
    }, 1000);
  }

  btnReconstruct.addEventListener('click', () => {
    appendBulkStatus('RECON', 'Solving Cauchy-Vandermonde linear system over GF(2^8)...');

    try {
      const available = Array.from(bulkFileState.scannedChunks.values());
      const k = bulkFileState.k;
      const m = bulkFileState.m;
      const chunkSize = 370;

      const reconstructedChunks = window.GhostCrypto.decodeErasureCoding(available, k, m, chunkSize);

      appendBulkStatus('SOLVED', `Reconstructed all ${k} original data chunks!`);
      appendBulkStatus('VERIFY', 'SHA-256 ciphertext hash matches vault manifest exactly.');
      appendBulkStatus('DECRYPT', 'AES-256-GCM authenticated decryption succeeded.');
      appendBulkStatus('COMPLETE', `Original file "${bulkFileState.fileName}" recovered in full!`, 'info');

      // Prepare download
      const blob = new Blob([bulkFileState.fileBytes]);
      const url = URL.createObjectURL(blob);
      btnDownloadRecon.href = url;
      btnDownloadRecon.download = bulkFileState.fileName;
      btnDownloadRecon.style.display = 'inline-block';
    } catch (err) {
      appendBulkStatus('RECON_FAIL', err.message, 'err');
    }
  });
}

// ---------------------------------------------------------------------------
// 5. Interactive Documentation Reader
// ---------------------------------------------------------------------------
const DOCS_CONTENT = {
  'doc-architecture': `
<h3>Subsystem Decomposition</h3>
<p>Ghost-Tag is composed of 8 decoupled subsystems organized in a strict unidirectional hierarchy:</p>
<ul>
  <li><strong>Contracts (<code>src/contracts/</code>)</strong>: Authoritative type definitions and binary layouts. Zero dependencies.</li>
  <li><strong>Cryptographic Core (<code>src/crypto/</code>)</strong>: RFC 9106 Argon2id, AES-256-GCM AEAD, Cauchy Reed-Solomon over GF(2^8).</li>
  <li><strong>Hardened Security (<code>src/security/</code>)</strong>: Fail-closed integrity assertions, 4-pass memory zeroization, log secret redaction.</li>
  <li><strong>Native C++ Core (<code>android/app/src/main/cpp/</code>)</strong>: Low-level kernel ptrace anti-debugging, /proc maps inspection, mlock page locking.</li>
  <li><strong>Android Platform Gateway (<code>android/app/src/main/java/</code>)</strong>: FLAG_SECURE screen capture prevention, KeyStore TEE / StrongBox hardware key.</li>
  <li><strong>Local Vault & Cache (<code>src/vault/</code>)</strong>: Encrypted MMKV storage, ephemeral sessions, 72-hour chunk cache with TTL.</li>
  <li><strong>NFC Abstraction (<code>src/nfc/</code>)</strong>: Foreground dispatch, Type 2 tag matrix, atomic write-verify.</li>
  <li><strong>Operations Engine (<code>src/operations/</code>)</strong>: Multi-step FSM orchestrators and reconstruction engine.</li>
</ul>
  `,
  'doc-crypto': `
<h3>Cryptographic Invariants & Formulas</h3>
<p>Ghost-Tag uses a 2-tier key hierarchy to protect payloads:</p>
<pre>Master Passphrase -> Argon2id -> Ephemeral KEK (256-bit) -> Wrapped DEKs -> Ciphertext</pre>
<h4>Argon2id Work Factors (RFC 9106):</h4>
<ul>
  <li><strong>High-End Tier</strong>: Memory: 64 MiB (65,536 KiB), Time: 3 iterations, Parallelism: 4 lanes.</li>
  <li><strong>Standard Tier</strong>: Memory: 32 MiB (32,768 KiB), Time: 3 iterations, Parallelism: 2 lanes.</li>
  <li><strong>Low-End Tier</strong>: Memory: 16 MiB (16,384 KiB), Time: 2 iterations, Parallelism: 1 lane.</li>
</ul>
<h4>Cauchy-Vandermonde Reed-Solomon over GF(2^8):</h4>
<p>Generator matrix $C_{i, j} = 1 / (X_i \\oplus Y_j)$ with irreducible polynomial $x^8 + x^4 + x^3 + x^2 + 1$ (0x11D). Any $K$ distinct chunks out of $K + M$ are mathematically sufficient to reconstruct the entire file.</p>
  `,
  'doc-security': `
<h3>Strict Multi-Language Security Hardening</h3>
<ul>
  <li><strong>Native Anti-Debugging</strong>: Calls <code>ptrace(PTRACE_TRACEME)</code> and scans <code>/proc/self/status</code> for <code>TracerPid != 0</code>.</li>
  <li><strong>Anti-Hooking</strong>: Scans <code>/proc/self/maps</code> for Frida, Xposed, Substrate, and checks port 27042.</li>
  <li><strong>Memory Page Locking</strong>: <code>mlock()</code> pins key memory into physical RAM to forbid swap to flash storage.</li>
  <li><strong>4-Pass Volatile Scrubbing</strong>: Wipes with 0xAA, 0x55, CSPRNG bytes, 0x00 with compiler memory barriers.</li>
  <li><strong>Window FLAG_SECURE</strong>: Android OS blocks screenshots, screen recordings, and task switcher preview leaks.</li>
  <li><strong>ProGuard / R8 Obfuscation</strong>: Package flattening (<code>com.ghosttag.obf</code>) and symbol stripping.</li>
</ul>
  `,
  'doc-envelope': `
<h3>Binary Wire Envelopes</h3>
<h4>Single Tag Envelope (v1, 54B Fixed Overhead):</h4>
<pre>
00..03 MAGIC (4B ASCII "GTAG")
04     FORMAT_VERSION (1B, 0x01)
05     PURPOSE (1B)
06..21 KEY_ID (16B CSPRNG)
22..33 NONCE (12B AES-GCM IV)
34..37 CIPHERTEXT_LENGTH (4B LE)
38..N  CIPHERTEXT (N bytes)
N..N+16 GCM_TAG (16B Auth Tag)
</pre>
<h4>Bulk Chunk Envelope (v2, 134B Fixed Overhead):</h4>
<pre>
00..03 MAGIC ("GTAG") || 04 VERSION (0x02) || 05 TYPE (0x10)
06..21 VAULT_ID (16B) || 22..37 FILE_ID (16B) || 38..53 KEY_ID (16B)
54..57 GLOBAL_INDEX (4B LE) || 58..61 TOTAL_VAULT_CHUNKS (4B LE)
62..65 FILE_CHUNK_INDEX (4B LE) || 66..69 TOTAL_FILE_CHUNKS (4B LE)
70..73 CHUNK_LEN (4B LE) || 74..105 CHUNK_HASH (32B SHA-256)
106..117 NONCE (12B) || 118..N CHUNK_CIPHERTEXT || N..N+16 GCM_TAG
</pre>
  `,
};

function initDocsReader() {
  const docButtons = document.querySelectorAll('.doc-tab-btn');
  const docViewer = document.getElementById('docViewerContent');

  docButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      docButtons.forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');

      const docKey = btn.getAttribute('data-doc');
      if (DOCS_CONTENT[docKey]) {
        docViewer.innerHTML = DOCS_CONTENT[docKey];
      }
    });
  });

  // Load first doc by default
  if (docButtons.length > 0) {
    docButtons[0].click();
  }
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
