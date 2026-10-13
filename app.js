// ==========================================
// MONITORAGGIO CONSUMABILI & FATTURAZIONI APP
// Mobile PWA Core Logic (Aggiornato con Scadenze Prescrizioni Mese)
// ==========================================

let allPatients = [];
let filteredPatients = [];
let currentTab = 'dashboard';
let currentDaFatturareSubtab = 'npnp';
let currentDaFatturareFilter = 'all_unbilled'; // 'all_unbilled' | 'no_matrix' | 'in_matrix' | 'all_micro_unbilled'
let currentMicroFilter = 'all';
let currentPatientType = 'micro'; // 'micro' | 'gc'
let selectedPrescriptionMonth = new Date().getMonth() + 1; // Mese corrente 1-12
let selectedPatient = null;
let patientForPrescription = null;

// PIN & Biometric State (Zero-Knowledge: nessun PIN o chiave salvati nel codice)
let enteredPin = '';
const PIN_HASH_KEY = 'mon_app_pin_sha256';
const BIOMETRIC_KEY = 'mon_app_bio_enabled';
const PBKDF2_SALT = 'Medtronic_CampaniaMolise_Salt_2026';

// Database IndexedDB
const DB_NAME = 'MonitoraggioConsumabiliDB';
const DB_VERSION = 1;
const STORE_NAME = 'patients';
const SCHEMA_VERSION_KEY = 'mon_app_schema_version';
const CURRENT_SCHEMA_VERSION = 'v5_aes256';

const MONTH_NAMES = {
  1: 'Gennaio', 2: 'Febbraio', 3: 'Marzo', 4: 'Aprile',
  5: 'Maggio', 6: 'Giugno', 7: 'Luglio', 8: 'Agosto',
  9: 'Settembre', 10: 'Ottobre', 11: 'Novembre', 12: 'Dicembre'
};

// ==================== INIZIALIZZAZIONE ====================
document.addEventListener('DOMContentLoaded', async () => {
  initPinState();
  await initDatabaseAndLoadData();
  if (allPatients.length > 0) {
    populateDropdownFilters();
    applyGlobalFilters();
  }
  highlightActiveMonthButton();
  lucide.createIcons();
});

// ==================== SICUREZZA & CIFRATURA AES-256-GCM ====================
async function computePinHash(pin) {
  const data = new TextEncoder().encode(PBKDF2_SALT + ':' + pin);
  const hashBuf = await window.crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function decryptPayloadWithPin(pin) {
  const resp = await fetch('initial_data.enc?v=' + CURRENT_SCHEMA_VERSION);
  if (!resp.ok) throw new Error('Impossibile scaricare archivio cifrato');
  const buf = await resp.arrayBuffer();
  const rawBytes = new Uint8Array(buf);
  const iv = rawBytes.slice(0, 12);
  const ciphertext = rawBytes.slice(12);

  const subtle = window.crypto.subtle;
  const keyMaterial = await subtle.importKey(
    'raw',
    new TextEncoder().encode(pin),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  const key = await subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: new TextEncoder().encode(PBKDF2_SALT),
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  // Se il PIN è errato, subtle.decrypt lancia un'eccezione crittografica (tag GCM non valido)
  const decryptedCompressed = await subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    ciphertext
  );

  const ds = new DecompressionStream('gzip');
  const decompressedStream = new Blob([decryptedCompressed]).stream().pipeThrough(ds);
  const jsonText = await new Response(decompressedStream).text();
  return JSON.parse(jsonText);
}

function initPinState() {
  updatePinDots();
  if (localStorage.getItem(BIOMETRIC_KEY) === 'true' && localStorage.getItem(PIN_HASH_KEY)) {
    setTimeout(() => triggerBiometrics(), 400);
  }
}

function pressPin(digit) {
  if (enteredPin.length < 4) {
    enteredPin += digit;
    updatePinDots();
    if (enteredPin.length === 4) {
      setTimeout(verifyPin, 80);
    }
  }
}

function deletePin() {
  if (enteredPin.length > 0) {
    enteredPin = enteredPin.slice(0, -1);
    updatePinDots();
  }
  document.getElementById('pinError').textContent = '';
}

function updatePinDots() {
  const dots = document.querySelectorAll('#pinDots div');
  dots.forEach((dot, idx) => {
    if (idx < enteredPin.length) {
      dot.className = 'w-3.5 h-3.5 rounded-full bg-sky-500 border-2 border-sky-400 scale-110 transition-all duration-150';
    } else {
      dot.className = 'w-3.5 h-3.5 rounded-full border-2 border-slate-600 transition-all duration-150';
    }
  });
}

async function verifyPin() {
  const candidatePin = enteredPin;
  const errEl = document.getElementById('pinError');
  const savedHash = localStorage.getItem(PIN_HASH_KEY);

  try {
    // Caso 1: Dati già presenti in IndexedDB e hash PIN già registrato sul dispositivo
    if (allPatients.length > 0 && savedHash) {
      const candidateHash = await computePinHash(candidatePin);
      if (candidateHash === savedHash) {
        unlockApp();
        return;
      } else {
        errEl.className = 'text-xs text-rose-400 font-medium h-4';
        errEl.textContent = 'PIN non corretto. Riprova.';
        enteredPin = '';
        updatePinDots();
        return;
      }
    }

    // Caso 2: Primo sblocco sul dispositivo -> Decifra initial_data.enc tramite AES-256-GCM con il PIN inserito
    errEl.className = 'text-xs text-sky-400 font-medium h-4';
    errEl.textContent = 'Decifratura archivio AES-256 in corso...';

    const data = await decryptPayloadWithPin(candidatePin);
    const freshPatients = data.patients || [];

    const db = await openDB();
    const stored = await getAllPatientsFromDB(db);
    if (stored && stored.length > 0) {
      const storedMap = new Map(stored.map(p => [p.uid, p]));
      freshPatients.forEach(fp => {
        const oldP = storedMap.get(fp.uid);
        if (oldP) {
          if (oldP.data_prescrizione) fp.data_prescrizione = oldP.data_prescrizione;
          if (oldP.manual_edit && oldP.inv_date) {
            fp.inv_date = oldP.inv_date;
            fp.manual_edit = true;
          }
        }
      });
    }

    allPatients = freshPatients;
    await savePatientsToDB(db, allPatients);
    localStorage.setItem(SCHEMA_VERSION_KEY, CURRENT_SCHEMA_VERSION);
    localStorage.setItem(PIN_HASH_KEY, await computePinHash(candidatePin));

    populateDropdownFilters();
    applyGlobalFilters();
    updateStorageStats();
    unlockApp();
  } catch (err) {
    console.warn('Decifratura fallita:', err);
    errEl.className = 'text-xs text-rose-400 font-medium h-4';
    errEl.textContent = 'PIN non corretto. Accesso negato.';
    enteredPin = '';
    updatePinDots();
  }
}

function unlockApp() {
  document.getElementById('lockScreen').classList.add('hidden');
  enteredPin = '';
  updatePinDots();
  document.getElementById('pinError').textContent = '';
}

function lockApp() {
  enteredPin = '';
  updatePinDots();
  document.getElementById('pinError').textContent = '';
  document.getElementById('lockScreen').classList.remove('hidden');
}

async function triggerBiometrics() {
  if (!window.PublicKeyCredential) {
    document.getElementById('pinError').textContent = 'Biometria non supportata sul browser attuale.';
    return;
  }
  try {
    if (localStorage.getItem(BIOMETRIC_KEY) === 'true' && allPatients.length > 0) {
      unlockApp();
    } else {
      registerBiometrics();
    }
  } catch (err) {
    console.log('Biometric error', err);
  }
}

function registerBiometrics() {
  localStorage.setItem(BIOMETRIC_KEY, 'true');
  alert('Face ID / Sblocco Biometrico attivato per questo dispositivo!');
}

async function changePinDialog() {
  const oldPin = prompt('Inserisci il PIN attuale:');
  if (!oldPin) return;
  const savedHash = localStorage.getItem(PIN_HASH_KEY);
  if (savedHash && (await computePinHash(oldPin)) !== savedHash) {
    alert('PIN attuale non valido.');
    return;
  }
  const newPin = prompt('Inserisci il nuovo PIN locale a 4 cifre:');
  if (newPin && newPin.length === 4 && /^\d+$/.test(newPin)) {
    localStorage.setItem(PIN_HASH_KEY, await computePinHash(newPin));
    alert('Nuovo PIN salvato con successo su questo dispositivo!');
  } else {
    alert('PIN non valido. Deve essere composto da 4 numeri.');
  }
}

// ==================== DATABASE (INDEXEDDB) ====================
function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'uid' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function initDatabaseAndLoadData() {
  try {
    const db = await openDB();
    const stored = await getAllPatientsFromDB(db);
    const savedSchema = localStorage.getItem(SCHEMA_VERSION_KEY);

    if (stored && stored.length > 0 && savedSchema === CURRENT_SCHEMA_VERSION) {
      allPatients = stored;
      console.log(`Caricati ${allPatients.length} pazienti da IndexedDB locale (${CURRENT_SCHEMA_VERSION})`);
      updateStorageStats();
    } else {
      console.log('In attesa del PIN per decifrare initial_data.enc (AES-256-GCM)...');
    }
  } catch (err) {
    console.error('Errore lettura IndexedDB:', err);
  }
}

function getAllPatientsFromDB(db) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const req = store.getAll();
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function savePatientsToDB(db, patients) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    patients.forEach(p => store.put(p));
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function updateStorageStats() {
  const elTotal = document.getElementById('statTotalPatients');
  const elDate = document.getElementById('statLastUpdate');
  if (elTotal) elTotal.textContent = allPatients.length;
  if (elDate) elDate.textContent = new Date().toLocaleDateString('it-IT') + ' ' + new Date().toLocaleTimeString('it-IT');
}

// ==================== NAVIGAZIONE TABS ====================
function switchTab(tabName, subfilter = null) {
  currentTab = tabName;
  
  const titleEl = document.getElementById('headerTitle');
  const subtitles = {
    dashboard: 'Dashboard',
    da_fatturare: 'Da Fatturare & Scadenze',
    prescrizioni: `Scadenze Prescrizioni (${MONTH_NAMES[selectedPrescriptionMonth]})`,
    micro: 'Anagrafica Pazienti',
    settings: 'Dati & PIN'
  };
  titleEl.textContent = subtitles[tabName] || 'Monitoraggio';

  ['dashboard', 'da_fatturare', 'prescrizioni', 'micro', 'settings'].forEach(t => {
    const sec = document.getElementById(`view-${t}`);
    if (sec) {
      if (t === tabName) sec.classList.remove('hidden');
      else sec.classList.add('hidden');
    }
    const btn = document.getElementById(`nav-btn-${t}`);
    if (btn) {
      if (t === tabName) {
        btn.classList.add('text-sky-400');
        btn.classList.remove('text-slate-400');
      } else {
        btn.classList.remove('text-sky-400');
        btn.classList.add('text-slate-400');
      }
    }
  });

  if (tabName === 'micro' && subfilter) {
    togglePatientType('micro');
    setMicroFilter(subfilter);
  } else if (tabName === 'da_fatturare') {
    if (subfilter === 'scadenza') {
      switchDaFatturareSubtab('scadenza');
    } else {
      switchDaFatturareSubtab('npnp');
      if (subfilter && ['all_unbilled', 'no_matrix', 'in_matrix', 'all_micro_unbilled'].includes(subfilter)) {
        setDaFatturareFilter(subfilter);
      }
    }
  }

  if (tabName === 'dashboard') renderDashboardKPI();
  else if (tabName === 'da_fatturare') renderDaFatturareList();
  else if (tabName === 'prescrizioni') renderPrescrizioniList();
  else if (tabName === 'micro') renderMicroList();

  lucide.createIcons();
}

function switchDaFatturareSubtab(subtab) {
  currentDaFatturareSubtab = subtab;
  const btnNpnp = document.getElementById('subtab-btn-npnp');
  const btnScad = document.getElementById('subtab-btn-scadenza');
  const descNpnp = document.getElementById('subtab-desc-npnp');
  const descScad = document.getElementById('subtab-desc-scadenza');
  const chipsContainer = document.getElementById('daFatturareFilterChips');

  if (subtab === 'npnp') {
    btnNpnp.className = 'flex-1 py-1.5 text-xs font-semibold rounded-lg bg-sky-600 text-white transition';
    btnScad.className = 'flex-1 py-1.5 text-xs font-semibold rounded-lg text-slate-400 hover:text-white transition';
    descNpnp.classList.remove('hidden');
    descScad.classList.add('hidden');
    if (chipsContainer) chipsContainer.classList.remove('hidden');
  } else {
    btnScad.className = 'flex-1 py-1.5 text-xs font-semibold rounded-lg bg-sky-600 text-white transition';
    btnNpnp.className = 'flex-1 py-1.5 text-xs font-semibold rounded-lg text-slate-400 hover:text-white transition';
    descScad.classList.remove('hidden');
    descNpnp.classList.add('hidden');
    if (chipsContainer) chipsContainer.classList.add('hidden');
  }
  renderDaFatturareList();
}

function setDaFatturareFilter(filter) {
  currentDaFatturareFilter = filter;
  const styles = {
    all_unbilled: {
      active: 'px-2.5 py-1.5 rounded-xl bg-sky-600 text-white font-bold shrink-0 shadow-md shadow-sky-600/20 transition',
      inactive: 'px-2.5 py-1.5 rounded-xl bg-slate-800 text-slate-300 font-medium shrink-0 transition'
    },
    no_matrix: {
      active: 'px-2.5 py-1.5 rounded-xl bg-rose-600 text-white font-bold shrink-0 shadow-md shadow-rose-600/30 transition',
      inactive: 'px-2.5 py-1.5 rounded-xl bg-slate-800 text-rose-300 border border-rose-800/40 font-semibold shrink-0 transition'
    },
    in_matrix: {
      active: 'px-2.5 py-1.5 rounded-xl bg-amber-600 text-white font-bold shrink-0 shadow-md shadow-amber-600/30 transition',
      inactive: 'px-2.5 py-1.5 rounded-xl bg-slate-800 text-amber-300 border border-amber-800/40 font-semibold shrink-0 transition'
    },
    all_micro_unbilled: {
      active: 'px-2.5 py-1.5 rounded-xl bg-indigo-600 text-white font-bold shrink-0 shadow-md shadow-indigo-600/30 transition',
      inactive: 'px-2.5 py-1.5 rounded-xl bg-slate-800 text-slate-300 font-medium shrink-0 transition'
    }
  };

  Object.keys(styles).forEach(k => {
    const el = document.getElementById(`chip-df-${k}`);
    if (el) {
      el.className = (k === filter) ? styles[k].active : styles[k].inactive;
    }
  });

  renderDaFatturareList();
}

function togglePatientType(type) {
  currentPatientType = type;
  const btnMicro = document.getElementById('toggle-sub-micro');
  const btnGc = document.getElementById('toggle-sub-gc');
  const chips = document.getElementById('microFilterChips');

  if (type === 'micro') {
    btnMicro.className = 'flex-1 py-1.5 text-xs font-semibold rounded-lg bg-sky-600 text-white transition';
    btnGc.className = 'flex-1 py-1.5 text-xs font-semibold rounded-lg text-slate-400 hover:text-white transition';
    chips.classList.remove('hidden');
  } else {
    btnGc.className = 'flex-1 py-1.5 text-xs font-semibold rounded-lg bg-indigo-600 text-white transition';
    btnMicro.className = 'flex-1 py-1.5 text-xs font-semibold rounded-lg text-slate-400 hover:text-white transition';
    chips.classList.add('hidden');
  }
  renderMicroList();
}

// ==================== FILTRI GLOBALI ====================
function populateDropdownFilters() {
  const salesSet = new Set();
  const aslSet = new Set();

  allPatients.forEach(p => {
    if (p.sales_rep) salesSet.add(p.sales_rep.trim());
    if (p.asl) aslSet.add(p.asl.trim());
  });

  const selSales = document.getElementById('filterSales');
  const selAsl = document.getElementById('filterAsl');

  Array.from(salesSet).sort().forEach(s => {
    const opt = document.createElement('option');
    opt.value = s;
    opt.textContent = s;
    selSales.appendChild(opt);
  });

  Array.from(aslSet).sort().forEach(a => {
    const opt = document.createElement('option');
    opt.value = a;
    opt.textContent = a;
    selAsl.appendChild(opt);
  });
}

function applyGlobalFilters() {
  const salesVal = document.getElementById('filterSales').value;
  const aslVal = document.getElementById('filterAsl').value;

  filteredPatients = allPatients.filter(p => {
    if (salesVal && (!p.sales_rep || !p.sales_rep.includes(salesVal))) return false;
    if (aslVal && (!p.asl || !p.asl.includes(aslVal))) return false;
    return true;
  });

  renderDashboardKPI();
  if (currentTab === 'da_fatturare') renderDaFatturareList();
  else if (currentTab === 'prescrizioni') renderPrescrizioniList();
  else if (currentTab === 'micro') renderMicroList();
}

function resetFilters() {
  document.getElementById('filterSales').value = '';
  document.getElementById('filterAsl').value = '';
  applyGlobalFilters();
}

// ==================== RENDERING DASHBOARD KPI ====================
function renderDashboardKPI() {
  const microPatients = filteredPatients.filter(p => ['NPNP', 'EPNP'].includes(p.classificazione));
  const gcPatients = filteredPatients.filter(p => ['NPGC', 'EPGC'].includes(p.classificazione));

  const invoicedMicro = microPatients.filter(p => !!p.inv_date);
  const openOrderMicro = microPatients.filter(p => !p.inv_date && !!p.in_matrix);

  const today = new Date();
  const cutoff18m = new Date(today.getTime() - (18 * 30.5 * 24 * 60 * 60 * 1000));

  // Tutti gli NPNP degli ultimi 18 mesi NON ancora fatturati (esclusi DROPOUT)
  const unbilledNPNP18m = microPatients.filter(p => {
    if (p.classificazione !== 'NPNP') return false;
    if (p.inv_date) return false;
    if (p.seriale === 'DROPOUT') return false;
    if (!p.data_consenso) return false;
    const dtCons = new Date(p.data_consenso);
    return dtCons >= cutoff18m;
  });

  const criticalNPNP = unbilledNPNP18m.filter(p => !p.in_matrix);
  const inMatrixNPNP = unbilledNPNP18m.filter(p => !!p.in_matrix);

  document.getElementById('kpiTotalMicro').textContent = microPatients.length;
  document.getElementById('kpiTotalGC').textContent = gcPatients.length;
  document.getElementById('kpiFatturati').textContent = invoicedMicro.length;

  const pct = microPatients.length > 0 ? Math.round((invoicedMicro.length / microPatients.length) * 100) : 0;
  document.getElementById('kpiFatturatiPct').textContent = `${pct}% del totale micro`;

  document.getElementById('kpiDaFatturare').textContent = unbilledNPNP18m.length;
  const subEl = document.getElementById('kpiDaFatturareSub');
  if (subEl) {
    subEl.textContent = `${inMatrixNPNP.length} in Matrix · ${criticalNPNP.length} senza bolla`;
  }
  document.getElementById('kpiOpenOrderCount').textContent = openOrderMicro.length;

  const banner = document.getElementById('alertBannerMMX');
  const navBadge = document.getElementById('navBadgeAlert');
  if (criticalNPNP.length > 0) {
    banner.classList.remove('hidden');
    navBadge.classList.remove('hidden');
    document.getElementById('badgeCountMMX').textContent = criticalNPNP.length;
  } else {
    banner.classList.add('hidden');
    navBadge.classList.add('hidden');
  }
}

// ==================== RENDERING: DA FATTURARE & SCADENZE ====================
function renderDaFatturareList() {
  const container = document.getElementById('listDaFatturare');
  container.innerHTML = '';
  const search = (document.getElementById('searchDaFatturare').value || '').toLowerCase().trim();

  const microPatients = filteredPatients.filter(p => ['NPNP', 'EPNP'].includes(p.classificazione));
  const today = new Date();

  if (currentDaFatturareSubtab === 'npnp') {
    const cutoff18m = new Date(today.getTime() - (18 * 30.5 * 24 * 60 * 60 * 1000));

    // Solo pazienti NON fatturati e NON DROPOUT
    const allUnbilledMicro = microPatients.filter(p => !p.inv_date && p.seriale !== 'DROPOUT');
    const npnp18Unbilled = allUnbilledMicro.filter(p => {
      if (p.classificazione !== 'NPNP') return false;
      if (!p.data_consenso) return false;
      return new Date(p.data_consenso) >= cutoff18m;
    });
    const noMatList = npnp18Unbilled.filter(p => !p.in_matrix);
    const inMatList = npnp18Unbilled.filter(p => !!p.in_matrix);

    // Aggiorna contatori nei chip
    const elAll = document.getElementById('cnt-df-all');
    const elNoMat = document.getElementById('cnt-df-nomat');
    const elInMat = document.getElementById('cnt-df-inmat');
    const elAllMicro = document.getElementById('cnt-df-allmicro');
    if (elAll) elAll.textContent = npnp18Unbilled.length;
    if (elNoMat) elNoMat.textContent = noMatList.length;
    if (elInMat) elInMat.textContent = inMatList.length;
    if (elAllMicro) elAllMicro.textContent = allUnbilledMicro.length;

    let baseList = npnp18Unbilled;
    if (currentDaFatturareFilter === 'no_matrix') baseList = noMatList;
    else if (currentDaFatturareFilter === 'in_matrix') baseList = inMatList;
    else if (currentDaFatturareFilter === 'all_micro_unbilled') baseList = allUnbilledMicro;

    const npnpList = baseList.filter(p => {
      if (search) {
        const matBlock = (p.matrix_info && p.matrix_info.block) ? p.matrix_info.block : '';
        const fullStr = `${p.cognome} ${p.nome} ${p.uid} ${p.seriale} ${p.asl} ${p.medico} ${matBlock}`.toLowerCase();
        if (!fullStr.includes(search)) return false;
      }
      return true;
    });

    if (npnpList.length === 0) {
      container.innerHTML = `<div class="p-8 text-center text-slate-500 text-xs">Nessun paziente da fatturare corrispondente al filtro selezionato.</div>`;
      return;
    }

    // Ordina: prima i critici senza bolla in Matrix, poi per Ageing Matrix decrescente
    npnpList.sort((a, b) => {
      const aCrit = !a.in_matrix ? 1 : 0;
      const bCrit = !b.in_matrix ? 1 : 0;
      if (bCrit !== aCrit) return bCrit - aCrit;
      const aAge = (a.matrix_info && a.matrix_info.ageing) || 0;
      const bAge = (b.matrix_info && b.matrix_info.ageing) || 0;
      return bAge - aAge;
    });

    npnpList.forEach(p => {
      const isMissingMatrix = !p.in_matrix;
      const isCriticalAlert = isMissingMatrix;

      const card = document.createElement('div');
      card.onclick = () => openPatientModal(p);
      card.className = `p-3.5 rounded-2xl border transition active:scale-[0.99] cursor-pointer ${
        isCriticalAlert 
          ? 'bg-rose-950/40 border-rose-500/50 shadow-md shadow-rose-950/20' 
          : 'bg-amber-950/20 border-amber-500/30'
      }`;

      let statusHtml = '';
      if (isCriticalAlert) {
        statusHtml = `
          <div class="mt-2.5 pt-2.5 border-t border-rose-500/30 text-[11px] text-rose-300 space-y-1">
            <div class="flex items-center gap-1.5"><i data-lucide="x-circle" class="w-3.5 h-3.5 text-rose-400 shrink-0"></i> Manca data di fatturazione</div>
            <div class="flex items-center gap-1.5"><i data-lucide="x-circle" class="w-3.5 h-3.5 text-rose-400 shrink-0"></i> Non presente in open order</div>
            <div class="flex items-center gap-1.5 font-bold text-rose-200 bg-rose-500/20 px-2 py-1 rounded-lg mt-1">
              <i data-lucide="alert-triangle" class="w-3.5 h-3.5 text-amber-300 shrink-0"></i> Sicuro di aver fatto la bolla?
            </div>
          </div>
        `;
      } else {
        const mat = p.matrix_info || {};
        statusHtml = `
          <div class="mt-2.5 pt-2.5 border-t border-slate-800 text-[11px] text-amber-300">
            <div class="flex items-center justify-between font-semibold">
              <span class="flex items-center gap-1.5"><i data-lucide="check-circle-2" class="w-3.5 h-3.5 text-amber-400"></i> Bolla Presente in Matrix (Doc: ${mat.sales_doc || '--'})</span>
              <span class="text-[10px] text-amber-200 font-bold bg-amber-500/20 px-1.5 py-0.5 rounded">Ageing: ${mat.ageing || 0} gg</span>
            </div>
            <div class="text-[10px] text-slate-300 mt-1 truncate">Blocco: <strong>${mat.block || 'Nessun blocco'}</strong></div>
          </div>
        `;
      }

      card.innerHTML = `
        <div class="flex items-start justify-between">
          <div>
            <div class="flex items-center gap-1.5 flex-wrap">
              <h4 class="text-sm font-bold text-white capitalize">${p.cognome} ${p.nome}</h4>
              <span class="text-[9px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">UID: ${p.uid}</span>
              <span class="text-[9px] px-1.5 py-0.5 rounded bg-slate-800 text-sky-300 font-bold">${p.classificazione}</span>
            </div>
            <p class="text-[11px] text-slate-400 mt-0.5">${p.asl || 'ASL non specificata'}</p>
          </div>
          <span class="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold ${isCriticalAlert ? 'bg-rose-500/30 text-rose-300' : 'bg-amber-500/20 text-amber-300'}">
            ${p.seriale}
          </span>
        </div>
        <div class="flex items-center gap-3 mt-2 text-[10px] text-slate-400">
          <span>Consenso: <strong class="text-slate-200">${p.data_consenso || '--'}</strong></span>
          <span>Sales: <strong class="text-slate-200">${p.sales_rep || '--'}</strong></span>
          <span>Centro: <strong class="text-slate-300 truncate max-w-[110px] inline-block align-bottom">${p.centro || '--'}</strong></span>
        </div>
        ${statusHtml}
      `;
      container.appendChild(card);
    });

  } else {
    // Sottotab: SCADENZA 4 ANNI
    const scadenzaList = microPatients.filter(p => {
      if (!p.inv_date) return false;
      const invDate = new Date(p.inv_date);
      const diffYears = (today - invDate) / (365.25 * 24 * 60 * 60 * 1000);
      if (diffYears < 3.5) return false;

      if (search) {
        const fullStr = `${p.cognome} ${p.nome} ${p.uid} ${p.seriale} ${p.asl} ${p.medico}`.toLowerCase();
        if (!fullStr.includes(search)) return false;
      }
      return true;
    });

    scadenzaList.sort((a, b) => new Date(a.inv_date) - new Date(b.inv_date));

    if (scadenzaList.length === 0) {
      container.innerHTML = `<div class="p-8 text-center text-slate-500 text-xs">Nessun paziente in scadenza 4 anni corrispondente ai filtri.</div>`;
      return;
    }

    scadenzaList.forEach(p => {
      const invDate = new Date(p.inv_date);
      const diffYears = ((today - invDate) / (365.25 * 24 * 60 * 60 * 1000)).toFixed(1);
      const expiryDate = new Date(invDate.getTime() + (4 * 365.25 * 24 * 60 * 60 * 1000));
      const diffDays = Math.round((expiryDate - today) / (24 * 60 * 60 * 1000));
      const isExpired = diffDays <= 0;

      const card = document.createElement('div');
      card.onclick = () => openPatientModal(p);
      card.className = `p-3.5 rounded-2xl border transition active:scale-[0.99] cursor-pointer ${
        isExpired 
          ? 'bg-rose-950/30 border-rose-800/40' 
          : 'bg-amber-950/20 border-amber-800/40'
      }`;

      card.innerHTML = `
        <div class="flex items-start justify-between">
          <div>
            <div class="flex items-center gap-1.5">
              <h4 class="text-sm font-bold text-white capitalize">${p.cognome} ${p.nome}</h4>
              <span class="text-[9px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">UID: ${p.uid}</span>
            </div>
            <p class="text-[11px] text-slate-400 mt-0.5">${p.asl || 'ASL non specificata'}</p>
          </div>
          <span class="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-slate-800 text-slate-300">
            ${p.seriale}
          </span>
        </div>
        <div class="mt-2.5 pt-2 border-t border-slate-800 flex items-center justify-between text-xs">
          <div>
            <span class="text-[10px] text-slate-500 block">Fatturato il:</span>
            <span class="font-bold text-white">${p.inv_date} (${diffYears} anni fa)</span>
          </div>
          <div class="text-right">
            <span class="text-[10px] text-slate-500 block">Stato 4 Anni:</span>
            <span class="font-bold ${isExpired ? 'text-rose-400' : 'text-amber-400'}">
              ${isExpired ? `Scaduto da ${Math.abs(diffDays)} gg` : `Scade tra ${diffDays} gg`}
            </span>
          </div>
        </div>
      `;
      container.appendChild(card);
    });
  }
  lucide.createIcons();
}

// ==================== RENDERING: SCADENZE PRESCRIZIONI ANNUALI (PER MESE) ====================
function selectPrescriptionMonth(month) {
  selectedPrescriptionMonth = month;
  highlightActiveMonthButton();
  document.getElementById('headerTitle').textContent = `Scadenze Prescrizioni (${MONTH_NAMES[month]})`;
  renderPrescrizioniList();
}

function highlightActiveMonthButton() {
  for (let m = 1; m <= 12; m++) {
    const btn = document.getElementById(`btn-month-${m}`);
    if (btn) {
      if (m === selectedPrescriptionMonth) {
        btn.className = 'py-1.5 rounded-xl border border-sky-400 bg-sky-600 text-white font-bold shadow-md shadow-sky-600/30 scale-105 transition';
      } else {
        btn.className = 'py-1.5 rounded-xl border border-slate-800 bg-slate-950 text-slate-400 hover:text-white font-semibold active:scale-95 transition';
      }
    }
  }
}

function openPatientModalByUid(uid) {
  const p = allPatients.find(x => String(x.uid) === String(uid));
  if (p) openPatientModal(p);
}

function openEditPrescriptionModalByUid(uid) {
  const p = allPatients.find(x => String(x.uid) === String(uid));
  if (p) openEditPrescriptionModal(p);
}

function renderPrescrizioniList() {
  const container = document.getElementById('listPrescrizioni');
  container.innerHTML = '';
  const search = (document.getElementById('searchPrescrizioni').value || '').toLowerCase().trim();

  // Filtra i pazienti Micro in base alla regola:
  // 1) data_prescrizione manuale (se inserita)
  // 2) presc_base_date = Data Ordine Consumabile Annuale (12m) se presente, altrimenti Fatturazione Micro (per ordini 3-6m o altro)
  const microPatients = filteredPatients.filter(p => ['NPNP', 'EPNP'].includes(p.classificazione));

  const monthPatients = microPatients.filter(p => {
    const dateStr = p.data_prescrizione || p.presc_base_date || p.inv_date || p.data_consenso;
    if (!dateStr) return false;
    const d = new Date(dateStr);
    if (d.getMonth() + 1 !== selectedPrescriptionMonth) return false;

    if (search) {
      const fullStr = `${p.cognome} ${p.nome} ${p.uid} ${p.seriale} ${p.asl} ${p.medico} ${p.centro}`.toLowerCase();
      if (!fullStr.includes(search)) return false;
    }
    return true;
  });

  document.getElementById('prescMonthCountBadge').textContent = `${monthPatients.length} pazienti`;

  if (monthPatients.length === 0) {
    container.innerHTML = `<div class="p-8 text-center text-slate-500 text-xs">Nessun paziente con scadenza prescrizione a ${MONTH_NAMES[selectedPrescriptionMonth]} per i filtri attivi.</div>`;
    return;
  }

  // Ordina: prima chi NON ha ancora la data prescrizione aggiornata manualmente
  monthPatients.sort((a, b) => {
    const aHas = a.data_prescrizione ? 1 : 0;
    const bHas = b.data_prescrizione ? 1 : 0;
    return aHas - bHas;
  });

  monthPatients.forEach(p => {
    const hasRenewed = !!p.data_prescrizione;
    const isFromAnnualOrder = p.presc_base_source === 'Ordine Annuale (12m)';
    const domBadge = p.domiciliare
      ? `<span class="text-[9px] px-1.5 py-0.2 rounded bg-indigo-950 text-indigo-300 border border-indigo-700/50 font-semibold">🏠 Dom.</span>`
      : '';
    const sourceBadge = isFromAnnualOrder
      ? `<span class="text-[9px] px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-300 border border-emerald-700/50 font-semibold">📦 Ord. Annuale 12m</span>`
      : `<span class="text-[9px] px-1.5 py-0.2 rounded bg-sky-950 text-sky-300 border border-sky-800/50 font-semibold">📟 Fatt. Micro</span>`;

    const card = document.createElement('div');
    card.className = `p-3.5 bg-slate-900 rounded-2xl border transition ${
      hasRenewed ? 'border-emerald-800/40 bg-emerald-950/10' : 'border-slate-800 hover:border-slate-700'
    }`;

    card.innerHTML = `
      <div class="flex items-start justify-between">
        <div>
          <div class="flex items-center gap-1.5 flex-wrap">
            <h4 class="text-xs font-bold text-white capitalize cursor-pointer hover:underline" onclick="openPatientModalByUid('${p.uid}')">${p.cognome} ${p.nome}</h4>
            <span class="text-[9px] px-1 py-0.2 rounded bg-slate-800 text-slate-400 font-mono">${p.uid}</span>
            ${domBadge}
            ${sourceBadge}
          </div>
          <p class="text-[10px] text-slate-400 mt-0.5 truncate max-w-[230px]">${p.asl || 'ASL non indicata'}</p>
        </div>
        <span class="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 shrink-0">
          ${p.seriale}
        </span>
      </div>

      <!-- Dati Clinici, Centri di Riferimento & Base Calcolo Scadenza -->
      <div class="mt-2.5 pt-2 border-t border-slate-800/80 grid grid-cols-2 gap-2 text-[10px]">
        <div>
          <span class="text-slate-500 block">Medico Prescrittore:</span>
          <span class="font-medium text-slate-200 truncate block">${p.medico || 'Non indicato'}</span>
        </div>
        <div>
          <span class="text-slate-500 block">Centro Diabetologico:</span>
          <span class="font-medium text-slate-200 truncate block">${p.centro || 'Non indicato'}</span>
        </div>
        <div>
          <span class="text-slate-500 block">Rif. Scadenza (${isFromAnnualOrder ? 'Ord. 12m' : 'Micro'}):</span>
          <span class="${isFromAnnualOrder ? 'text-emerald-300' : 'text-sky-300'} font-bold truncate block">
            ${p.presc_base_date || p.inv_date || '--'}
          </span>
        </div>
        <div>
          <span class="text-slate-500 block">Ultimo Ord. Consumabile:</span>
          <span class="${p.last_cons_date ? 'text-indigo-300 font-medium' : 'text-slate-500'} truncate block">
            ${p.last_cons_date ? `${p.last_cons_date} (${p.last_cons_cadence || 'Forn.'})` : 'Nessuno in Rpt'}
          </span>
        </div>
      </div>

      <!-- Stato Prescrizione & Azione Rapida -->
      <div class="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between">
        <div>
          ${hasRenewed 
            ? `<span class="text-[10px] font-semibold text-emerald-400 flex items-center gap-1"><i data-lucide="check" class="w-3.5 h-3.5"></i> Rinnovata il ${p.data_prescrizione}</span>`
            : `<span class="text-[10px] font-semibold text-amber-400 flex items-center gap-1"><i data-lucide="clock" class="w-3.5 h-3.5"></i> Scadenza: ${MONTH_NAMES[selectedPrescriptionMonth]} (${isFromAnnualOrder ? 'da Ordine Annuale' : 'da Fatt. Micro'})</span>`
          }
        </div>
        <button onclick="openEditPrescriptionModalByUid('${p.uid}')" class="px-2.5 py-1 rounded-xl bg-slate-800 hover:bg-sky-600 text-sky-300 hover:text-white border border-slate-700 text-[10px] font-medium transition active:scale-95">
          ${hasRenewed ? 'Modifica Data' : 'Aggiorna Data'}
        </button>
      </div>
    `;
    container.appendChild(card);
  });
  lucide.createIcons();
}

// ==================== GESTIONE DATA PRESCRIZIONE ====================
function openEditPrescriptionModal(patient) {
  patientForPrescription = patient;
  document.getElementById('labelPrescriptionPatient').textContent = `Paziente: ${patient.cognome} ${patient.nome} (UID ${patient.uid})`;
  document.getElementById('inputPrescriptionDate').value = patient.data_prescrizione || new Date().toISOString().slice(0, 10);
  document.getElementById('editPrescriptionModal').classList.remove('hidden');
}

function closeEditPrescriptionModal() {
  document.getElementById('editPrescriptionModal').classList.add('hidden');
  patientForPrescription = null;
}

async function savePrescriptionDate() {
  if (!patientForPrescription) return;
  const newDate = document.getElementById('inputPrescriptionDate').value;

  patientForPrescription.data_prescrizione = newDate || null;

  try {
    const db = await openDB();
    await savePatientsToDB(db, [patientForPrescription]);
  } catch (err) {
    console.error('Errore salvataggio prescrizione:', err);
  }

  closeEditPrescriptionModal();
  renderPrescrizioniList();
  alert('Data rinnovo prescrizione salvata con successo!');
}

// ==================== RENDERING: PAZIENTI (MICRO & GC) ====================
function setMicroFilter(filter) {
  currentMicroFilter = filter;
  ['all', 'invoiced', 'matrix', 'missing'].forEach(f => {
    const chip = document.getElementById(`chip-micro-${f}`);
    if (chip) {
      if (f === filter) {
        chip.className = 'px-2.5 py-1 rounded-full bg-sky-600 text-white font-medium shrink-0';
      } else {
        chip.className = 'px-2.5 py-1 rounded-full bg-slate-800 text-slate-300 font-medium shrink-0';
      }
    }
  });
  renderMicroList();
}

// Helper per calcolo e stato Scadenza 4 Anni (48 mesi)
function getExpiry4YearsInfo(invDateStr) {
  if (!invDateStr) return { dateStr: '--', text: 'Non fatturato', color: 'text-slate-500', isExpired: false, isNear: false };
  const d = new Date(invDateStr);
  if (isNaN(d.getTime())) return { dateStr: '--', text: 'Data non valida', color: 'text-slate-500', isExpired: false, isNear: false };
  const exp = new Date(d);
  exp.setFullYear(d.getFullYear() + 4);
  const expStr = exp.toISOString().slice(0, 10);
  const today = new Date();
  const diffDays = Math.round((exp - today) / (1000 * 60 * 60 * 24));

  if (diffDays <= 0) {
    return {
      dateStr: expStr,
      diffDays,
      text: `Scaduto (${Math.abs(diffDays)} gg fa)`,
      color: 'text-rose-400 font-bold',
      isExpired: true,
      isNear: false
    };
  } else if (diffDays <= 180) { // entro 6 mesi
    return {
      dateStr: expStr,
      diffDays,
      text: `Scade tra ${diffDays} gg`,
      color: 'text-amber-400 font-bold',
      isExpired: false,
      isNear: true
    };
  } else {
    return {
      dateStr: expStr,
      diffDays,
      text: `In corso (${Math.round(diffDays / 30)} mesi)`,
      color: 'text-sky-400',
      isExpired: false,
      isNear: false
    };
  }
}

function renderMicroList() {
  const container = document.getElementById('listMicro');
  container.innerHTML = '';
  const search = (document.getElementById('searchMicro').value || '').toLowerCase().trim();

  const isMicroMode = currentPatientType === 'micro';
  const targetClasses = isMicroMode ? ['NPNP', 'EPNP'] : ['NPGC', 'EPGC'];
  const pList = filteredPatients.filter(p => targetClasses.includes(p.classificazione));

  if (isMicroMode) {
    const cntAll = pList.length;
    const cntInv = pList.filter(p => !!p.inv_date).length;
    const cntMat = pList.filter(p => !!p.in_matrix).length;
    const cntMis = pList.filter(p => !p.inv_date).length;

    document.getElementById('cnt-m-all').textContent = cntAll;
    document.getElementById('cnt-m-inv').textContent = cntInv;
    document.getElementById('cnt-m-mat').textContent = cntMat;
    document.getElementById('cnt-m-mis').textContent = cntMis;
  }

  const displayList = pList.filter(p => {
    if (isMicroMode) {
      if (currentMicroFilter === 'invoiced' && !p.inv_date) return false;
      if (currentMicroFilter === 'matrix' && !p.in_matrix) return false;
      if (currentMicroFilter === 'missing' && p.inv_date) return false;
    }

    if (search) {
      const fullStr = `${p.cognome} ${p.nome} ${p.uid} ${p.seriale} ${p.asl} ${p.medico} ${p.centro}`.toLowerCase();
      if (!fullStr.includes(search)) return false;
    }
    return true;
  });

  if (displayList.length === 0) {
    container.innerHTML = `<div class="p-8 text-center text-slate-500 text-xs">Nessun paziente trovato per i criteri selezionati.</div>`;
    return;
  }

  displayList.slice(0, 150).forEach(p => {
    const card = document.createElement('div');
    card.onclick = () => openPatientModal(p);
    card.className = 'p-3 bg-slate-900 rounded-2xl border border-slate-800 hover:border-slate-700 transition active:scale-[0.99] cursor-pointer';

    const hasInvoice = !!p.inv_date;
    const inMatrix = !!p.in_matrix;
    const expInfo = getExpiry4YearsInfo(p.inv_date);
    const isRecoveredViaUid = p.inv_source && p.inv_source.startsWith('UID');

    card.innerHTML = `
      <div class="flex items-start justify-between">
        <div>
          <div class="flex items-center gap-1.5 flex-wrap">
            <h4 class="text-xs font-bold text-white capitalize">${p.cognome} ${p.nome}</h4>
            <span class="text-[9px] px-1 py-0.2 rounded bg-slate-800 text-slate-400 font-mono">${p.uid}</span>
            ${p.domiciliare ? '<span class="text-[9px] px-1 py-0.2 rounded bg-indigo-950 text-indigo-300 border border-indigo-800/50">🏠 Dom.</span>' : ''}
            ${isRecoveredViaUid ? '<span class="text-[9px] px-1 py-0.2 rounded bg-sky-950 text-sky-300 border border-sky-800/50" title="Data recuperata da storico ordini UID">🔄 da UID</span>' : ''}
          </div>
          <p class="text-[10px] text-slate-400 mt-0.5 truncate max-w-[200px]">${p.asl || 'ASL non indicata'}</p>
        </div>
        <span class="text-[10px] font-mono px-2 py-0.5 rounded-full shrink-0 ${
          isMicroMode 
            ? (hasInvoice ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/40' : 'bg-slate-800 text-slate-400')
            : 'bg-indigo-950 text-indigo-300 border border-indigo-800/40'
        }">
          ${p.seriale || p.tipo_sensore || p.classificazione}
        </span>
      </div>

      <!-- Dati Chiave & Scadenza 4 Anni in Evidenza -->
      <div class="mt-2 pt-2 border-t border-slate-800/80 grid grid-cols-3 gap-1.5 text-[10px]">
        <div>
          <span class="text-slate-500 block truncate">Consenso:</span>
          <span class="font-medium text-slate-200 truncate block">${p.data_consenso || '--'}</span>
        </div>
        <div>
          <span class="text-slate-500 block truncate">Fatturato:</span>
          <span class="font-bold ${hasInvoice ? 'text-emerald-400' : 'text-rose-400'} truncate block">
            ${hasInvoice ? p.inv_date : (inMatrix ? 'In Matrix' : 'Non Fatt.')}
          </span>
        </div>
        <div class="text-right">
          <span class="text-slate-500 block truncate">${isMicroMode ? 'Scadenza 4A:' : 'Ult. Sensore:'}</span>
          <span class="truncate block ${isMicroMode ? expInfo.color : 'text-indigo-300 font-semibold'}">
            ${isMicroMode ? expInfo.dateStr : (p.last_sens_date || expInfo.dateStr)}
          </span>
        </div>
      </div>
    `;
    container.appendChild(card);
  });
}

// ==================== SCHEDA DETTAGLIO PAZIENTE (MODAL) ====================
function openPatientModal(patient) {
  selectedPatient = patient;

  document.getElementById('modalPatientName').textContent = `${patient.cognome} ${patient.nome}`;
  document.getElementById('modalPatientUid').textContent = `UID: ${patient.uid}`;
  document.getElementById('modalPatientAsl').textContent = patient.asl || 'ASL non indicata';

  const domBadge = document.getElementById('modalDomiciliareBadge');
  if (domBadge) {
    if (patient.domiciliare) domBadge.classList.remove('hidden');
    else domBadge.classList.add('hidden');
  }

  document.getElementById('modalDataConsenso').textContent = patient.data_consenso || 'Non specificata';
  document.getElementById('modalDataFattura').textContent = patient.inv_date || 'Non Fatturato';

  const invSrcEl = document.getElementById('modalInvSource');
  if (invSrcEl) {
    invSrcEl.textContent = patient.manual_edit
      ? 'Inserita Manualmente'
      : (patient.inv_source || (patient.inv_date ? 'Seriale Diretto' : 'Nessuna fattura'));
  }

  // Scadenza 4 Anni nella modale
  const expInfo = getExpiry4YearsInfo(patient.inv_date);
  document.getElementById('modalDataScadenza4Anni').textContent = expInfo.dateStr;
  document.getElementById('modalExpiryStatusText').textContent = expInfo.text;
  document.getElementById('modalExpiryStatusText').className = `font-bold ${expInfo.color}`;

  const badge = document.getElementById('modalStatusBadge');
  if (patient.inv_date) {
    badge.className = 'px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800/40';
    badge.textContent = `🟢 Fatturato (${patient.inv_qtr || 'OK'})`;
  } else if (patient.in_matrix) {
    badge.className = 'px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-amber-950 text-amber-400 border border-amber-800/40';
    badge.textContent = '🟡 In Matrix (Bolla MMX)';
  } else {
    badge.className = 'px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-rose-950 text-rose-400 border border-rose-800/40';
    badge.textContent = '🔴 Da Fatturare';
  }

  const matBox = document.getElementById('modalMatrixBox');
  if (patient.in_matrix && patient.matrix_info) {
    const m = patient.matrix_info;
    matBox.className = 'bg-slate-950 rounded-2xl p-4 border border-amber-800/50 space-y-2';
    matBox.innerHTML = `
      <div class="flex items-center justify-between text-amber-300 font-bold text-xs">
        <span class="flex items-center gap-1.5"><i data-lucide="layers" class="w-4 h-4"></i> Ordine Aperto Matrix</span>
        <span class="text-[10px] px-2 py-0.5 rounded bg-amber-500/20">Doc: ${m.sales_doc || '--'}</span>
      </div>
      <div class="grid grid-cols-2 gap-2 text-[10px] pt-1">
        <div><span class="text-slate-500">Motivo Blocco:</span><p class="font-medium text-slate-200 mt-0.5">${m.block || 'Nessuno'}</p></div>
        <div><span class="text-slate-500">Invecchiamento:</span><p class="font-bold text-amber-400 mt-0.5">${m.ageing || 0} giorni</p></div>
        <div class="col-span-2"><span class="text-slate-500">Riferimento PO / Cliente:</span><p class="font-mono text-slate-300 mt-0.5">${m.po || '--'}</p></div>
      </div>
    `;
  } else {
    matBox.className = 'bg-slate-950 rounded-2xl p-4 border border-slate-800 space-y-1';
    matBox.innerHTML = `
      <div class="flex items-center gap-2 text-slate-400 text-xs">
        <i data-lucide="info" class="w-4 h-4"></i>
        <span>Nessun ordine aperto presente attualmente in NEWMATRIX.</span>
      </div>
    `;
  }

  // BOX 2B: STORICO ORDINI PER UID (DA RPT_20261010)
  const uidOrders = patient.uid_orders || [];
  const uidCountEl = document.getElementById('modalUidOrdersCount');
  const lastConsDateEl = document.getElementById('modalLastConsDate');
  const lastConsPoEl = document.getElementById('modalLastConsPo');
  const lastSensDateEl = document.getElementById('modalLastSensDate');
  const domStatusEl = document.getElementById('modalDomStatusText');
  const uidListEl = document.getElementById('modalUidOrdersList');

  if (uidCountEl) uidCountEl.textContent = `${uidOrders.length} ordini recenti`;
  if (lastConsDateEl) {
    lastConsDateEl.textContent = patient.last_cons_date
      ? `${patient.last_cons_date} (${patient.last_cons_cadence || 'Forn.'})`
      : 'Nessuno';
  }
  if (lastConsPoEl) {
    const baseSrc = patient.presc_base_source === 'Ordine Annuale (12m)'
      ? `✓ Scadenza da Ord. 12m (${patient.presc_base_date})`
      : `Scadenza da Fatt. Micro (${patient.inv_date || '--'})`;
    lastConsPoEl.textContent = baseSrc;
  }
  if (lastSensDateEl) lastSensDateEl.textContent = patient.last_sens_date || 'Nessuno';
  if (domStatusEl) domStatusEl.textContent = patient.domiciliare ? '🏠 Consegna Domiciliare' : '🏥 Consegna ASL / Centro';

  if (uidListEl) {
    uidListEl.innerHTML = '';
    if (uidOrders.length > 0) {
      const typeLabels = {
        ZOR: { text: 'ZOR Vendita', cls: 'bg-emerald-950 text-emerald-300 border-emerald-800/50' },
        ZWR: { text: 'ZWR Sost. Garanzia', cls: 'bg-amber-950 text-amber-300 border-amber-800/50' },
        ZCC1: { text: 'ZCC1 Omaggio', cls: 'bg-sky-950 text-sky-300 border-sky-800/50' },
        KE: { text: 'KE Conto Dep.', cls: 'bg-purple-950 text-purple-300 border-purple-800/50' }
      };

      uidOrders.forEach(o => {
        const tInfo = typeLabels[o.type] || { text: o.type || 'Ordine', cls: 'bg-slate-800 text-slate-300 border-slate-700' };
        const tagsHtml = (o.tags || []).map(tag => {
          let colorCls = 'bg-slate-800 text-slate-300';
          if (tag === 'Micro') colorCls = 'bg-sky-500/20 text-sky-300';
          else if (tag.includes('Annuale')) colorCls = 'bg-emerald-500/20 text-emerald-300 border border-emerald-600/40';
          else if (tag.startsWith('Consumabile')) colorCls = 'bg-indigo-500/20 text-indigo-300';
          else if (tag === 'Sensore') colorCls = 'bg-teal-500/20 text-teal-300';
          else if (tag === 'CGM') colorCls = 'bg-violet-500/20 text-violet-300';
          else if (tag === 'Accessori') colorCls = 'bg-slate-700 text-slate-300';
          return `<span class="text-[9px] px-1.5 py-0.2 rounded font-semibold ${colorCls}">${tag}</span>`;
        }).join('');

        const row = document.createElement('div');
        row.className = 'p-2.5 rounded-xl bg-slate-900 border border-slate-800/90 space-y-1';
        row.innerHTML = `
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-1.5">
              <span class="font-mono font-bold text-white text-[11px]">SO: ${o.so}</span>
              <span class="text-[9px] px-1.5 py-0.2 rounded border font-semibold ${tInfo.cls}">${tInfo.text}</span>
              ${o.dom ? '<span class="text-[9px]" title="Domiciliare">🏠</span>' : ''}
            </div>
            <span class="text-[10px] font-semibold text-slate-300">${o.date || '--'}</span>
          </div>
          <div class="flex items-center justify-between pt-0.5">
            <div class="flex items-center gap-1 flex-wrap">${tagsHtml || '<span class="text-[9px] text-slate-500">Fornitura</span>'}</div>
            <div class="text-[9px] font-mono text-slate-400 truncate max-w-[140px]">PO: ${o.po || '--'}</div>
          </div>
          ${o.inv_date ? `<div class="text-[9px] text-emerald-400 font-medium">✓ Fatturato il ${o.inv_date}</div>` : (o.in_matrix ? `<div class="text-[9px] text-amber-400 font-medium">⏳ Presente in Matrix Open Order</div>` : '')}
        `;
        uidListEl.appendChild(row);
      });
    } else {
      uidListEl.innerHTML = `<p class="text-[11px] text-slate-500 italic">Nessun ordine registrato per questo UID in Rpt_20261010.</p>`;
    }
  }

  // BOX 3: ARTICOLI NEL PO (CONFEZIONI COLONNA L)
  const orderInfoEl = document.getElementById('modalOrderInfo');
  const poBadgeEl = document.getElementById('modalPoBadge');
  const itemsContainer = document.getElementById('modalPoItemsList');
  itemsContainer.innerHTML = '';

  if (patient.po_number || patient.so_number) {
    poBadgeEl.textContent = `PO: ${patient.po_number || '--'}`;
    orderInfoEl.textContent = `Ordine SAP: ${patient.so_number || '--'} | Data Fatt./Ord.: ${patient.inv_date || '--'}`;
  } else {
    poBadgeEl.textContent = 'PO: Non associato';
    orderInfoEl.textContent = 'Nessun ordine associato direttamente a questo seriale.';
  }

  const items = patient.po_items || [];
  if (items.length > 0) {
    items.forEach(it => {
      const itemRow = document.createElement('div');
      itemRow.className = 'p-2 rounded-xl bg-slate-900/90 border border-slate-800/80 flex items-center justify-between';
      itemRow.innerHTML = `
        <div class="truncate pr-2">
          <div class="flex items-center gap-1.5">
            <span class="font-mono font-bold text-sky-400 text-[11px]">${it.cfn}</span>
            <span class="text-[10px] text-slate-400 truncate max-w-[170px]">${it.desc}</span>
          </div>
          <div class="text-[9px] text-slate-500 mt-0.5">Lotto/Seriale: ${it.batch || '--'}</div>
        </div>
        <div class="text-right shrink-0">
          <span class="text-[11px] font-bold text-emerald-400">${it.conf || 0} conf.</span>
        </div>
      `;
      itemsContainer.appendChild(itemRow);
    });
  } else {
    itemsContainer.innerHTML = `<p class="text-[11px] text-slate-500 italic">Nessun dettaglio confezioni disponibile per questo PO.</p>`;
  }

  document.getElementById('modalSerialeMicro').textContent = patient.seriale || '--';
  document.getElementById('modalSerialeMinilink').textContent = patient.seriale_minilink || '--';
  document.getElementById('modalModelloMicro').textContent = patient.modello_micro || '--';
  document.getElementById('modalMedico').textContent = patient.medico || '--';
  document.getElementById('modalCentro').textContent = patient.centro || '--';

  document.getElementById('patientModal').classList.remove('hidden');
  lucide.createIcons();
}

function closePatientModal() {
  document.getElementById('patientModal').classList.add('hidden');
  selectedPatient = null;
}

// ==================== MODIFICA MANUALE DATA FATTURAZIONE ====================
function openEditInvoiceDateModal() {
  if (!selectedPatient) return;
  const input = document.getElementById('inputManualDate');
  input.value = selectedPatient.inv_date || '';
  document.getElementById('editDateModal').classList.remove('hidden');
}

function closeEditInvoiceDateModal() {
  document.getElementById('editDateModal').classList.add('hidden');
}

async function saveManualInvoiceDate() {
  if (!selectedPatient) return;
  const newDate = document.getElementById('inputManualDate').value;

  selectedPatient.inv_date = newDate || null;
  selectedPatient.manual_edit = true;

  try {
    const db = await openDB();
    await savePatientsToDB(db, [selectedPatient]);
  } catch (err) {
    console.error('Errore salvataggio data manuale:', err);
  }

  closeEditInvoiceDateModal();
  openPatientModal(selectedPatient);
  applyGlobalFilters();
  alert('Data di fatturazione aggiornata con successo!');
}

// ==================== IMPORT FILE EXCEL (CLIENT-SIDE) ====================
function parseExcelDateVal(val) {
  if (!val) return null;
  if (val instanceof Date && !isNaN(val.getTime())) {
    return val.toISOString().slice(0, 10);
  }
  if (typeof val === 'number') {
    const dt = new Date(Math.round((val - 25569) * 86400 * 1000));
    if (!isNaN(dt.getTime())) return dt.toISOString().slice(0, 10);
  }
  const s = String(val).trim();
  if (/^\d{4}-\d{2}-\d{2}/.test(s)) return s.slice(0, 10);
  return null;
}

async function handleExcelImport(fileType, event) {
  const file = event.target.files[0];
  if (!file) return;

  const progress = document.getElementById('importProgress');
  const progressText = document.getElementById('importProgressText');
  progress.classList.remove('hidden');
  progressText.textContent = `Lettura file ${file.name} in corso...`;

  try {
    const data = await file.arrayBuffer();
    const workbook = XLSX.read(data, { type: 'array', cellDates: true });
    progressText.textContent = `Elaborazione e merge dati in corso...`;

    let updatedCount = 0;

    if (fileType === 'ib') {
      const sheetName = workbook.SheetNames.find(n => n.includes('IB_FY') || n.includes('Micro')) || workbook.SheetNames[0];
      const rows = XLSX.utils.sheet_to_json(workbook.Sheets[sheetName], { header: 1, defval: '' });
      const pMap = new Map(allPatients.map(p => [String(p.uid), p]));

      for (let i = 1; i < rows.length; i++) {
        const r = rows[i];
        const uid = r[0] !== '' && r[0] !== null ? String(r[0]).replace(/\.0$/, '').trim() : '';
        if (!uid) continue;
        const existing = pMap.get(uid) || { uid, po_items: [], uid_orders: [] };
        existing.centro = String(r[1] || existing.centro || '').trim();
        existing.cognome = String(r[2] || existing.cognome || '').trim();
        existing.nome = String(r[3] || existing.nome || '').trim();
        existing.citta = String(r[8] || existing.citta || '').trim();
        existing.seriale = String(r[15] || existing.seriale || '').trim();
        existing.medico = String(r[19] || existing.medico || '').trim();
        existing.set_infusionale = String(r[20] || existing.set_infusionale || '').trim();
        existing.sales_rep = String(r[21] || existing.sales_rep || '').trim();
        existing.data_consenso = parseExcelDateVal(r[22]) || existing.data_consenso || null;
        existing.classificazione = String(r[23] || existing.classificazione || '').trim();
        existing.modello_micro = String(r[26] || existing.modello_micro || '').trim();
        existing.tipo_sensore = String(r[27] || existing.tipo_sensore || '').trim();
        existing.asl = String(r[32] || existing.asl || '').trim();
        pMap.set(uid, existing);
        updatedCount++;
      }
      allPatients = Array.from(pMap.values());
      document.getElementById('labelIbFile').textContent = `Caricato: ${file.name} (${updatedCount} righe)`;

    } else if (fileType === 'inv') {
      const sheetName = workbook.SheetNames.find(n => n.includes('Report')) || workbook.SheetNames[0];
      const rows = XLSX.utils.sheet_to_json(workbook.Sheets[sheetName], { header: 1, defval: '' });
      const batchMap = new Map();
      const soMap = new Map();

      for (let i = 4; i < rows.length; i++) {
        const r = rows[i];
        const batch = String(r[28] || '').trim();
        const invDt = parseExcelDateVal(r[18]);
        const qtr = String(r[16] || '').trim();
        const soRaw = String(r[8] || '').trim();
        const soClean = soRaw.replace(/^0+/, '');
        const poRaw = String(r[7] || '').trim();
        if (batch && invDt) {
          if (!batchMap.has(batch) || invDt > batchMap.get(batch).inv_date) {
            batchMap.set(batch, { inv_date: invDt, inv_qtr: qtr, so: soRaw, po: poRaw });
          }
        }
        if (soClean && invDt) {
          if (!soMap.has(soClean) || invDt > soMap.get(soClean).inv_date) {
            soMap.set(soClean, { inv_date: invDt, inv_qtr: qtr, so: soRaw, po: poRaw });
          }
        }
      }

      allPatients.forEach(p => {
        if (p.seriale && batchMap.has(p.seriale)) {
          const info = batchMap.get(p.seriale);
          p.inv_date = info.inv_date;
          p.inv_qtr = info.inv_qtr;
          p.so_number = info.so;
          p.po_number = info.po;
          p.inv_source = 'Seriale Diretto';
          updatedCount++;
        } else if (p.uid_orders && p.uid_orders.length > 0) {
          for (const o of p.uid_orders) {
            const soCl = String(o.so || '').replace(/^0+/, '');
            const isMicroOrder = (o.tags || []).includes('Micro');
            if (o.type === 'ZOR' && isMicroOrder && soMap.has(soCl)) {
              const info = soMap.get(soCl);
              p.inv_date = info.inv_date;
              p.inv_qtr = info.inv_qtr;
              p.so_number = info.so;
              p.po_number = info.po;
              p.inv_source = 'UID (Ordine ZOR Micro)';
              updatedCount++;
              break;
            }
          }
        }
      });
      document.getElementById('labelInvFile').textContent = `Caricato: ${file.name} (${updatedCount} fatture associate)`;

    } else if (fileType === 'mat') {
      const sheetName = workbook.SheetNames.find(n => n.includes('Open Order')) || workbook.SheetNames[0];
      const rows = XLSX.utils.sheet_to_json(workbook.Sheets[sheetName], { header: 1, defval: '' });
      const matBySerial = new Map();
      const matBySo = new Map();

      for (let i = 20; i < rows.length; i++) {
        const r = rows[i];
        const batch = String(r[13] || '').trim();
        const soDoc = String(r[5] || '').trim();
        const soClean = soDoc.replace(/^0+/, '');
        const info = {
          sales_doc: soDoc,
          block: String(r[2] || '').trim(),
          date: parseExcelDateVal(r[3]),
          ageing: Number(r[10]) || 0,
          po: String(r[6] || '').trim()
        };
        if (batch.startsWith('NG')) matBySerial.set(batch, info);
        if (soClean) matBySo.set(soClean, info);
      }

      allPatients.forEach(p => {
        if (p.seriale && matBySerial.has(p.seriale)) {
          p.in_matrix = true;
          p.matrix_info = matBySerial.get(p.seriale);
          updatedCount++;
        } else {
          p.in_matrix = false;
          p.matrix_info = null;
        }
      });
      document.getElementById('labelMatFile').textContent = `Caricato: ${file.name} (${updatedCount} in Matrix)`;

    } else if (fileType === 'rpt') {
      const sheetName = workbook.SheetNames[0];
      const rows = XLSX.utils.sheet_to_json(workbook.Sheets[sheetName], { header: 1, defval: '' });
      const ordersByUid = new Map();

      for (let i = 1; i < rows.length; i++) {
        const r = rows[i];
        if (Number(r[4]) === 1) continue; // ordine cancellato
        const uid = r[8] !== '' && r[8] !== null ? String(r[8]).replace(/\.0$/, '').trim() : '';
        if (!uid) continue;
        const tags = [];
        if (Number(r[9]) === 1) tags.push('Micro');
        if (Number(r[10]) === 1) tags.push('Consumabile');
        if (Number(r[11]) === 1) tags.push('Sensore');
        if (Number(r[13]) === 1) tags.push('CGM');
        if (Number(r[12]) === 1) tags.push('Accessori');

        if (!ordersByUid.has(uid)) ordersByUid.set(uid, []);
        ordersByUid.get(uid).push({
          so: String(r[1] || '').trim(),
          date: parseExcelDateVal(r[2]),
          po: String(r[3] || '').trim(),
          type: String(r[5] || '').trim(),
          dom: Number(r[7]) === 1,
          tags
        });
      }

      allPatients.forEach(p => {
        const ords = ordersByUid.get(String(p.uid));
        if (ords && ords.length > 0) {
          ords.sort((a, b) => String(b.date || '').localeCompare(String(a.date || '')));
          p.uid_orders = ords.slice(0, 8);
          p.domiciliare = ords.some(o => o.dom);
          const cons = ords.find(o => o.tags.includes('Consumabile') && o.date);
          if (cons) {
            p.last_cons_date = cons.date;
            p.last_cons_po = cons.po;
          }
          updatedCount++;
        }
      });
      document.getElementById('labelRptFile').textContent = `Caricato: ${file.name} (${updatedCount} pazienti aggiornati)`;
    }

    const db = await openDB();
    await savePatientsToDB(db, allPatients);
    populateDropdownFilters();
    applyGlobalFilters();
    updateStorageStats();

    alert(`File "${file.name}" elaborato con successo! Aggiornati ${updatedCount} record nel database locale.`);
  } catch (err) {
    alert('Errore durante la lettura del file Excel: ' + err.message);
  } finally {
    progress.classList.add('hidden');
  }
}

// ==================== EXPORT BACKUP JSON ====================
function exportDataJson() {
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(allPatients, null, 2));
  const downloadAnchor = document.createElement('a');
  downloadAnchor.setAttribute("href", dataStr);
  downloadAnchor.setAttribute("download", `backup_monitoraggio_${new Date().toISOString().slice(0, 10)}.json`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
}

async function resetToInitialData() {
  if (!confirm('Vuoi davvero ripristinare il database allo stato iniziale cancellando le modifiche manuali?')) return;
  const pin = prompt('Inserisci il PIN per decifrare l\'archivio iniziale AES-256:');
  if (!pin) return;
  try {
    const data = await decryptPayloadWithPin(pin);
    allPatients = data.patients || [];
    const db = await openDB();
    await savePatientsToDB(db, allPatients);
    localStorage.setItem(SCHEMA_VERSION_KEY, CURRENT_SCHEMA_VERSION);
    applyGlobalFilters();
    alert('Database ripristinato con successo!');
  } catch (err) {
    alert('PIN non valido o errore decifratura archivio.');
  }
}
