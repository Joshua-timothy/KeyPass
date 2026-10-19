'use strict';

import { deriveHmacKey, derivePassword, validateSettings, validateMaster, requirementsFor, canonicalServiceIdentifier, DEFAULT_SETTINGS } from './crypto-core.js';
const $ = (id) => document.getElementById(id);
const masterInput = $('masterPassword');
const serviceInput = $('serviceIdentifier');
const generateButton = $('generateButton');
const formError = $('formError');
const derivationStatus = $('derivationStatus');
const statusText = $('statusText');
const generatedPassword = $('generatedPassword');
const emptyOutput = $('emptyOutput');
const passwordOutput = $('passwordOutput');
const copyButton = $('copyButton');
const regenerateButton = $('regenerateButton');
const resultTitle = $('resultTitle');
const resultState = $('resultState');
const lengthMeta = $('lengthMeta');
const settingsDialog = $('settingsDialog');
const securityDialog = $('securityDialog');
const settingsError = $('settingsError');
const lengthInput = $('lengthInput');
const lengthValue = $('lengthValue');
const prefixInput = $('prefixInput');
const suffixInput = $('suffixInput');
const toast = $('toast');
const toastMessageNode = $('toastMessage');

let settings = { ...DEFAULT_SETTINGS };
let resultVisible = true;
let generatedValue = '';
let toastTimeout = null;
let generationToken = 0;

function showError(message) { formError.textContent = message; formError.hidden = false; }
function clearError() { formError.textContent = ''; formError.hidden = true; }
function showSettingsError(message) { settingsError.textContent = message; settingsError.hidden = false; }
function clearSettingsError() { settingsError.textContent = ''; settingsError.hidden = true; }
function setGenerating(isGenerating, message = 'Deriving your password locally…') {
  generateButton.disabled = isGenerating;
  serviceInput.disabled = isGenerating;
  masterInput.disabled = isGenerating;
  statusText.textContent = message;
  derivationStatus.hidden = !isGenerating;
  generateButton.querySelector('.button-label').textContent = isGenerating ? 'Deriving securely…' : 'Generate password';
}
function toastMessageForUser(message) {
  toastMessageNode.textContent = message;
  toast.hidden = false;
  if (toastTimeout) clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => { toast.hidden = true; }, 2600);
}
function setResultState(ready) {
  resultState.replaceChildren();
  const dot = document.createElement('span');
  dot.className = 'state-dot';
  resultState.append(dot, document.createTextNode(ready ? 'Ready' : 'Waiting'));
  resultState.classList.toggle('is-ready', ready);
}

function updateMasterCriteria() {
  const criteria = requirementsFor(masterInput.value);
  document.querySelectorAll('#masterCriteria [data-criterion]').forEach((item) => {
    const key = item.dataset.criterion;
    const valid = Boolean(criteria[key]);
    item.classList.toggle('is-valid', valid);
    const marker = item.querySelector('.criteria-check');
    if (marker) marker.textContent = valid ? '✓' : '•';
    item.setAttribute('aria-label', `${key}: ${valid ? 'met' : 'not met'}`);
  });
}
async function generate() {
  clearError();
  let masterPassword = masterInput.value;
  const rawServiceIdentifier = serviceInput.value;
  const serviceIdentifier = canonicalServiceIdentifier(rawServiceIdentifier);
  const masterProblem = validateMaster(masterPassword);
  if (masterProblem) { showError(masterProblem); masterInput.focus(); return; }
  // Match the reference input rule before canonicalization: three typed chars minimum.
  if (rawServiceIdentifier.length < 3) { showError('Enter a service identifier with at least 3 characters.'); serviceInput.focus(); return; }
  if (rawServiceIdentifier.length > 200) { showError('The service identifier must be 200 characters or fewer.'); serviceInput.focus(); return; }
  const configProblem = validateSettings(settings);
  if (configProblem) { showError(configProblem); return; }
  if (!window.isSecureContext || !window.crypto?.subtle) { showError('Web Crypto is not available. Open this app over HTTPS or on localhost in a supported browser.'); return; }

  const token = ++generationToken;
  setGenerating(true, 'Hashing the service identifier and deriving its key locally…');
  try {
    const serviceKey = await deriveHmacKey(masterPassword, serviceIdentifier);
    // Drop the input reference immediately after key derivation. JavaScript cannot
    // guarantee string zeroization, but the form and mutable byte buffer are cleared.
    masterInput.value = '';
    masterPassword = '';
    updateMasterCriteria();
    if (token !== generationToken) return;

    statusText.textContent = 'Signing the service identifier and encoding the result…';
    const password = await derivePassword(serviceKey, serviceIdentifier, settings);
    if (token !== generationToken) return;
    generatedValue = password;
    resultVisible = true;
    renderGeneratedPassword();
    resultTitle.textContent = rawServiceIdentifier.trim();
    setResultState(true);
    passwordOutput.dataset.empty = 'false';
    lengthMeta.textContent = `${password.length} characters`;
    copyButton.disabled = false;
    regenerateButton.disabled = false;
    $('toggleOutput').hidden = false;
    $('toggleOutput').setAttribute('aria-label', 'Hide generated password');
    $('toggleOutput').setAttribute('aria-pressed', 'true');
    $('algorithmMeta').textContent = 'PBKDF2 · HMAC-SHA256 · compatible profile';
  } catch (error) {
    // Do not log the master key, derived password, or cryptographic input values.
    masterInput.value = '';
    masterPassword = '';
    updateMasterCriteria();
    showError(error?.name === 'NotSupportedError' ? 'This browser does not support the required cryptographic operation. Update your browser and try again.' : 'Password generation failed in this browser. Confirm Web Crypto is available, then try again.');
  } finally {
    // The original workflow requests the master key again for every generation.
    masterInput.value = '';
    masterPassword = '';
    updateMasterCriteria();
    if (token === generationToken) setGenerating(false);
  }
}
function renderGeneratedPassword() {
  generatedPassword.hidden = false;
  emptyOutput.hidden = true;
  generatedPassword.textContent = resultVisible ? generatedValue : '•'.repeat(Math.min(generatedValue.length, 40));
  $('toggleOutput').setAttribute('aria-label', resultVisible ? 'Hide generated password' : 'Show generated password');
  $('toggleOutput').setAttribute('aria-pressed', resultVisible ? 'true' : 'false');
}
function clearGeneratedResult() {
  generatedValue = '';
  resultVisible = true;
  generatedPassword.textContent = '';
  generatedPassword.hidden = true;
  emptyOutput.hidden = false;
  passwordOutput.dataset.empty = 'true';
  resultTitle.textContent = 'Ready when you are';
  setResultState(false);
  lengthMeta.textContent = '— characters';
  $('algorithmMeta').textContent = 'PBKDF2 · HMAC-SHA256';
  $('toggleOutput').hidden = true;
  copyButton.disabled = true;
  regenerateButton.disabled = true;
}
function clearSession() {
  generationToken += 1;
  masterInput.value = '';
  serviceInput.value = '';
  clearGeneratedResult();
  clearError();
  updateMasterCriteria();
  masterInput.disabled = false;
  serviceInput.disabled = false;
  generateButton.disabled = false;
  derivationStatus.hidden = true;
  generateButton.querySelector('.button-label').textContent = 'Generate password';
  settings = { ...DEFAULT_SETTINGS };
  syncSettingsControls(settings);
  toastMessageForUser('Session cleared from the page.');
}
function syncSettingsControls(config) {
  lengthInput.value = String(config.length);
  lengthValue.value = String(config.length);
  lengthValue.textContent = String(config.length);
  prefixInput.value = config.prefix;
  suffixInput.value = config.suffix;
}
function openSettings() {
  syncSettingsControls(settings);
  clearSettingsError();
  if (!settingsDialog.open) settingsDialog.showModal();
}
function applySettings() {
  const candidate = { length: Number(lengthInput.value), prefix: prefixInput.value.trim(), suffix: suffixInput.value.trim() };
  const problem = validateSettings(candidate);
  if (problem) { showSettingsError(problem); return; }
  settings = { ...candidate, prefix: candidate.prefix.trim(), suffix: candidate.suffix.trim() }; 
  settingsDialog.close();
  clearSettingsError();
  if (generatedValue) clearGeneratedResult();
  toastMessageForUser('Password settings applied.');
}
async function copyResult() {
  if (!generatedValue) return;
  try {
    if (!navigator.clipboard || typeof navigator.clipboard.writeText !== 'function') throw new Error('Clipboard API is unavailable.');
    await navigator.clipboard.writeText(generatedValue);
    toastMessageForUser('Password copied. Your system clipboard may retain it.');
  } catch {
    toastMessageForUser('Clipboard access failed. Reveal the password and copy it manually.');
  }
}
function openSecurity() { if (!securityDialog.open) securityDialog.showModal(); }

function setTheme(theme) {
  const isDark = theme === 'dark';
  document.documentElement.dataset.theme = isDark ? 'dark' : 'light';
  const toggle = $('themeToggle');
  toggle.setAttribute('aria-pressed', String(isDark));
  toggle.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
  toggle.setAttribute('title', isDark ? 'Switch to light mode' : 'Switch to dark mode');
  const themeColor = document.querySelector('meta[name="theme-color"]');
  if (themeColor) themeColor.content = isDark ? '#111310' : '#f5f4f0';
}

masterInput.addEventListener('input', () => { updateMasterCriteria(); clearError(); if (generatedValue) clearGeneratedResult(); });
serviceInput.addEventListener('input', () => { clearError(); if (generatedValue) clearGeneratedResult(); });
serviceInput.addEventListener('keydown', (event) => { if (event.key === 'Enter') { event.preventDefault(); generate(); } });
$('toggleMaster').addEventListener('click', () => {
  const show = masterInput.type === 'password';
  masterInput.type = show ? 'text' : 'password';
  $('toggleMaster').setAttribute('aria-label', show ? 'Hide master password' : 'Show master password');
  $('toggleMaster').setAttribute('aria-pressed', show ? 'true' : 'false');
});
$('clearService').addEventListener('click', () => { serviceInput.value = ''; serviceInput.focus(); clearGeneratedResult(); clearError(); });
generateButton.addEventListener('click', generate);
regenerateButton.addEventListener('click', () => { masterInput.focus(); toastMessageForUser('Re-enter your master key to generate this password again.'); });
$('settingsButton').addEventListener('click', openSettings);
$('saveSettingsButton').addEventListener('click', applySettings);
$('resetSettingsButton').addEventListener('click', () => { syncSettingsControls(DEFAULT_SETTINGS); clearSettingsError(); });
lengthInput.addEventListener('input', () => { lengthValue.value = lengthInput.value; lengthValue.textContent = lengthInput.value; clearSettingsError(); });
[prefixInput, suffixInput].forEach((input) => input.addEventListener('input', clearSettingsError));
$('toggleOutput').addEventListener('click', () => { resultVisible = !resultVisible; renderGeneratedPassword(); });
copyButton.addEventListener('click', copyResult);
$('clearAllButton').addEventListener('click', clearSession);
$('themeToggle').addEventListener('click', () => {
  setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
});
$('securityInfoButton').addEventListener('click', openSecurity);
$('learnSecurityButton').addEventListener('click', openSecurity);
$('closeSecurityButton').addEventListener('click', () => securityDialog.close());
$('securityGotItButton').addEventListener('click', () => securityDialog.close());
document.addEventListener('keydown', (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === 'Enter' && !settingsDialog.open && !securityDialog.open) { event.preventDefault(); generate(); }
  if (event.key === 'Escape') { if (settingsDialog.open) settingsDialog.close(); if (securityDialog.open) securityDialog.close(); }
});
updateMasterCriteria();
clearGeneratedResult();

// Custom visual scrollbar. Page scrolling itself remains native and accessible.
const customScrollbar = $('customScrollbar');
const customScrollbarTrack = $('customScrollbarTrack');
const customScrollbarThumb = $('customScrollbarThumb');
let customScrollDrag = null;
let customScrollFrame = 0;

function syncCustomScrollbar() {
  if (!customScrollbar || !customScrollbarTrack || !customScrollbarThumb) return;
  const viewportHeight = window.innerHeight;
  const documentHeight = Math.max(document.documentElement.scrollHeight, document.body.scrollHeight);
  const maxScroll = documentHeight - viewportHeight;
  if (viewportHeight <= 0 || maxScroll <= 2) {
    customScrollbar.hidden = true;
    return;
  }
  customScrollbar.hidden = false;
  const trackHeight = customScrollbarTrack.clientHeight;
  const thumbHeight = Math.min(trackHeight, Math.max(30, Math.round(trackHeight * viewportHeight / documentHeight)));
  const maxTravel = Math.max(0, trackHeight - thumbHeight);
  const scrollTop = Math.min(maxScroll, Math.max(0, window.scrollY || document.documentElement.scrollTop || 0));
  customScrollbarThumb.style.height = `${thumbHeight}px`;
  customScrollbarThumb.style.transform = `translate3d(0, ${maxScroll > 0 ? maxTravel * scrollTop / maxScroll : 0}px, 0)`;
}

function scheduleCustomScrollbarSync() {
  if (customScrollFrame) return;
  customScrollFrame = window.requestAnimationFrame(() => {
    customScrollFrame = 0;
    syncCustomScrollbar();
  });
}

function endCustomScrollDrag(event) {
  if (!customScrollDrag || (event && event.pointerId !== customScrollDrag.pointerId)) return;
  customScrollDrag = null;
  customScrollbar.classList.remove('is-dragging');
  document.documentElement.classList.remove('custom-scrollbar-dragging');
  scheduleCustomScrollbarSync();
}

customScrollbarThumb.addEventListener('pointerdown', (event) => {
  if (event.pointerType === 'mouse' && event.button !== 0) return;
  const trackRect = customScrollbarTrack.getBoundingClientRect();
  const thumbRect = customScrollbarThumb.getBoundingClientRect();
  customScrollDrag = {
    pointerId: event.pointerId,
    startY: event.clientY,
    startTop: thumbRect.top - trackRect.top,
    trackHeight: trackRect.height,
    thumbHeight: thumbRect.height
  };
  customScrollbar.classList.add('is-dragging');
  document.documentElement.classList.add('custom-scrollbar-dragging');
  customScrollbarThumb.setPointerCapture(event.pointerId);
  event.preventDefault();
});

customScrollbarThumb.addEventListener('pointermove', (event) => {
  if (!customScrollDrag || event.pointerId !== customScrollDrag.pointerId) return;
  const documentHeight = Math.max(document.documentElement.scrollHeight, document.body.scrollHeight);
  const maxScroll = Math.max(0, documentHeight - window.innerHeight);
  const maxTravel = Math.max(0, customScrollDrag.trackHeight - customScrollDrag.thumbHeight);
  const top = Math.max(0, Math.min(maxTravel, customScrollDrag.startTop + event.clientY - customScrollDrag.startY));
  window.scrollTo({ top: maxTravel > 0 ? top / maxTravel * maxScroll : 0, behavior: 'auto' });
});
customScrollbarThumb.addEventListener('pointerup', endCustomScrollDrag);
customScrollbarThumb.addEventListener('pointercancel', endCustomScrollDrag);
customScrollbarThumb.addEventListener('lostpointercapture', endCustomScrollDrag);

customScrollbarTrack.addEventListener('pointerdown', (event) => {
  if (event.target === customScrollbarThumb || (event.pointerType === 'mouse' && event.button !== 0)) return;
  const trackRect = customScrollbarTrack.getBoundingClientRect();
  const thumbHeight = customScrollbarThumb.getBoundingClientRect().height;
  const maxTravel = Math.max(0, trackRect.height - thumbHeight);
  const targetTop = Math.max(0, Math.min(maxTravel, event.clientY - trackRect.top - thumbHeight / 2));
  const documentHeight = Math.max(document.documentElement.scrollHeight, document.body.scrollHeight);
  const maxScroll = Math.max(0, documentHeight - window.innerHeight);
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  window.scrollTo({ top: maxTravel > 0 ? targetTop / maxTravel * maxScroll : 0, behavior: reduceMotion ? 'auto' : 'smooth' });
});

window.addEventListener('scroll', scheduleCustomScrollbarSync, { passive: true });
window.addEventListener('resize', scheduleCustomScrollbarSync, { passive: true });
window.addEventListener('load', scheduleCustomScrollbarSync, { once: true });
if ('ResizeObserver' in window) {
  const customScrollbarResizeObserver = new ResizeObserver(scheduleCustomScrollbarSync);
  customScrollbarResizeObserver.observe(document.body);
}
scheduleCustomScrollbarSync();
