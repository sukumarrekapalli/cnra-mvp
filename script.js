const header = document.querySelector('.site-header');
const menuToggle = document.querySelector('.menu-toggle');
const modal = document.querySelector('#assessmentModal');
const closeButton = document.querySelector('.modal-close');
const openButtons = document.querySelectorAll('.js-open-assessment');
const form = document.querySelector('#assessmentForm');
const copyButton = document.querySelector('.copy-button');

function openModal() {
  modal.hidden = false;
  document.body.style.overflow = 'hidden';
  window.setTimeout(() => modal.querySelector('input')?.focus(), 80);
}

function closeModal() {
  modal.hidden = true;
  document.body.style.overflow = '';
}

openButtons.forEach((button) => button.addEventListener('click', openModal));
closeButton.addEventListener('click', closeModal);
modal.addEventListener('click', (event) => { if (event.target === modal) closeModal(); });
document.addEventListener('keydown', (event) => { if (event.key === 'Escape' && !modal.hidden) closeModal(); });

menuToggle.addEventListener('click', () => {
  const isOpen = header.classList.toggle('nav-open');
  menuToggle.setAttribute('aria-expanded', String(isOpen));
});

document.querySelectorAll('.desktop-nav a').forEach((link) => link.addEventListener('click', () => {
  header.classList.remove('nav-open');
  menuToggle.setAttribute('aria-expanded', 'false');
}));

form.addEventListener('submit', (event) => {
  event.preventDefault();
  const email = form.querySelector('input[type="email"]').value.trim();
  const context = document.querySelector('#assessmentContext')?.value.trim() || 'No additional context provided.';
  const subject = 'CNRA beta assessment request';
  const body = `Hi Sukumar,\n\nI would like to request a CNRA cloud-native readiness assessment.\n\nMy email: ${email}\nAdditional context: ${context}\n\nThank you.`;
  window.location.href = `mailto:sukumar.sachin09@gmail.com?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
});

copyButton.addEventListener('click', async () => {
  const command = 'helm upgrade --install cnra oci://registry-1.docker.io/sukumar9/cnra-mvp --version 0.2.4 --namespace cnra-system --create-namespace';
  try { await navigator.clipboard.writeText(command); } catch (_) { /* Clipboard may be unavailable in local previews. */ }
  copyButton.textContent = '✓';
  setTimeout(() => { copyButton.textContent = '□'; }, 1600);
});

document.querySelectorAll('.docs-copy').forEach((button) => {
  button.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(button.dataset.copy); } catch (_) { /* Clipboard may be unavailable in local previews. */ }
    const original = button.textContent;
    button.textContent = 'Copied';
    setTimeout(() => { button.textContent = original; }, 1600);
  });
});
